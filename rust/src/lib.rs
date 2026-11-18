#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

// ── Diagnostics ─────────────────────────────────────────────────────────────
//
// This crate reported through `eprintln!`, i.e. stderr. On Android stderr is
// discarded, so every handshake failure, pin rejection and connection error was
// written to /dev/null — a failed pairing and a successful one produced
// byte-for-byte identical output: nothing. The one component that knew why a
// session failed was the one component incapable of saying so.
//
// `rd_log!` writes to the Android log on device and to stderr everywhere else,
// so the host build and the test suite are unaffected.

#[cfg(target_os = "android")]
mod android_log {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    // liblog ships in the NDK sysroot and is always present on device, so
    // linking it costs nothing and avoids pulling in a logging crate.
    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    /// ANDROID_LOG_INFO — matches `Log.i` on the Kotlin side, so native and
    /// Kotlin lines interleave at one level under a single `adb logcat`.
    const ANDROID_LOG_INFO: c_int = 4;

    pub fn write(tag: &str, msg: &str) {
        // An interior NUL cannot cross the C boundary. Replace rather than drop:
        // a mangled diagnostic still beats a silent one, which is the exact
        // failure this module exists to end.
        let sanitize = |s: &str| s.replace('\0', "?");
        if let (Ok(t), Ok(m)) = (CString::new(sanitize(tag)), CString::new(sanitize(msg))) {
            unsafe { __android_log_write(ANDROID_LOG_INFO, t.as_ptr(), m.as_ptr()) };
        }
    }
}

/// Emit a diagnostic: Android log on device, stderr elsewhere.
macro_rules! rd_log {
    ($($arg:tt)*) => {{
        #[cfg(target_os = "android")]
        { crate::android_log::write("RDNative", &format!($($arg)*)); }
        #[cfg(not(target_os = "android"))]
        { eprintln!($($arg)*); }
    }};
}

/// This device's own persistent Noise identity.
pub mod identity;

/// The app-private directory Kotlin hands us at startup.
///
/// Set once, before any connection. Until Block 9 the client generated a fresh
/// Noise keypair per connection, so every reconnect looked like a different
/// device to the host and durable pairing was impossible by construction.
static APP_DATA_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Record where this device keeps its identity. First call wins.
///
/// Named and public so the JNI entry point is a thin translation of Java types
/// and nothing more: the rule about what constitutes a usable path lives here,
/// where a test can reach it, rather than inside an `unsafe extern "C"` that
/// only a running JVM can call. An empty path is refused because `PathBuf::from("")`
/// is a valid `PathBuf` that resolves to the process's working directory —
/// silently keeping the device identity wherever the app happened to be
/// started from.
///
/// Returns whether this call is the one that set it. A later call with a
/// different path is ignored rather than honoured: the identity file is already
/// open at the first location, and moving it mid-run would strand it.
pub fn set_data_dir(path: &str) -> bool {
    if path.is_empty() {
        rd_log!("set_data_dir: empty path ignored");
        return false;
    }
    APP_DATA_DIR.set(std::path::PathBuf::from(path)).is_ok()
}

/// This device's stable private key, or a throwaway if Kotlin never told us
/// where to keep one.
///
/// A throwaway still connects — viewing and QR pairing work exactly as before —
/// it simply cannot be recognised on the next run. That degradation is loud
/// rather than silent, because a client that quietly forgets its identity looks
/// identical to a host that quietly forgot the device.
fn device_private_key() -> anyhow::Result<Vec<u8>> {
    match APP_DATA_DIR.get() {
        Some(dir) => {
            let path = identity::identity_file(dir);
            identity::load_or_create(&path).map_err(|e| anyhow::anyhow!("{e}"))
        }
        None => {
            rd_log!("no app data dir set; using a throwaway identity — pairing will not persist");
            Ok(snow::Builder::new(NOISE_PATTERN.parse()?)
                .generate_keypair()?
                .private)
        }
    }
}
use anyhow::Result;
use jni::sys::{jbyteArray, jclass, jint, JNI_VERSION_1_6};
use jni::NativeMethod;
use lazy_static::lazy_static;
use module14_apk_session::engine::APKSessionEngine;
use module14_apk_session::events::APKSessionEvent;
use module14_apk_session::frame::FrameEnvelope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_NOISE_FRAME: usize = 65535;

/// One decrypted message received from the pinned Noise transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedNoiseFrame {
    pub plaintext: Vec<u8>,
    pub ciphertext_len: usize,
}

/// A live, host-pinned RemoteDexter client session.
///
/// The socket and Noise state deliberately have one mutable owner so transport
/// nonces cannot be reordered by independent reader/writer tasks.
pub struct PinnedNoiseSession {
    stream: TcpStream,
    noise: snow::TransportState,
    /// Bytes read from the socket that do not yet form a whole framed message.
    ///
    /// This exists so `recv()` is **cancel-safe**. The session loop selects
    /// between `recv()` and the outbound command channel, so the `recv()` future
    /// is dropped whenever a command wins the race. Reading straight into a
    /// local with `read_exact` would discard a partially-read frame on every
    /// such drop, desynchronizing the framing and then the Noise nonces. Partial
    /// reads accumulate here instead and survive cancellation.
    rx_buf: Vec<u8>,
}

/// How the client reaches the host.
///
/// The two are not interchangeable and neither is a fallback for the other: a
/// direct invite names a socket the host is listening on, a relay invite names
/// a relay and the session it issued. Which one is used is decided by which
/// invite was scanned, never by trying one and falling back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientReach {
    /// Straight to a host that is listening.
    Direct {
        /// The host's address, exactly as the invite gave it.
        host: String,
        /// The host's port.
        port: u16,
    },
    /// Through a relay, which splices this connection to the host's.
    ViaRelay {
        /// The relay's address.
        relay: String,
        /// The relay's port.
        relay_port: u16,
        /// The session id the relay issued to the host, from the invite.
        session: String,
    },
}

impl ClientReach {
    /// Open the stream the Noise handshake will run over.
    ///
    /// **The relay case exchanges control frames first and then gets out of the
    /// way.** Everything after `Joined` is opaque to it, and the handshake that
    /// follows is byte for byte the one the direct path runs — which is what
    /// makes the relay untrusted rather than trusted. A relay that substituted
    /// itself for the host would have to pass a Noise handshake against a key
    /// it does not hold.
    async fn open(&self) -> Result<TcpStream> {
        match self {
            ClientReach::Direct { host, port } => connect_for_session(host, *port).await,
            ClientReach::ViaRelay {
                relay,
                relay_port,
                session,
            } => {
                let mut stream = connect_for_session(relay, *relay_port).await?;
                relay_join(&mut stream, session).await?;
                Ok(stream)
            }
        }
    }

    /// What the status line says.
    ///
    /// **Never the session id.** It is what this device presents to reach the
    /// host, so it belongs in the invite and nowhere else — the same rule the
    /// token has always had, and the host applies it to its own logs too.
    fn endpoint(&self) -> String {
        match self {
            ClientReach::Direct { host, port } => format!("{host}:{port}"),
            ClientReach::ViaRelay {
                relay, relay_port, ..
            } => format!("relay {relay}:{relay_port}"),
        }
    }
}

/// Connect a session socket with Nagle's algorithm off.
///
/// Measured on the operator's phone over weak Wi-Fi, 2026-09-14: input is a
/// stream of small messages, and with Nagle on each one waits for the peer to
/// acknowledge whatever this phone sent before it — so on a lossy link, where
/// acknowledgements are exactly what goes missing, every keystroke queues
/// behind the last. A remote desktop wants each event on the wire as it
/// happens. The host sets the same option on its side.
async fn connect_for_session(host: &str, port: u16) -> Result<TcpStream> {
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Ask the relay to splice this connection to `session`.
///
/// Length-prefixed control frames, bounded before anything is read: a relay —
/// or something impersonating one — must not be able to make the client
/// allocate by announcing a huge frame. The cap is the relay's own
/// [`relay_proto::MAX_CONTROL_FRAME`], from the same crate both sides use, so
/// there is one definition of the grammar rather than a third.
async fn relay_join(stream: &mut TcpStream, session: &str) -> Result<()> {
    let body = relay_proto::encode(&relay_proto::ControlFrame::Join {
        v: relay_proto::PROTOCOL_VERSION,
        session: session.to_string(),
    });
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let declared = u32::from_be_bytes(len) as usize;
    let n = relay_proto::check_len(declared)
        .map_err(|_| anyhow::anyhow!("relay announced a control frame of {declared} bytes"))?;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;

    match relay_proto::decode(&buf) {
        Ok(relay_proto::ControlFrame::Joined) => Ok(()),
        // The relay's reason is coarse by design and is passed through as
        // given, never embellished into a guess about what went wrong.
        Ok(relay_proto::ControlFrame::Denied { why }) => {
            anyhow::bail!("the relay refused this session: {why}")
        }
        Ok(_) => anyhow::bail!("the relay sent an unexpected frame"),
        Err(_) => anyhow::bail!("the relay sent a malformed frame"),
    }
}

impl PinnedNoiseSession {
    /// Connect: pinned Noise first, then the pairing token **inside** the
    /// encrypted channel.
    ///
    /// ## What changed in the Block 4 repair
    ///
    /// This used to send `{"Handshake":{"session_token":...}}` as a plaintext
    /// length-prefixed JSON frame *before* the handshake, and bind the same
    /// token in as the Noise prologue. The token was therefore readable by
    /// anyone on the path, and the host had an `RD_BIND_TOKEN_PROLOGUE=0`
    /// switch that turned the binding off entirely.
    ///
    /// Now: handshake, then one bounded encrypted `pair_auth` message. There is
    /// no plaintext frame, no prologue, and **no compatibility downgrade** — a
    /// host that speaks the old protocol simply fails, which is the intended
    /// outcome rather than a regression to guard against.
    pub async fn connect(
        host: String,
        port: u16,
        token: String,
        expected_host_pub: Vec<u8>,
    ) -> Result<Self> {
        if token.is_empty() {
            anyhow::bail!("session token must not be empty");
        }
        Self::connect_inner(ClientReach::Direct { host, port }, token, expected_host_pub).await
    }

    /// Connect to a host THROUGH A RELAY, with a one-use token from a v5 QR.
    ///
    /// Identical to [`connect`] in everything that matters: the same empty-token
    /// refusal, the same 32-byte pin requirement, the same handshake, the same
    /// encrypted `pair_auth`. What differs is only how the socket is obtained.
    ///
    /// **The relay is not trusted by this path and gains nothing from it.** It
    /// sees a session id it issued and then ciphertext. The host key pinned in
    /// the invite is checked in the handshake exactly as on the direct path, so
    /// a relay that spliced this connection to a machine of its own choosing
    /// fails at the pin rather than succeeding quietly.
    pub async fn connect_via_relay(
        relay: String,
        relay_port: u16,
        session: String,
        token: String,
        expected_host_pub: Vec<u8>,
    ) -> Result<Self> {
        if token.is_empty() {
            anyhow::bail!("session token must not be empty");
        }
        if session.is_empty() {
            anyhow::bail!("relay session must not be empty");
        }
        Self::connect_inner(
            ClientReach::ViaRelay {
                relay,
                relay_port,
                session,
            },
            token,
            expected_host_pub,
        )
        .await
    }

    /// Reconnect as a device the host has already enrolled — **no token**.
    ///
    /// ## Why this is a separate entry point
    ///
    /// [`connect`] refuses an empty token and must keep refusing it. That guard
    /// is what stops an invite whose token failed to parse from silently
    /// downgrading into an unauthenticated connection attempt: on the invite
    /// path, a missing token means something went wrong, not "try it without
    /// one". Relaxing the guard would have made every caller's mistake look
    /// like a feature.
    ///
    /// So the token-less connection is its own named call. The caller has to
    /// mean it, and the two paths cannot be reached by accident from each
    /// other.
    ///
    /// ## What actually authenticates here
    ///
    /// The device's own Noise static key, and nothing else. The host reads it
    /// from the completed handshake and looks it up in its device store; an
    /// unenrolled or revoked key is refused identically, so the host never
    /// becomes an oracle for which is which. `expected_host_pub` still pins the
    /// host exactly as on the invite path — dropping the token does not drop
    /// the host's side of the mutual check.
    ///
    /// This requires a **persistent** device identity. With a throwaway key
    /// (see [`device_private_key`]) every reconnect presents a key the host has
    /// never seen and is correctly refused as unknown.
    pub async fn connect_paired(
        host: String,
        port: u16,
        expected_host_pub: Vec<u8>,
    ) -> Result<Self> {
        Self::connect_inner(
            ClientReach::Direct { host, port },
            String::new(),
            expected_host_pub,
        )
        .await
    }

    /// Reconnect THROUGH A RELAY as a device the host has already enrolled —
    /// **no token**.
    ///
    /// [`connect_paired`] for the relay route, and a separate named call for the
    /// same reason that one is: the token-less path has to be meant, and must
    /// not be reachable by an invite whose token failed to parse.
    ///
    /// ## Why this became possible
    ///
    /// The relay used to issue a random session id per registration, so a host
    /// restart killed the id the phone had paired against and there was nothing
    /// to reconnect to. An enrolled host now gets the same id every time it
    /// registers, for as long as the relay runs, so the id the phone kept from
    /// its pairing still names that host after the host restarts.
    ///
    /// It does NOT survive a restart of the RELAY: the relay derives ids through
    /// a key it keeps only in memory. A stored id refused after that is
    /// indistinguishable, from here, from a host that is not running — the relay
    /// gives both the same answer on purpose — and the remedy for both is on the
    /// host side.
    ///
    /// ## What authenticates, and what the relay learns
    ///
    /// Exactly as [`connect_paired`]: the device's own Noise static key, and the
    /// host key pinned in the handshake. The relay sees the session id it issued
    /// and then ciphertext, and a relay that spliced this connection to a machine
    /// of its own choosing fails at the pin.
    pub async fn connect_paired_via_relay(
        relay: String,
        relay_port: u16,
        session: String,
        expected_host_pub: Vec<u8>,
    ) -> Result<Self> {
        // Refused before any socket opens, exactly as the token path refuses.
        // An empty id would be sent to the relay as a join and come back as
        // "no such session" — a network round trip to report a local mistake.
        if session.is_empty() {
            anyhow::bail!("relay session must not be empty");
        }
        Self::connect_inner(
            ClientReach::ViaRelay {
                relay,
                relay_port,
                session,
            },
            String::new(),
            expected_host_pub,
        )
        .await
    }

    async fn connect_inner(
        reach: ClientReach,
        token: String,
        expected_host_pub: Vec<u8>,
    ) -> Result<Self> {
        if expected_host_pub.len() != 32 {
            anyhow::bail!("host pin must be exactly 32 bytes");
        }

        // NOTHING is written to the HOST before the handshake. The first bytes
        // it sees are Noise message 1.
        //
        // On the relay route a control exchange happens first, but it is with
        // the RELAY and ends before the host is involved at all: the relay
        // splices only once both sides are present, so the first bytes to
        // cross to the host are still Noise message 1.
        let mut stream = reach.open().await?;
        let private = device_private_key()?;
        let mut noise =
            noise_transport_handshake(&mut stream, &private, true, &expected_host_pub).await?;

        // The token, encrypted, as the first transport message.
        let auth = serde_json::json!({
            "token": token,
            "protocol": "rdv3",
            // 4: Block 10 framing. Every message after pair_ok is a
            // wire::Envelope. A host that speaks 3 refuses this at
            // pair_auth with pair_denied, without spending the token.
            "version": 4u8,
        });
        let pt = serde_json::to_vec(&auth)?;
        let mut ct = vec![0u8; MAX_NOISE_FRAME];
        let n = noise.write_message(&pt, &mut ct)?;
        send_noise_msg(&mut stream, &ct[..n]).await?;

        // The host answers pair_ok or pair_denied, both encrypted. A host that
        // refuses closes without replying; that is a hard error here.
        let reply_ct = recv_noise_msg(&mut stream).await?;
        let mut reply = vec![0u8; MAX_NOISE_FRAME];
        let rn = noise.read_message(&reply_ct, &mut reply)?;
        let reply: serde_json::Value = serde_json::from_slice(&reply[..rn])?;
        if reply.get("type").and_then(|t| t.as_str()) != Some("pair_ok") {
            anyhow::bail!("pairing refused by host");
        }

        Ok(Self {
            stream,
            noise,
            rx_buf: Vec::new(),
        })
    }

    /// Frame a command and send it.
    ///
    /// The kind is chosen by [`kind_for_command`], so every caller — the
    /// session loop and the host's own integration tests alike — puts the same
    /// bytes on the wire. That matters more than the convenience: a test that
    /// framed messages itself would be a second implementation of the protocol,
    /// and the whole point of Block 10's `the_shipping_client_*` tests is that
    /// the thing under test is the thing that ships.
    ///
    /// Refuses locally rather than sending something the host will deny — a
    /// remote refusal arrives as a generic error with nothing pointing at the
    /// cause.
    pub async fn send_command(&mut self, payload: &[u8]) -> Result<usize> {
        let kind = kind_for_command(payload);
        let envelope = wire::Envelope::new(kind, 0, payload.to_vec())
            .map_err(|e| anyhow::anyhow!("cannot frame a {kind:?}: {e:?}"))?;
        self.send(&envelope.encode()).await
    }

    /// Encrypt and send one protocol message.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<usize> {
        if plaintext.is_empty() {
            anyhow::bail!("plaintext message must not be empty");
        }
        let mut ciphertext = vec![0u8; MAX_NOISE_FRAME];
        let ciphertext_len = self.noise.write_message(plaintext, &mut ciphertext)?;
        if ciphertext_len == 0 || ciphertext_len > MAX_NOISE_FRAME {
            anyhow::bail!("encrypted frame out of bounds: {ciphertext_len}");
        }
        send_noise_msg(&mut self.stream, &ciphertext[..ciphertext_len]).await?;
        Ok(ciphertext_len)
    }

    /// Take one complete framed message out of `rx_buf`, if one has arrived.
    /// Pure and synchronous, so it is not a cancellation point.
    fn take_framed(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == 0 || len > MAX_NOISE_FRAME {
            anyhow::bail!("noise message out of bounds: {len}");
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let frame = buf[4..4 + len].to_vec();
        buf.drain(..4 + len);
        Ok(Some(frame))
    }

    /// Receive and decrypt one protocol message. Any framing/decrypt failure is
    /// terminal to the caller; continuing would desynchronize Noise nonces.
    ///
    /// **Cancel-safe.** The only await is a plain `read` whose bytes are
    /// appended to `rx_buf` before anything else happens, so dropping this
    /// future (as `select!` does) never loses a partially-received frame.
    pub async fn recv(&mut self) -> Result<ReceivedNoiseFrame> {
        let ciphertext = loop {
            if let Some(frame) = Self::take_framed(&mut self.rx_buf)? {
                break frame;
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                anyhow::bail!("host closed the connection");
            }
            self.rx_buf.extend_from_slice(&chunk[..n]);
        };
        let ciphertext_len = ciphertext.len();
        let mut plaintext = vec![0u8; MAX_NOISE_FRAME];
        let plaintext_len = self.noise.read_message(&ciphertext, &mut plaintext)?;
        plaintext.truncate(plaintext_len);
        Ok(ReceivedNoiseFrame {
            plaintext,
            ciphertext_len,
        })
    }
}

lazy_static! {
    static ref ENGINE: Mutex<APKSessionEngine> = Mutex::new(APKSessionEngine::new());
    /// Stored JavaVM for Rust → Kotlin callbacks.
    static ref JAVA_VM: Mutex<Option<jni::JavaVM>> = Mutex::new(None);
    /// Global references to the Kotlin callback classes, resolved once during
    /// `JNI_OnLoad` and keyed by the class name in `callback_registrations()`.
    ///
    /// Not a convenience cache — a correctness requirement. A native thread
    /// attached with `AttachCurrentThread` has no Java frames on its stack, so
    /// `FindClass` there falls back to the **system** class loader and cannot
    /// see application classes. The Agent2 callback is dispatched from the
    /// tokio session thread, which is exactly that case. `JNI_OnLoad` runs on
    /// the thread that called `System.loadLibrary`, which does have the app
    /// class loader, so the lookup happens there and is kept as a global ref.
    static ref CALLBACK_CLASSES: Mutex<HashMap<&'static str, jni::objects::GlobalRef>> =
        Mutex::new(HashMap::new());
}

/// The cached class for one callback, or `None` before `JNI_OnLoad` has run.
fn callback_class(class: &'static str) -> Option<jni::objects::GlobalRef> {
    CALLBACK_CLASSES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(class)
        .cloned()
}

// ── Internal implementation ──────────────────────────────────────────

fn do_init_session() {
    ENGINE.lock().unwrap().init();
}
fn do_shutdown_session() {
    ENGINE.lock().unwrap().shutdown();
}
fn do_tick() {
    tick_and_dispatch_frame(call_kotlin_on_frame);
}
fn do_system_sleep() {
    ENGINE
        .lock()
        .unwrap()
        .handle_event(APKSessionEvent::SystemSleep);
}
fn do_system_wake() {
    ENGINE
        .lock()
        .unwrap()
        .handle_event(APKSessionEvent::SystemWake);
}
fn do_transport_idle() {
    ENGINE
        .lock()
        .unwrap()
        .handle_event(APKSessionEvent::TransportIdle);
}
fn do_transport_wake() {
    ENGINE
        .lock()
        .unwrap()
        .handle_event(APKSessionEvent::TransportWake);
}
fn do_request_screenshot() {
    ENGINE.lock().unwrap().request_screenshot();
}
// do_camera_frame / do_mic_frame removed with the VirtualOffice split.

// ── Byte‑array helper (raw JNI) ─────────────────────────────────────

unsafe fn extract_bytes(env: *mut jni::sys::JNIEnv, arr: jbyteArray) -> Vec<u8> {
    if arr.is_null() {
        return Vec::new();
    }
    let len = ((**env).GetArrayLength.unwrap())(env, arr);
    if len <= 0 {
        return Vec::new();
    }
    let elems = ((**env).GetByteArrayElements.unwrap())(env, arr, std::ptr::null_mut());
    if elems.is_null() {
        return Vec::new();
    }
    let bytes = std::slice::from_raw_parts(elems as *const u8, len as usize).to_vec();
    ((**env).ReleaseByteArrayElements.unwrap())(env, arr, elems, 0);
    bytes
}

// ── JNI wrappers — no‑arg ───────────────────────────────────────────

/// Renounce this device's identity, so the host stops recognising it.
///
/// The next connection generates a new key and the host refuses it as unknown
/// until the owner pairs again. Returns true when the stored key is gone,
/// including when there was nothing to remove.
#[no_mangle]
unsafe extern "C" fn jni_forget_identity(
    _e: *mut jni::sys::JNIEnv,
    _c: jclass,
) -> jni::sys::jboolean {
    match APP_DATA_DIR.get() {
        Some(dir) => match identity::forget(&identity::identity_file(dir)) {
            Ok(()) => {
                rd_log!("device identity forgotten; the next connection will need a new QR");
                1
            }
            Err(e) => {
                rd_log!("could not forget device identity: {e}");
                0
            }
        },
        // Nothing was ever stored, so there is nothing to forget.
        None => 1,
    }
}

/// Kotlin tells us where its app-private directory is, once, at startup.
///
/// Idempotent: a second call is ignored rather than allowed to move the
/// identity out from under a live session.
#[no_mangle]
unsafe extern "C" fn jni_set_data_dir(
    e: *mut jni::sys::JNIEnv,
    _c: jclass,
    dir: jni::sys::jstring,
) {
    let Ok(mut env) = jni::JNIEnv::from_raw(e) else {
        return;
    };
    let obj = jni::objects::JString::from_raw(dir);
    let Ok(text) = env.get_string(&obj) else {
        rd_log!("set_data_dir: unreadable path");
        return;
    };
    let path: String = text.into();
    set_data_dir(&path);
}

unsafe extern "C" fn jni_init_session(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_init_session();
}
unsafe extern "C" fn jni_shutdown(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_shutdown_session();
}
unsafe extern "C" fn jni_tick(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_tick();
}
unsafe extern "C" fn jni_sleep(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_system_sleep();
}
unsafe extern "C" fn jni_wake(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_system_wake();
}
unsafe extern "C" fn jni_tidle(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_transport_idle();
}
unsafe extern "C" fn jni_twake(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_transport_wake();
}
unsafe extern "C" fn jni_screenshot(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    do_request_screenshot();
}

/// Attach the Kotlin `FrameReceiver`. From here each tick delivers at most one
/// frame through `FrameReceiver.rdOnFrame`.
unsafe extern "C" fn jni_register_frame_receiver(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    ENGINE.lock().unwrap().set_frame_receiver_registered(true);
}

/// Detach it again. Kotlin calls this when the last viewer goes away, so a
/// backgrounded app is not decoding JPEGs at nothing — without it a receiver
/// stays registered for the life of the process.
unsafe extern "C" fn jni_unregister_frame_receiver(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    ENGINE.lock().unwrap().set_frame_receiver_registered(false);
}

/// `RDRust.sendCommand(json): Boolean` — Kotlin's only way into the live Noise
/// session. Returns false rather than throwing, and never blocks: validation is
/// synchronous and the enqueue is `try_send`, so calling this from the Android
/// main thread cannot wait on the network.
unsafe extern "C" fn jni_send_command(
    env: *mut jni::sys::JNIEnv,
    _c: jclass,
    json: jni::sys::jstring,
) -> jni::sys::jboolean {
    if json.is_null() {
        return jni::sys::JNI_FALSE;
    }
    let mut env = match jni::JNIEnv::from_raw(env) {
        Ok(e) => e,
        Err(_) => return jni::sys::JNI_FALSE,
    };
    // JNI hands us modified UTF-8; `get_string` rejects anything not decodable.
    let json: String = match env.get_string(&jni::objects::JString::from_raw(json)) {
        Ok(s) => s.into(),
        Err(_) => return jni::sys::JNI_FALSE,
    };
    match submit_session_command(&json) {
        Ok(()) => jni::sys::JNI_TRUE,
        Err(reason) => {
            // Reason only. The command body may carry session-scoped detail.
            rd_log!("[android_client] command rejected: {reason:?}");
            jni::sys::JNI_FALSE
        }
    }
}

/// `RDRust.stopSession()` — ask the owning loop to close cleanly.
unsafe extern "C" fn jni_stop_session(_e: *mut jni::sys::JNIEnv, _c: jclass) {
    if let Err(reason) = request_session_shutdown() {
        rd_log!("[android_client] stopSession: {reason:?}");
    }
}

// The camera/mic JNI wrappers (jni_cam_start/stop, jni_mic_start/stop, and the
// frame handlers below) were removed with the RemoteDexter ⇔ VirtualOffice
// split — driving the phone's camera and mic is a VO-agent feature. The matching
// `MediaBindings` registration is gone from JNI_OnLoad; the Kotlin
// `MediaBindings`/`CameraController`/`MicController` classes were deleted too.

// ── Session status, observable from Kotlin ──────────────────────────
//
// `startSession` returns the instant the worker thread is spawned, so its
// return tells the caller only that the call was accepted — never whether the
// TCP connect, the Noise handshake or the key pin succeeded. All of those
// happen later, on another thread, and previously had no way to report back:
// the app could not distinguish a live session from a total failure, and
// neither could the user.
//
// This is a single latest-state string rather than an event stream on purpose.
// Kotlin polls it; there is no callback to register, no lifetime to manage
// across the JNI boundary, and no risk of a queued event arriving after the
// Activity that cared about it has gone.

/// Current session state, mirrored to Kotlin via `RDRust.sessionStatus()`.
static SESSION_STATUS: Mutex<Option<String>> = Mutex::new(None);

/// Record the session state. Values are `state|detail`, where `state` is one of
/// `idle`, `connecting`, `connected`, `failed` — parsed by `RDRust.sessionStatus`.
fn set_session_status(state: &str, detail: &str) {
    if let Ok(mut s) = SESSION_STATUS.lock() {
        *s = Some(format!("{state}|{detail}"));
    }
    rd_log!("[android_client] session {state}: {detail}");
}

fn session_status_string() -> String {
    SESSION_STATUS
        .lock()
        .ok()
        .and_then(|s| s.clone())
        .unwrap_or_else(|| "idle|no session started".to_string())
}

/// `RDRust.sessionStatus(): String` — latest state of the session worker.
unsafe extern "C" fn jni_session_status(
    env: *mut jni::sys::JNIEnv,
    _c: jclass,
) -> jni::sys::jstring {
    let env = match jni::JNIEnv::from_raw(env) {
        Ok(e) => e,
        Err(_) => return std::ptr::null_mut(),
    };
    match env.new_string(session_status_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ── JNI wrappers — startSession ─────────────────────────────────────

unsafe extern "C" fn jni_start_session(
    env: *mut jni::sys::JNIEnv,
    _c: jclass,
    host_ip: jni::sys::jstring,
    port: jint,
    session_token: jni::sys::jstring,
    host_pubkey: jbyteArray,
) {
    // Pin the host's Noise static key BEFORE building the JNIEnv wrapper, while
    // we still have the raw env pointer for the byte-array helper.
    let expected_host_pub = extract_bytes(env, host_pubkey);

    let mut env = match jni::JNIEnv::from_raw(env) {
        Ok(e) => e,
        Err(_) => return,
    };
    let host_ip: String = match env.get_string(&jni::objects::JString::from_raw(host_ip)) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let session_token: String =
        match env.get_string(&jni::objects::JString::from_raw(session_token)) {
            Ok(s) => s.into(),
            Err(_) => return,
        };
    let port: u16 = port as u16;

    // Fail closed: a 32-byte pinned host key is mandatory. Without it we cannot
    // authenticate the host, so we refuse to connect at all.
    if expected_host_pub.len() != 32 {
        set_session_status("failed", "missing or invalid 32-byte host pin");
        return;
    }

    set_session_status("connecting", &format!("{host_ip}:{port}"));

    std::thread::spawn(move || {
        let endpoint = format!("{host_ip}:{port}");
        match block_on_client_handshake(host_ip, port, session_token, expected_host_pub) {
            // The handshake future returning Ok means the session loop ran to a
            // clean close, not that it is still live — so this is "idle", not
            // "connected". `connected` is set from inside the handshake, at the
            // point the pin is actually verified.
            Ok(()) => set_session_status("idle", &format!("session to {endpoint} ended")),
            Err(e) => set_session_status("failed", &format!("{endpoint}: {e}")),
        }
    });
}

/// `RDRust.startRelaySession(relayIp, relayPort, session, sessionToken, hostPubkey)`.
///
/// The v5 route. A separate native from `startSession` for the same reason
/// `startPairedSession` is: what matters to a reader of the Kotlin is WHICH
/// ROUTE is being taken, and a method that decides it from whether a string
/// happens to be blank hides exactly that. It also means the APK cannot reach
/// the relay path by accident from a direct invite whose address failed to
/// parse.
///
/// The host pin is mandatory and still 32 bytes. Going through a relay changes
/// nothing about who the host has to prove itself to be.
unsafe extern "C" fn jni_start_relay_session(
    env: *mut jni::sys::JNIEnv,
    _c: jclass,
    relay_ip: jni::sys::jstring,
    relay_port: jint,
    session: jni::sys::jstring,
    session_token: jni::sys::jstring,
    host_pubkey: jbyteArray,
) {
    let expected_host_pub = extract_bytes(env, host_pubkey);

    let mut env = match jni::JNIEnv::from_raw(env) {
        Ok(e) => e,
        Err(_) => return,
    };
    let relay_ip: String = match env.get_string(&jni::objects::JString::from_raw(relay_ip)) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let session: String = match env.get_string(&jni::objects::JString::from_raw(session)) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let session_token: String =
        match env.get_string(&jni::objects::JString::from_raw(session_token)) {
            Ok(s) => s.into(),
            Err(_) => return,
        };
    let relay_port: u16 = relay_port as u16;

    if expected_host_pub.len() != 32 {
        set_session_status("failed", "missing or invalid 32-byte host pin");
        return;
    }
    if session.is_empty() {
        set_session_status("failed", "relay invite carried no session");
        return;
    }

    // The status line names the RELAY, never the session id: the id is what
    // this device presents to reach the host, and `sessionStatus()` is read by
    // the UI and copied into logs.
    let endpoint = format!("relay {relay_ip}:{relay_port}");
    set_session_status("connecting", &endpoint);

    std::thread::spawn(move || {
        match block_on_relay_handshake(
            relay_ip,
            relay_port,
            session,
            session_token,
            expected_host_pub,
        ) {
            Ok(()) => set_session_status("idle", &format!("session via {endpoint} ended")),
            Err(e) => set_session_status("failed", &format!("{endpoint}: {e}")),
        }
    });
}

/// `RDRust.startPairedSession(hostIp, port, hostPubkey)` — reconnect with no QR.
///
/// Deliberately a separate native from `startSession` rather than the same one
/// with an empty token. The distinction that matters to a reader of the Kotlin
/// is *which credential is being presented*, and a method that decides it from
/// whether a string happens to be blank hides exactly that. It also means the
/// APK cannot reach the token-less path by passing a token it failed to read.
///
/// The host pin is still mandatory and still 32 bytes: this drops the device's
/// credential, never the host's.
unsafe extern "C" fn jni_start_paired_session(
    env: *mut jni::sys::JNIEnv,
    _c: jclass,
    host_ip: jni::sys::jstring,
    port: jint,
    host_pubkey: jbyteArray,
) {
    let expected_host_pub = extract_bytes(env, host_pubkey);

    let mut env = match jni::JNIEnv::from_raw(env) {
        Ok(e) => e,
        Err(_) => return,
    };
    let host_ip: String = match env.get_string(&jni::objects::JString::from_raw(host_ip)) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let port: u16 = port as u16;

    if expected_host_pub.len() != 32 {
        set_session_status("failed", "missing or invalid 32-byte host pin");
        return;
    }

    set_session_status("connecting", &format!("{host_ip}:{port}"));

    std::thread::spawn(move || {
        let endpoint = format!("{host_ip}:{port}");
        match block_on_paired_handshake(host_ip, port, expected_host_pub) {
            Ok(()) => set_session_status("idle", &format!("session to {endpoint} ended")),
            Err(e) => set_session_status("failed", &format!("{endpoint}: {e}")),
        }
    });
}

/// `RDRust.startPairedRelaySession(relayIp, relayPort, hostPubkey, session)` —
/// reconnect with no QR, through the relay this device paired through.
///
/// Its own native for the reason `startPairedSession` is: which credential is
/// presented must be visible in the call, not decided by a blank string.
///
/// ## The parameter order is deliberate
///
/// The natural order — address, port, session, pin — gives
/// `(String, Int, String, ByteArray)`, which is EXACTLY the shape and JNI
/// descriptor of `startSession(hostIp, port, sessionToken, hostPubkey)`. A call
/// site that passed a stored relay session id where a pairing token belongs, or
/// the other way round, would compile without a murmur. Putting the pin before
/// the session makes this `(String, Int, ByteArray, String)`, so the two can
/// never be confused by the compiler, and a test pins that no two natives share
/// a descriptor.
///
/// ## Never in a status line
///
/// The endpoint is `relay <addr>:<port>`, as for the relay pairing path. The
/// session id is a credential against the relay — a stranger holding one can
/// occupy the host's join slot — and the status string reaches the log and the
/// screen.
///
/// ## Failures the existing natives stay silent about
///
/// They return without touching the status when a Java string cannot be read,
/// which leaves the Kotlin side reading whatever the LAST session reported. This
/// one says so. And a port the Kotlin side got wrong is refused rather than
/// truncated by `as u16` into a different, valid-looking port.
unsafe extern "C" fn jni_start_paired_relay_session(
    env: *mut jni::sys::JNIEnv,
    _c: jclass,
    relay_ip: jni::sys::jstring,
    relay_port: jint,
    host_pubkey: jbyteArray,
    session: jni::sys::jstring,
) {
    let expected_host_pub = extract_bytes(env, host_pubkey);

    let mut env = match jni::JNIEnv::from_raw(env) {
        Ok(e) => e,
        Err(_) => {
            set_session_status("failed", "could not read the reconnect request");
            return;
        }
    };
    let relay_ip: String = match env.get_string(&jni::objects::JString::from_raw(relay_ip)) {
        Ok(s) => s.into(),
        Err(_) => {
            set_session_status("failed", "could not read the stored relay address");
            return;
        }
    };
    let session: String = match env.get_string(&jni::objects::JString::from_raw(session)) {
        Ok(s) => s.into(),
        Err(_) => {
            set_session_status("failed", "could not read the stored relay session");
            return;
        }
    };
    let Some(relay_port) = relay_port_from(relay_port) else {
        set_session_status("failed", "the stored relay port is not a port");
        return;
    };

    if expected_host_pub.len() != 32 {
        set_session_status("failed", "missing or invalid 32-byte host pin");
        return;
    }
    if session.is_empty() {
        set_session_status("failed", "no relay session is stored for this host");
        return;
    }

    let endpoint = format!("relay {relay_ip}:{relay_port}");
    set_session_status("connecting", &endpoint);

    std::thread::spawn(move || {
        match block_on_paired_relay_handshake(relay_ip, relay_port, session, expected_host_pub) {
            Ok(()) => set_session_status("idle", &format!("session via {endpoint} ended")),
            Err(e) => set_session_status("failed", &format!("{endpoint}: {e}")),
        }
    });
}

/// A port from the Java side, or `None` if it is not one.
///
/// `as u16` would turn 70000 into 4464 and 0 into "any port": a wrong stored
/// value would be dialled as a different, plausible one.
fn relay_port_from(port: jint) -> Option<u16> {
    match u16::try_from(port) {
        Ok(0) | Err(_) => None,
        Ok(p) => Some(p),
    }
}

// ── Client handshake implementation ──────────────────────────────────

/// Noise pattern used by the live initiator handshake in `noise_transport_handshake`.
const NOISE_PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256";

/// Performs the full Noise_XX three-message handshake over a live TCP socket.
/// Returns a `snow::TransportState` ready for encrypting/decrypting frames.
async fn noise_transport_handshake(
    stream: &mut TcpStream,
    local_priv: &[u8],
    initiator: bool,
    expected_host_pub: &[u8],
) -> Result<snow::TransportState> {
    // No prologue. The token used to be bound in here, which only ever made
    // sense because it had already been sent in the clear a moment earlier. It
    // now travels inside the transport, so there is nothing to bind and no
    // `RD_BIND_TOKEN_PROLOGUE` switch to turn the binding off.
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?).local_private_key(local_priv);

    let mut hs = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };

    let mut buf = vec![0u8; 65535];

    // XX pattern: -> e, <- e ee s es, -> s se
    // Initiator sends msg1, reads msg2, sends msg3
    // Responder reads msg1, sends msg2, reads msg3
    if initiator {
        // -> e
        let len = hs.write_message(&[], &mut buf)?;
        send_noise_msg(stream, &buf[..len]).await?;

        // <- e, ee, s, es  (this message carries the host's static public key)
        let msg = recv_noise_msg(stream).await?;
        hs.read_message(&msg, &mut buf)?;

        // ── HOST KEY PINNING (closes the MITM hole) ──────────────────
        // The host's static key is now known. Abort unless it matches the key
        // that was pinned out-of-band via the invite (QR/NFC/Wi-Fi). A MITM
        // cannot present this key without the host's private key.
        match hs.get_remote_static() {
            Some(remote_static) if remote_static == expected_host_pub => {}
            Some(_) => anyhow::bail!("host key pin MISMATCH — aborting (possible MITM)"),
            None => anyhow::bail!("host did not present a static key — aborting"),
        }

        // -> s, se
        let len = hs.write_message(&[], &mut buf)?;
        send_noise_msg(stream, &buf[..len]).await?;
    } else {
        // <- e
        let msg = recv_noise_msg(stream).await?;
        hs.read_message(&msg, &mut buf)?;

        // -> e, ee, s, es
        let len = hs.write_message(&[], &mut buf)?;
        send_noise_msg(stream, &buf[..len]).await?;

        // <- s, se
        let msg = recv_noise_msg(stream).await?;
        hs.read_message(&msg, &mut buf)?;
    }

    Ok(hs.into_transport_mode()?)
}

/// Write one length-prefixed message in ONE write.
///
/// It used to be two — the four-byte length, then the body — which put every
/// input event on the wire as two packets, and with Nagle on held the body
/// until the length was acknowledged. One buffer is one segment for anything
/// that fits, and half the packets for a lossy link to lose.
async fn send_noise_msg<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> Result<()> {
    if data.is_empty() || data.len() > MAX_NOISE_FRAME {
        anyhow::bail!("noise message out of bounds: {}", data.len());
    }
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(data);
    stream.write_all(&framed).await?;
    Ok(())
}

async fn recv_noise_msg(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_NOISE_FRAME {
        anyhow::bail!("noise message out of bounds: {len}");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Connect, own the session for its whole life, then release the channel.
///
/// This is the production session path. The JNI start method runs exactly this
/// on its own thread and runtime; the host-side integration tests drive the
/// same function directly, so the tests exercise the real ownership and
/// lifecycle rather than a parallel arrangement built for testing.
pub async fn run_pinned_session(
    host_ip: String,
    port: u16,
    token: String,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    run_session(
        ClientReach::Direct {
            host: host_ip,
            port,
        },
        ClientAuth::Token(token),
        expected_host_pub,
    )
    .await
}

/// The same session, reached THROUGH A RELAY.
///
/// Same ownership, same command channel, same loop, same pin. Only the route
/// differs, and the relay is out of the picture the moment the splice begins.
pub async fn run_relay_session(
    relay: String,
    relay_port: u16,
    session: String,
    token: String,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    run_session(
        ClientReach::ViaRelay {
            relay,
            relay_port,
            session,
        },
        ClientAuth::Token(token),
        expected_host_pub,
    )
    .await
}

/// How this connection intends to prove who it is.
///
/// An enum rather than "an empty token means paired". That convention exists on
/// the wire because the host has to read *something*, but it must not exist in
/// the code that decides: a `String` that is empty by accident is
/// indistinguishable from one that is empty on purpose, and the accident would
/// silently downgrade an invite into a token-less attempt. Here the two cases
/// cannot be confused, and adding a third would not compile until every match
/// handled it.
enum ClientAuth {
    /// A one-use token from a freshly scanned QR. Enrolls the device.
    Token(String),
    /// Nothing but this device's own Noise static key, which the host must
    /// already have enrolled.
    Paired,
}

/// Reconnect as an already-enrolled device — the no-QR path.
///
/// Same session ownership, same command channel, same loop as
/// [`run_pinned_session`]; only the credential differs.
pub async fn run_paired_session(
    host_ip: String,
    port: u16,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    run_session(
        ClientReach::Direct {
            host: host_ip,
            port,
        },
        ClientAuth::Paired,
        expected_host_pub,
    )
    .await
}

/// [`run_paired_session`] through a relay: a token-less reconnect to a host this
/// device is already enrolled with, presenting the session id it kept from its
/// relay pairing. The production session loop, so a test driving this drives
/// what the phone runs.
pub async fn run_paired_relay_session(
    relay: String,
    relay_port: u16,
    session: String,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    run_session(
        ClientReach::ViaRelay {
            relay,
            relay_port,
            session,
        },
        ClientAuth::Paired,
        expected_host_pub,
    )
    .await
}

async fn run_session(
    reach: ClientReach,
    auth: ClientAuth,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    // Claim the channel BEFORE connecting, so a second concurrent start is
    // refused while the first is still handshaking rather than racing it.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
    let Some(generation) = claim_session(tx) else {
        anyhow::bail!("a session already owns the command channel");
    };

    // Capture the status line before the reach is handed over. It names the
    // endpoint and NEVER the relay session id.
    let endpoint = reach.endpoint();

    let result = async {
        let mut session = match (reach, auth) {
            (ClientReach::Direct { host, port }, ClientAuth::Token(token)) => {
                PinnedNoiseSession::connect(host, port, token, expected_host_pub).await?
            }
            (ClientReach::Direct { host, port }, ClientAuth::Paired) => {
                PinnedNoiseSession::connect_paired(host, port, expected_host_pub).await?
            }
            (
                ClientReach::ViaRelay {
                    relay,
                    relay_port,
                    session,
                },
                ClientAuth::Token(token),
            ) => {
                PinnedNoiseSession::connect_via_relay(
                    relay,
                    relay_port,
                    session,
                    token,
                    expected_host_pub,
                )
                .await?
            }
            // A paired reconnect through a relay. It used to be refused: the
            // relay issued a random session id per registration, so the id a
            // phone paired against died with the host's next restart and there
            // was nothing to reconnect to. An enrolled host now keeps its id for
            // as long as the relay runs, and the phone keeps the id it paired
            // with — never invented here, only presented.
            (
                ClientReach::ViaRelay {
                    relay,
                    relay_port,
                    session,
                },
                ClientAuth::Paired,
            ) => {
                PinnedNoiseSession::connect_paired_via_relay(
                    relay,
                    relay_port,
                    session,
                    expected_host_pub,
                )
                .await?
            }
        };
        // The only point at which the host has proved it holds the pinned key.
        // Everything before this is an unauthenticated socket.
        set_session_status("connected", &format!("{endpoint} — host key pinned"));
        ENGINE
            .lock()
            .unwrap()
            .handle_event(APKSessionEvent::TransportConnected);
        start_noise_session_loop(&mut session, &mut rx).await
    }
    .await;

    // Always hand the channel back, and only if it is still ours.
    release_session(generation);
    ENGINE
        .lock()
        .unwrap()
        .handle_event(APKSessionEvent::TransportDisconnected);
    result
}

/// Test-only observer for inbound Agent2 JSON, installed through the engine's
/// real callback seam (the same one `JNI_OnLoad` uses for Kotlin). Lets the
/// host-side loopback tests see what actually crossed the encrypted link.
#[cfg(feature = "test-support")]
pub fn set_agent2_observer_for_test<F: Fn(&str) + Send + Sync + 'static>(observer: F) {
    ENGINE.lock().unwrap().set_agent2_callback(observer);
}

fn block_on_client_handshake(
    host_ip: String,
    port: u16,
    token: String,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(run_pinned_session(
        host_ip,
        port,
        token,
        expected_host_pub,
    ))
}

fn block_on_relay_handshake(
    relay: String,
    relay_port: u16,
    session: String,
    token: String,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(run_relay_session(
        relay,
        relay_port,
        session,
        token,
        expected_host_pub,
    ))
}

fn block_on_paired_handshake(host_ip: String, port: u16, expected_host_pub: Vec<u8>) -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(run_paired_session(host_ip, port, expected_host_pub))
}

fn block_on_paired_relay_handshake(
    relay: String,
    relay_port: u16,
    session: String,
    expected_host_pub: Vec<u8>,
) -> Result<()> {
    tokio::runtime::Runtime::new()?.block_on(run_paired_relay_session(
        relay,
        relay_port,
        session,
        expected_host_pub,
    ))
}

/// What one decrypted host message turned out to be.
#[derive(Debug, Clone, PartialEq)]
pub enum InboundMessage {
    /// A JSON command/response destined for the Agent2 engine.
    Command(String),
    /// A stream chunk that has not completed a frame yet.
    ChunkPending,
    /// A stream chunk that completed a whole video frame.
    Frame(stream_chunk::ReassembledFrame),
    /// Neither a well-formed chunk nor text — dropped rather than guessed at.
    Unrecognized,
}

/// Route one decrypted host message.
///
/// The host multiplexes two kinds of message onto the single encrypted stream
/// and they are told apart by the first byte: `0x01` is a binary stream chunk
/// carrying `stream_chunk`'s 14-byte header, and a JSON command response always
/// begins `{` (0x7B). The chunk parser is `stream_chunk`'s — the same code the
/// host produces with — so the two ends cannot drift apart.
///
/// This replaces a loop that ran *every* message through `str::from_utf8` and
/// dropped whatever failed. Stream chunks are binary and generally not valid
/// UTF-8, so every frame the host sent was being silently discarded.
pub fn classify_inbound(
    reassembler: &mut stream_chunk::FrameReassembler,
    plaintext: &[u8],
) -> InboundMessage {
    // Block 10: the KIND says what this is. Sniffing the first byte was the old
    // way and it was a guess — a JSON document whose first byte happened to be
    // 0x01 is not possible today, but "not possible today" is the reasoning
    // that produces protocol bugs later.
    let envelope = match wire::decode_exact(plaintext) {
        Ok(e) => e,
        Err(_) => return InboundMessage::Unrecognized,
    };
    match envelope.kind {
        wire::Kind::FrameChunkV1 => {
            // Still checked, because the envelope bounds the LENGTH and says
            // nothing about whether the payload is a well-formed chunk.
            if envelope.payload.len() < stream_chunk::HEADER_LEN {
                return InboundMessage::Unrecognized;
            }
            match reassembler.push(&envelope.payload) {
                Some(frame) => InboundMessage::Frame(frame),
                None => InboundMessage::ChunkPending,
            }
        }
        wire::Kind::ControlJson | wire::Kind::InputV1 => {
            match String::from_utf8(envelope.payload) {
                Ok(json) => InboundMessage::Command(json),
                Err(_) => InboundMessage::Unrecognized,
            }
        }
        // A host answering our liveness check. Nothing to route onward, and
        // NOT Unrecognized — that would log a fault for a healthy exchange.
        wire::Kind::Ping => InboundMessage::ChunkPending,
        wire::Kind::Close => InboundMessage::Unrecognized,
    }
}

/// Which envelope kind carries this outbound command.
///
/// Input gets its own kind rather than riding `ControlJson`, and the reason is
/// the ceiling: `InputV1` is bounded at 4 KiB while control JSON may be 16 KiB.
/// Input is the highest-frequency thing on this link and the only one that
/// reaches the host's injection path, so it is worth being the tightest bound
/// of the two — a peer cannot spend the control budget on the input path.
///
/// Anything unparseable is called `ControlJson`, which is the strict choice:
/// that kind runs the depth-bounded JSON check, so a malformed command is
/// refused by our OWN encoder before it reaches the wire, rather than being
/// waved through as opaque input bytes.
fn kind_for_command(payload: &[u8]) -> wire::Kind {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(payload).ok();
    let ty = parsed
        .as_ref()
        .and_then(|v| v.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    if ty == "input_event" {
        wire::Kind::InputV1
    } else {
        wire::Kind::ControlJson
    }
}

/// Hand a completed video frame to the session engine, which owns the inbound
/// queue, its drop-oldest policy and the backpressure signal back to the host.
///
/// Every field the reassembler recovered from the wire is carried through
/// unchanged — the viewer is never handed an invented size or sequence number.
/// The only value produced here is the receipt timestamp, in **microseconds**
/// to match the engine's `frame_interval_hint` (16_000 = 16 ms).
fn deliver_video_frame(frame: stream_chunk::ReassembledFrame) {
    FRAMES_IN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    ENGINE
        .lock()
        .unwrap()
        .handle_event(APKSessionEvent::InboundFrame(FrameEnvelope {
            timestamp,
            sequence: frame.seq,
            width: frame.width,
            height: frame.height,
            keyframe: frame.keyframe,
            data: frame.data,
        }));
}

/// Route one inbound Agent2 JSON message to Kotlin, **with `ENGINE` unlocked**.
///
/// Same rule as `tick_and_dispatch_frame`, and for a sharper reason: the Kotlin
/// side of this callback is `Agent2Bindings` → `Agent2Router.handle`, which
/// calls straight back into `rd_on_clipboard_update`, `rd_on_system_wake` and
/// `rd_on_system_sleep`. Those take `ENGINE`. Since std's Mutex is not
/// reentrant, dispatching under the lock deadlocks the session thread on the
/// first such host command — and leaves it holding the lock the tick path needs,
/// so the viewer freezes with it.
fn dispatch_agent2_command(json: &str) {
    let callback = ENGINE.lock().unwrap().agent2_callback();
    if let Some(cb) = callback {
        cb(json);
    }
}

/// One tick of the client's frame path.
///
/// The lock discipline is the whole point of this function existing:
///
/// 1. lock `ENGINE`,
/// 2. run the media scheduler,
/// 3. take at most one frame — the newest — if a viewer is attached,
/// 4. **release `ENGINE`**,
/// 5. only then invoke the receiver.
///
/// A JNI call made while holding `ENGINE` would deadlock the client the moment
/// Kotlin re-entered any native method, and decoding a JPEG under it would
/// stall the Noise loop behind Android's rendering. Taking `deliver` as a
/// parameter keeps that discipline testable without a JVM: production passes
/// the Kotlin callback, the tests pass a closure that proves the lock is free.
///
/// With no receiver attached, frames are left in the engine's bounded queue
/// (`MAX_FRAMES`, drop-oldest) rather than accumulating for a UI that may never
/// arrive. Returns whether a frame was dispatched.
/// Frames that reached the client, and frames that reached the viewer.
///
/// Two counters rather than one, because the gap between them is the whole
/// diagnosis. A black screen has three quite different causes and they are
/// indistinguishable from the outside:
///
/// * `in` not rising — nothing is arriving; the fault is the host or the wire.
/// * `in` rising, `out` flat, receiver NOT registered — frames are arriving and
///   queueing behind a viewer that never attached.
/// * `in` rising, `out` rising — frames are being delivered and the fault is in
///   the renderer.
///
/// This exists because silent frame loss has now cost two debugging sessions.
/// The engine drops frames it cannot queue without a word, and the client
/// logged nothing at all between "connected" and a black picture — so the
/// operator's screen and every log agreed that everything was fine.
static FRAMES_IN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FRAMES_OUT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LAST_HEALTH_LOG: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// How often the stream health line is written.
///
/// Rate-limited rather than per frame: at 20fps a per-frame line is 20 lines a
/// second of noise that buries everything else in logcat, which is how a log
/// stops being read at all.
const HEALTH_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Say how the stream is doing, at most every [`HEALTH_LOG_INTERVAL`].
fn log_stream_health(registered: bool, queued: usize) {
    let mut last = LAST_HEALTH_LOG.lock().unwrap_or_else(|p| p.into_inner());
    let now = std::time::Instant::now();
    let due = match *last {
        None => true,
        Some(t) => now.duration_since(t) >= HEALTH_LOG_INTERVAL,
    };
    if !due {
        return;
    }
    *last = Some(now);
    let inbound = FRAMES_IN.load(std::sync::atomic::Ordering::Relaxed);
    let outbound = FRAMES_OUT.load(std::sync::atomic::Ordering::Relaxed);
    rd_log!(
        "[android_client] stream health: received={inbound} delivered={outbound} \
         queued={queued} viewer_attached={registered}"
    );
}

fn tick_and_dispatch_frame<F: FnOnce(&FrameEnvelope)>(deliver: F) -> bool {
    let (taken, registered, queued) = {
        let mut engine = ENGINE.lock().unwrap();
        engine.media_scheduler_tick();
        let registered = engine.is_frame_receiver_registered();
        let taken = if registered {
            engine.consume_latest_frame()
        } else {
            None
        };
        (taken, registered, engine.queued_frame_count())
    };
    // Outside the engine lock: the log must never be able to hold it.
    log_stream_health(registered, queued);
    match taken {
        Some(frame) => {
            FRAMES_OUT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            deliver(&frame);
            true
        }
        None => false,
    }
}

// ── Kotlin → session command channel ─────────────────────────────────
//
// `PinnedNoiseSession` is deliberately single-owner: Noise transport nonces are
// sequential, so a second writer or a shared/locked handle would desynchronize
// them. Kotlin therefore never touches the session. It hands JSON to a bounded
// channel, and the one task that owns the session drains it. That task is the
// only caller of `send`/`recv`, which keeps nonce ordering by construction.

/// Work the session-owning loop accepts from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCommand {
    /// Encrypt and send this already-validated JSON payload.
    Send(Vec<u8>),
    /// Leave the loop and close the connection cleanly.
    Shutdown,
}

/// Bounded so a Kotlin caller cannot grow native memory without limit. Small on
/// purpose: these are interactive control messages, not a data pipe.
const COMMAND_CHANNEL_CAPACITY: usize = 32;

/// Largest plaintext a command may be. The framed ciphertext must stay within
/// `MAX_NOISE_FRAME`, and AES-GCM adds a 16-byte tag.
pub const MAX_COMMAND_PLAINTEXT: usize = MAX_NOISE_FRAME - 16;

/// Why a command was not accepted. Carries no payload — a rejection reason is
/// safe to log, the command itself is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandRejection {
    Empty,
    NotJsonObject,
    TooLarge,
    NoSession,
    ChannelFull,
    ChannelClosed,
}

/// The sender registered by the currently-owning session, tagged with the
/// generation that created it so a departing session cannot unregister its
/// successor.
struct SessionCommandSink {
    generation: u64,
    tx: tokio::sync::mpsc::Sender<SessionCommand>,
}

lazy_static! {
    static ref COMMAND_SINK: Mutex<Option<SessionCommandSink>> = Mutex::new(None);
}

static NEXT_SESSION_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Claim ownership of the command channel for a new session.
///
/// Returns `None` when a session already owns it, so a second concurrent
/// `startSession` is refused rather than silently displacing the first — which
/// would leave two sockets alive with one of them unreachable.
fn claim_session(tx: tokio::sync::mpsc::Sender<SessionCommand>) -> Option<u64> {
    let mut sink = COMMAND_SINK.lock().unwrap_or_else(|p| p.into_inner());
    if sink.is_some() {
        return None;
    }
    let generation = NEXT_SESSION_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    *sink = Some(SessionCommandSink { generation, tx });
    Some(generation)
}

/// Release the channel, but only if it is still ours. Without the generation
/// check a slow teardown could unregister the sender of a session that started
/// after it.
fn release_session(generation: u64) {
    let mut sink = COMMAND_SINK.lock().unwrap_or_else(|p| p.into_inner());
    if sink.as_ref().map(|s| s.generation) == Some(generation) {
        *sink = None;
    }
}

/// Validate and enqueue one command from Kotlin.
///
/// Validation happens here, at the trusted Rust boundary, not in Kotlin. Never
/// blocks: `try_send` fails fast so a JNI call from the Android main thread can
/// never wait on network I/O.
pub fn submit_session_command(json: &str) -> std::result::Result<(), CommandRejection> {
    if json.trim().is_empty() {
        return Err(CommandRejection::Empty);
    }
    if json.len() > MAX_COMMAND_PLAINTEXT {
        return Err(CommandRejection::TooLarge);
    }
    // The host parses these as JSON objects; reject anything else before it can
    // occupy a channel slot or a Noise nonce.
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(v) if v.is_object() => {}
        _ => return Err(CommandRejection::NotJsonObject),
    }

    let sink = COMMAND_SINK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(sink) = sink.as_ref() else {
        return Err(CommandRejection::NoSession);
    };
    match sink
        .tx
        .try_send(SessionCommand::Send(json.as_bytes().to_vec()))
    {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(CommandRejection::ChannelFull),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            Err(CommandRejection::ChannelClosed)
        }
    }
}

/// Ask the owning session to shut down cleanly.
pub fn request_session_shutdown() -> std::result::Result<(), CommandRejection> {
    let sink = COMMAND_SINK.lock().unwrap_or_else(|p| p.into_inner());
    let Some(sink) = sink.as_ref() else {
        return Err(CommandRejection::NoSession);
    };
    match sink.tx.try_send(SessionCommand::Shutdown) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(CommandRejection::ChannelFull),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            Err(CommandRejection::ChannelClosed)
        }
    }
}

/// Encrypted session loop. The sole owner of the Noise transport: it decrypts
/// inbound messages and encrypts outbound commands, so nonces on both
/// directions advance from one place.
///
/// `recv()` is cancel-safe (see `PinnedNoiseSession::rx_buf`), which is what
/// makes it sound to race it against the command channel here.
async fn start_noise_session_loop(
    session: &mut PinnedNoiseSession,
    commands: &mut tokio::sync::mpsc::Receiver<SessionCommand>,
) -> Result<()> {
    let mut reassembler = stream_chunk::FrameReassembler::new();
    loop {
        tokio::select! {
            inbound = session.recv() => {
                let frame = inbound?;
                match classify_inbound(&mut reassembler, &frame.plaintext) {
                    InboundMessage::Command(json) => dispatch_agent2_command(&json),
                    InboundMessage::Frame(f) => deliver_video_frame(f),
                    InboundMessage::ChunkPending => {}
                    InboundMessage::Unrecognized => {
                        rd_log!(
                            "[android_client] dropping unrecognized {}-byte message",
                            frame.plaintext.len()
                        );
                    }
                }
            }
            command = commands.recv() => {
                match command {
                    Some(SessionCommand::Send(payload)) => {
                        // Block 10: framed before it goes out. A payload this
                        // client cannot envelope is one the host would refuse,
                        // so it is dropped HERE with a reason rather than sent
                        // and denied — the peer's refusal would arrive as a
                        // generic error with nothing pointing at the cause.
                        // The two failures here are NOT the same and must
                        // not share a branch.
                        //
                        // A FRAMING error is one bad command: drop it with a
                        // reason and carry on.
                        //
                        // A TRANSPORT error is terminal, because a partial
                        // write leaves the peers' nonce counters disagreeing
                        // and every message after it decrypts to nothing.
                        //
                        // `send_command` collapses both into one Result, which
                        // is right for a caller that just wants to send —
                        // hence the explicit two steps here rather than using
                        // it. Getting this wrong swallows a dead transport and
                        // the session goes quiet with nothing logged.
                        let kind = kind_for_command(&payload);
                        match wire::Envelope::new(kind, 0, payload) {
                            Ok(env) => session.send(&env.encode()).await?,
                            Err(e) => {
                                rd_log!(
                                    "[android_client] refusing to send a malformed {kind:?}: {e:?}"
                                );
                                continue;
                            }
                        };
                    }
                    // Explicit shutdown, or every sender dropped.
                    Some(SessionCommand::Shutdown) | None => return Ok(()),
                }
            }
        }
    }
}

// ── JNI wrappers — ByteArray ────────────────────────────────────────

// jni_cam_frame / jni_mic_frame removed with the VirtualOffice split (see above).

// ── Helper for NativeMethod construction ─────────────────────────────

fn nm(name: &str, sig: &str, ptr: *mut c_void) -> NativeMethod {
    NativeMethod {
        name: name.into(),
        sig: sig.into(),
        fn_ptr: ptr,
    }
}

// ── The native registration contract ─────────────────────────────────

/// One native method this library binds into a Kotlin class.
pub struct NativeBinding {
    pub method: &'static str,
    pub signature: &'static str,
    ptr: *mut c_void,
}

/// One Kotlin class and the natives registered onto it.
pub struct ClassBindings {
    pub class: &'static str,
    pub methods: Vec<NativeBinding>,
}

/// The Rust → Kotlin callback target, resolved (not merely assumed) during load.
pub const AGENT2_CALLBACK_CLASS: &str = "com/remotedexter/Agent2Bindings";
pub const AGENT2_CALLBACK_METHOD: &str = "rd_on_agent2_command";
pub const AGENT2_CALLBACK_SIG: &str = "(Ljava/lang/String;)V";

/// The video frame callback: `rdOnFrame(jpeg, sequence, width, height, keyframe)`.
///
/// The descriptor spells out the metadata the wire format supplies, so the
/// viewer never has to be handed a constant.
pub const FRAME_CALLBACK_CLASS: &str = "com/remotedexter/FrameReceiver";
pub const FRAME_CALLBACK_METHOD: &str = "rdOnFrame";
pub const FRAME_CALLBACK_SIG: &str = "([BJIIZ)V";

/// One Rust → Kotlin static method this library calls.
pub struct CallbackBinding {
    pub class: &'static str,
    pub method: &'static str,
    pub signature: &'static str,
}

/// Every callback `JNI_OnLoad` resolves before declaring the library loaded.
///
/// The same source of truth as `native_registrations()`, for the other
/// direction: a missing or mistyped Kotlin method refuses the library at load
/// rather than being discovered at the first host command or the first frame.
pub fn callback_registrations() -> Vec<CallbackBinding> {
    vec![
        CallbackBinding {
            class: AGENT2_CALLBACK_CLASS,
            method: AGENT2_CALLBACK_METHOD,
            signature: AGENT2_CALLBACK_SIG,
        },
        CallbackBinding {
            class: FRAME_CALLBACK_CLASS,
            method: FRAME_CALLBACK_METHOD,
            signature: FRAME_CALLBACK_SIG,
        },
    ]
}

/// Every native this library registers — the single source of truth shared by
/// `JNI_OnLoad` and the Kotlin-contract tests, so the two cannot drift.
fn native_registrations() -> Vec<ClassBindings> {
    fn b(method: &'static str, signature: &'static str, ptr: *mut c_void) -> NativeBinding {
        NativeBinding {
            method,
            signature,
            ptr,
        }
    }
    vec![
        ClassBindings {
            class: "com/remotedexter/TransportBindings",
            methods: vec![
                b(
                    "rd_set_data_dir",
                    "(Ljava/lang/String;)V",
                    jni_set_data_dir as *mut c_void,
                ),
                b(
                    "rd_forget_identity",
                    "()Z",
                    jni_forget_identity as *mut c_void,
                ),
                b("rd_init_session", "()V", jni_init_session as *mut c_void),
                b("rd_shutdown_session", "()V", jni_shutdown as *mut c_void),
                b("rd_tick", "()V", jni_tick as *mut c_void),
            ],
        },
        ClassBindings {
            class: "com/remotedexter/PowerBindings",
            methods: vec![
                b("rd_on_system_sleep", "()V", jni_sleep as *mut c_void),
                b("rd_on_system_wake", "()V", jni_wake as *mut c_void),
                b("rd_on_transport_idle", "()V", jni_tidle as *mut c_void),
                b("rd_on_transport_wake", "()V", jni_twake as *mut c_void),
            ],
        },
        ClassBindings {
            class: "com/remotedexter/ScreenshotBindings",
            methods: vec![b(
                "rd_request_screenshot",
                "()V",
                jni_screenshot as *mut c_void,
            )],
        },
        // MediaBindings (camera/mic) removed with the VirtualOffice split.
        ClassBindings {
            class: "com/remotedexter/RDRust",
            methods: vec![
                b(
                    "startSession",
                    "(Ljava/lang/String;ILjava/lang/String;[B)V",
                    jni_start_session as *mut c_void,
                ),
                b(
                    "startRelaySession",
                    "(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;[B)V",
                    jni_start_relay_session as *mut c_void,
                ),
                b(
                    "startPairedSession",
                    "(Ljava/lang/String;I[B)V",
                    jni_start_paired_session as *mut c_void,
                ),
                b(
                    "startPairedRelaySession",
                    "(Ljava/lang/String;I[BLjava/lang/String;)V",
                    jni_start_paired_relay_session as *mut c_void,
                ),
                b(
                    "registerFrameReceiver",
                    "()V",
                    jni_register_frame_receiver as *mut c_void,
                ),
                b(
                    "unregisterFrameReceiver",
                    "()V",
                    jni_unregister_frame_receiver as *mut c_void,
                ),
                b(
                    "sendCommand",
                    "(Ljava/lang/String;)Z",
                    jni_send_command as *mut c_void,
                ),
                b("stopSession", "()V", jni_stop_session as *mut c_void),
                b(
                    "sessionStatus",
                    "()Ljava/lang/String;",
                    jni_session_status as *mut c_void,
                ),
            ],
        },
    ]
}

// ── JNI_OnLoad — register all native methods, or fail closed ─────────

/// Fails closed. Previously every `register_native_methods` result was
/// discarded with `let _ =` and `JNI_VERSION_1_6` was returned regardless, so a
/// missing Kotlin declaration or a mistyped descriptor produced a library that
/// loaded successfully and then had no working entry points. Any failure here
/// now returns `JNI_ERR`, which aborts `System.loadLibrary` loudly instead.
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _: *mut c_void) -> jint {
    match jni_on_load_inner(vm) {
        Ok(()) => JNI_VERSION_1_6,
        Err(e) => {
            // Reason only — never a token, key, or command payload.
            rd_log!("[rd_jni] JNI_OnLoad failed, refusing to load: {e}");
            jni::sys::JNI_ERR
        }
    }
}

unsafe fn jni_on_load_inner(vm: *mut jni::sys::JavaVM) -> Result<()> {
    let vm = jni::JavaVM::from_raw(vm).map_err(|e| anyhow::anyhow!("JavaVM::from_raw: {e}"))?;
    let mut classes: HashMap<&'static str, jni::objects::GlobalRef> = HashMap::new();

    // Scoped so `env`'s borrow of `vm` ends before `vm` is stored below.
    {
        let mut env = vm
            .get_env()
            .map_err(|e| anyhow::anyhow!("JavaVM::get_env: {e}"))?;

        for binding in native_registrations() {
            let methods: Vec<NativeMethod> = binding
                .methods
                .iter()
                .map(|m| nm(m.method, m.signature, m.ptr))
                .collect();
            env.register_native_methods(binding.class, &methods)
                .map_err(|e| {
                    // A pending NoSuchMethodError would poison the next call.
                    let _ = env.exception_clear();
                    anyhow::anyhow!("RegisterNatives {}: {e}", binding.class)
                })?;
        }

        // Resolve every Rust → Kotlin callback now rather than discovering at
        // the first host command — or the first video frame — that a descriptor
        // never matched anything. The class is also pinned as a global ref
        // here, because this is the only thread guaranteed to reach it (see
        // CALLBACK_CLASSES).
        for cb in callback_registrations() {
            env.get_static_method_id(cb.class, cb.method, cb.signature)
                .map_err(|e| {
                    let _ = env.exception_clear();
                    anyhow::anyhow!("callback {}.{}{}: {e}", cb.class, cb.method, cb.signature)
                })?;
            let class = env.find_class(cb.class).map_err(|e| {
                let _ = env.exception_clear();
                anyhow::anyhow!("find_class {}: {e}", cb.class)
            })?;
            let global = env.new_global_ref(&class).map_err(|e| {
                let _ = env.exception_clear();
                anyhow::anyhow!("new_global_ref {}: {e}", cb.class)
            })?;
            classes.insert(cb.class, global);
        }
    }

    // Only now, with every binding proven, publish the VM and wire the engine.
    *CALLBACK_CLASSES.lock().unwrap() = classes;
    *JAVA_VM.lock().unwrap() = Some(vm);
    ENGINE.lock().unwrap().set_agent2_callback(|json| {
        call_kotlin_on_agent2_command(json);
    });
    Ok(())
}

// ── Rust → Kotlin callback: forward Agent2 JSON ──────────────────────

#[cfg(test)]
mod tests {
    // ── small messages leave at once ─────────────────────────────────────

    #[tokio::test]
    async fn a_session_socket_sends_small_messages_without_nagle_delay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let reach = ClientReach::Direct {
            host: "127.0.0.1".to_string(),
            port,
        };
        let (opened, _accepted) = tokio::join!(reach.open(), listener.accept());
        assert!(
            opened.unwrap().nodelay().unwrap(),
            "Nagle holds each input event until the last one is acknowledged"
        );
    }

    /// Counts `poll_write` calls, accepting everything it is given.
    struct CountingWriter {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl tokio::io::AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_noise_message_leaves_in_one_write() {
        let mut w = CountingWriter {
            writes: 0,
            bytes: Vec::new(),
        };
        send_noise_msg(&mut w, b"pointer-move").await.unwrap();
        assert_eq!(w.writes, 1, "length and body must go out together");
        let mut expected = 12u32.to_be_bytes().to_vec();
        expected.extend_from_slice(b"pointer-move");
        assert_eq!(w.bytes, expected);
    }

    /// The invite path must keep refusing a token-less connection.
    ///
    /// `connect_paired` exists precisely so that a token-less connection is a
    /// deliberate call. If this guard were ever relaxed to share one entry
    /// point, an invite whose token failed to parse would stop being an error
    /// and quietly become a paired-reconnect attempt — which either succeeds
    /// with the wrong intent or fails with a misleading reason.
    ///
    /// Note it refuses before any socket is opened: the address below is never
    /// connected to, so a failure here cannot be a network error wearing the
    /// right message.
    /// A paired relay reconnect with no stored session is a local mistake, and
    /// is reported as one — before a socket opens. Sent to the relay it would
    /// come back as "no such session", which reads as a host that is not
    /// running and sends the operator to the wrong machine.
    #[test]
    fn a_paired_relay_reconnect_refuses_an_empty_session_without_touching_the_network() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = runtime.block_on(super::PinnedNoiseSession::connect_paired_via_relay(
            // Reserved for documentation (RFC 5737); nothing answers here.
            "192.0.2.1".to_string(),
            9,
            String::new(),
            vec![0u8; 32],
        ));
        match outcome {
            Ok(_) => panic!("an empty relay session must be refused"),
            Err(e) => assert!(
                e.to_string().contains("relay session must not be empty"),
                "refusal must name the missing session, got: {e}"
            ),
        }
    }

    /// **No two session-starting natives share a JNI descriptor.**
    ///
    /// The paired relay reconnect takes an address, a port, a session id and a
    /// pin. In that natural order its shape is identical to `startSession`,
    /// which takes an address, a port, a PAIRING TOKEN and a pin — so a Kotlin
    /// call site that handed a stored session id to the token parameter, or the
    /// reverse, would compile and run. Ordering the pin before the session makes
    /// the mistake a type error; this keeps it one if a native is added later.
    ///
    /// Only the natives that start a session are compared. Several others are
    /// `()V` and are meant to be: they take nothing that could be swapped.
    /// **The phone recognises a relay refusal by this client's words.**
    ///
    /// `NativeFailure.RELAY_REFUSED_MARK` in the app is matched against the
    /// status detail this crate writes. If either side changed its text, every
    /// relay refusal would silently go back to being reported as "screen stream
    /// stopped" — nothing would fail, and the operator would be sent to the
    /// wrong machine. So a REAL refusal is produced here, over loopback, and
    /// checked against the constant as the app source declares it.
    /// **A stored relay session id never reaches a string.**
    ///
    /// The id is a credential against the relay: whoever holds one can occupy
    /// the host's join slot. The app now KEEPS it, so the code that handles it
    /// is no longer one pairing function — it is the stored route, the record,
    /// the registry that logs what it remembers, and the orchestrator that
    /// labels a connection. Any string template in them that mentions a session
    /// is a log line, a label or a toast waiting to carry it.
    ///
    /// Passing it as an ARGUMENT — to the native, or to the storage encoder —
    /// is what it is for, and is not a template.
    #[test]
    fn no_stored_relay_session_is_interpolated_into_a_string() {
        let dir = kotlin_dir();
        let mut scanned = 0;
        for file in [
            "RelayRoute.kt",
            "PairedHostRecord.kt",
            "PairedHostRegistry.kt",
            "SessionOrchestrator.kt",
        ] {
            let source = std::fs::read_to_string(dir.join(file))
                .unwrap_or_else(|e| panic!("cannot read {file}: {e}"));
            for (n, line) in source.lines().enumerate() {
                let code = line.trim_start();
                // Comments explain the rule; they are not the risk.
                if code.starts_with("//") || code.starts_with('*') || code.starts_with("/*") {
                    continue;
                }
                let templated = code.contains("$session")
                    || code.split("${").skip(1).any(|expr| {
                        expr.split('}')
                            .next()
                            .is_some_and(|e| e.contains("session"))
                    });
                assert!(
                    !templated,
                    "{file}:{} interpolates a relay session id into a string: {code}",
                    n + 1
                );
            }
            scanned += 1;
        }
        assert_eq!(scanned, 4);
    }

    #[test]
    fn a_relay_refusal_carries_the_words_the_app_looks_for() {
        let source = std::fs::read_to_string(kotlin_dir().join("SessionState.kt"))
            .expect("the app's SessionState.kt");
        let decl = source
            .lines()
            .find(|l| l.contains("const val RELAY_REFUSED_MARK"))
            .expect("the app no longer declares RELAY_REFUSED_MARK");
        let mark = decl
            .split('"')
            .nth(1)
            .expect("RELAY_REFUSED_MARK is not a string literal");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let why = runtime.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let relay = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut len = [0u8; 4];
                s.read_exact(&mut len).await.unwrap();
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                s.read_exact(&mut body).await.unwrap();
                let reply = relay_proto::encode(&relay_proto::ControlFrame::Denied {
                    why: "no such session".to_string(),
                });
                s.write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
                s.write_all(&reply).await.unwrap();
            });
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let outcome = super::relay_join(&mut stream, "AAAAAAAAAAAAAAAAAAAAAA").await;
            relay.await.unwrap();
            outcome
                .expect_err("a Denied frame was accepted")
                .to_string()
        });
        assert!(
            why.contains(mark),
            "the client reports a relay refusal as `{why}`, which does not contain the app's \
             RELAY_REFUSED_MARK `{mark}` — the app would call it a stream failure"
        );
    }

    #[test]
    fn every_session_starting_native_has_its_own_descriptor() {
        let starts: Vec<(&str, &str)> = native_registrations()
            .into_iter()
            .flat_map(|class| class.methods)
            .filter(|m| m.method.starts_with("start"))
            .map(|m| (m.method, m.signature))
            .collect();
        assert!(
            starts.iter().any(|(n, _)| *n == "startPairedRelaySession"),
            "the paired relay native is not registered at all"
        );
        assert!(
            starts.len() >= 4,
            "expected at least four session natives: {starts:?}"
        );
        for (i, (name, sig)) in starts.iter().enumerate() {
            for (other, other_sig) in &starts[i + 1..] {
                assert_ne!(
                    sig, other_sig,
                    "{name} and {other} have the same descriptor {sig}: a caller can pass one's \
                     credential to the other and the compiler will not notice"
                );
            }
        }
    }

    /// A stored port the Kotlin side got wrong is refused, not truncated. `as
    /// u16` would dial 70000 as 4464 and treat 0 as "any port".
    #[test]
    fn a_stored_relay_port_that_is_not_a_port_is_refused() {
        for bad in [0, -1, 65_536, 70_000, i32::MIN, i32::MAX] {
            assert_eq!(
                super::relay_port_from(bad),
                None,
                "{bad} was accepted as a relay port"
            );
        }
        assert_eq!(super::relay_port_from(9443), Some(9443));
        assert_eq!(super::relay_port_from(1), Some(1));
        assert_eq!(super::relay_port_from(65_535), Some(65_535));
    }

    #[test]
    fn connect_refuses_an_empty_token_without_touching_the_network() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Matched rather than `expect_err`: that would require `Debug` on
        // `PinnedNoiseSession`, and a session holding live Noise transport
        // state is not a type to make printable for a test's convenience.
        let outcome = runtime.block_on(super::PinnedNoiseSession::connect(
            // Reserved for documentation (RFC 5737); nothing answers here.
            "192.0.2.1".to_string(),
            9,
            String::new(),
            vec![0u8; 32],
        ));
        match outcome {
            Ok(_) => panic!("an empty token must be refused"),
            Err(e) => assert!(
                e.to_string().contains("session token must not be empty"),
                "refusal must name the empty token, got: {e}"
            ),
        }
    }

    /// An empty path must not become "wherever the process was started".
    #[test]
    fn an_empty_data_dir_is_refused() {
        assert!(!super::set_data_dir(""));
    }
    use super::*;
    use module14_apk_session::engine::MAX_FRAMES;
    use stream_chunk::{chunk_frame, FrameReassembler};

    // ── Phase 1: the JNI registration contract ───────────────────────────
    //
    // `RegisterNatives` fails at runtime if the Kotlin class does not declare a
    // matching method, and the JVM is not available on this box. These tests
    // therefore check the contract against the Kotlin sources that actually
    // ship, so a missing or mistyped declaration is caught here rather than on
    // a device. They are not a substitute for running it on Android, and the
    // difference is recorded as UNVERIFIED rather than assumed.

    fn kotlin_dir() -> std::path::PathBuf {
        // CARGO_MANIFEST_DIR is `<repo>/rust`; the Android project is its sibling.
        //
        // This points at `apk/`, the **buildable** Gradle project — the tree
        // `./gradlew assembleDebug` actually compiles and packages into the APK.
        // It previously pointed at the bare `app/` source tree, which has no
        // Gradle project and is never built, so the contract was being checked
        // against code that could not reach a device.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("repo root")
            .join("apk/app/src/main/java/com/remotedexter")
    }

    /// **The service shutdown may only be called by the service.**
    ///
    /// **The relay route must not be a weaker path than the direct one.**
    ///
    /// `SessionStarter` has two entry points now: `startFromInvite` for a host
    /// that is listening, and `startFromRelayInvite` for one reached through a
    /// relay. They are the security boundary for pairing, and neither can be
    /// unit-tested here — they need an Android `Context` and start a service.
    ///
    /// What CAN be checked is that the relay path still calls every gate the
    /// direct path calls. If someone adds a check to one and not the other,
    /// "scan the relay code instead" quietly becomes a way around it, and
    /// nothing else in this tree would notice.
    ///
    /// Scanned from the source, in the same style as the JNI contract test and
    /// the service-shutdown test: the rule is about WHAT a function calls, and
    /// no type expresses that.
    #[test]
    fn the_relay_pairing_path_applies_every_gate_the_direct_path_does() {
        let source =
            std::fs::read_to_string(kotlin_dir().join("bootstrap18").join("SessionStarter.kt"))
                .expect("SessionStarter.kt");

        let direct = source
            .split_once("fun startFromInvite(payload: InvitePayload")
            .expect("the direct entry point")
            .1;
        let direct = direct
            .split_once("fun startFromRelayInvite")
            .map(|(before, _)| before)
            .unwrap_or(direct);
        let relay = source
            .split_once("fun startFromRelayInvite(invite: InviteV5")
            .expect("the relay entry point")
            .1;
        let relay = relay
            .split_once("\n    fun startFromInvite(hostIp:")
            .map(|(before, _)| before)
            .unwrap_or(relay);

        // Each gate, named by something only that gate calls.
        for gate in [
            "InviteTrustPolicy.evaluate",
            "InviteSignatureVerifier.isValid",
            "NOISE_PUBKEY_BYTES",
            "FailureReason.InviteExpired",
            "FailureReason.InviteSignature",
            "FailureReason.Authorization",
            "IdentityMismatch",
            "arming?.disarm()",
            "\"rdv3\"",
        ] {
            assert!(
                direct.contains(gate),
                "the direct path no longer calls {gate} — this test's premise is stale"
            );
            assert!(
                relay.contains(gate),
                "the RELAY pairing path does not apply `{gate}`, which the direct path does. \
                 A route with fewer gates makes scanning the other code a way around them."
            );
        }

        // And the relay path must never log the session id, which is what this
        // device presents to the relay to be spliced to a host.
        assert!(
            !relay.contains("invite.session}") && !relay.contains("${invite.session"),
            "the relay pairing path interpolates the session id into a log line"
        );
    }

    /// `rd_shutdown_session` sets `service_running = false` in the session
    /// engine, and the engine only returns to `Active` from `Closed` or `Idle`
    /// **while the service is running**. So calling it to end a SESSION poisons
    /// the process: every later connection reports "connected" and every frame
    /// is dropped silently by `InboundFrame`'s `if state == Active` guard, with
    /// nothing logged on either side. The picture stays black while the app
    /// says it is streaming.
    ///
    /// That is not hypothetical. `SessionOrchestrator.disconnect()` called it,
    /// and the operator hit it on 2026-08-28: "this was only after I clicked
    /// forget this host that it went black." One disconnect was enough.
    ///
    /// The engine's own reconnect path was correct and tested
    /// (`disconnect_then_reconnect_accepts_frames_again`); nothing on the Rust
    /// side could catch a Kotlin caller reaching for the wrong teardown. This
    /// scans the source, in the same style as the JNI contract test above,
    /// because the rule is about WHO calls it and no type can express that.
    #[test]
    fn the_service_shutdown_is_only_called_by_the_service() {
        let dir = kotlin_dir();
        let mut offenders = Vec::new();
        let mut found_any = false;
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|x| x.to_str()) != Some("kt") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();
                for line in text.lines() {
                    // Declarations and comments are not calls.
                    let code = line.split("//").next().unwrap_or("");
                    if !code.contains("rd_shutdown_session(") {
                        continue;
                    }
                    if code.contains("external fun") {
                        continue;
                    }
                    found_any = true;
                    // RDService owns the service lifecycle. UpdateManager is
                    // about to replace the process, which is a service end by
                    // any reading.
                    if name != "RDService.kt" && name != "UpdateManager.kt" {
                        offenders.push(format!("{name}: {}", code.trim()));
                    }
                }
            }
        }
        assert!(
            found_any,
            "no call to rd_shutdown_session was found at all — this test has \
             stopped checking anything, which is worse than a failure"
        );
        assert!(
            offenders.is_empty(),
            "rd_shutdown_session is the SERVICE's teardown and sets \
             service_running = false, after which no reconnect can reach Active \
             and every frame is dropped silently. Called from: {offenders:?}"
        );
    }

    /// Kotlin type as written in a declaration -> JNI descriptor fragment.
    fn kotlin_type_to_descriptor(ty: &str) -> String {
        match ty.trim() {
            "Int" => "I".to_string(),
            "Long" => "J".to_string(),
            "Boolean" => "Z".to_string(),
            "Float" => "F".to_string(),
            "Double" => "D".to_string(),
            "String" => "Ljava/lang/String;".to_string(),
            "ByteArray" => "[B".to_string(),
            "" | "Unit" => "V".to_string(),
            other => panic!("unmapped Kotlin type in a native declaration: {other:?}"),
        }
    }

    /// One Kotlin function declaration, parsed from the shipping source.
    struct KotlinFun {
        descriptor: String,
        /// (parameter name, Kotlin type as written)
        params: Vec<(String, String)>,
        jvm_static: bool,
    }

    /// Does the declaration starting after `before` carry `@JvmStatic`?
    ///
    /// Walks back over blank lines, comments and other annotations; any other
    /// code line ends the annotation block.
    fn has_jvm_static(before: &str) -> bool {
        for line in before.lines().rev() {
            let l = line.trim();
            if l.is_empty() || l.starts_with("//") || l.starts_with('*') || l.starts_with("/*") {
                continue;
            }
            if l.starts_with('@') {
                if l.starts_with("@JvmStatic") {
                    return true;
                }
                continue;
            }
            return false;
        }
        false
    }

    /// Parse the parameter list and return type of the declaration whose name
    /// ends at `source[..name_end]`, starting the scan at `name_end`.
    fn parse_signature(source: &str, name_end: usize) -> (String, Vec<(String, String)>, usize) {
        let rest = &source[name_end..];
        let open = rest.find('(').expect("declaration has a parameter list");

        // Walk to the matching close paren so nested parens cannot end it early.
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in rest[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("declaration never closes its parameter list");

        let mut params = Vec::new();
        for p in rest[open + 1..close].split(',') {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            let (pname, ty) = p
                .split_once(':')
                .unwrap_or_else(|| panic!("parameter {p:?} has no type annotation"));
            params.push((pname.trim().to_string(), ty.trim().to_string()));
        }

        // An explicit return type follows as `: Type` before the line ends.
        let tail_line = rest[close + 1..].lines().next().unwrap_or("").trim();
        let ret = tail_line.strip_prefix(':').unwrap_or("").trim();

        let mut descriptor = String::from("(");
        for (_, ty) in &params {
            descriptor.push_str(&kotlin_type_to_descriptor(ty));
        }
        descriptor.push(')');
        descriptor.push_str(&kotlin_type_to_descriptor(ret));

        (descriptor, params, name_end + close)
    }

    /// Find `fun <name>(…)` in a Kotlin source and parse its contract.
    /// Ignores `external fun`, which is the Kotlin → Rust direction.
    fn declared_fun(source: &str, name: &str) -> Option<KotlinFun> {
        let needle = format!("fun {name}(");
        let mut cursor = 0usize;
        while let Some(found) = source[cursor..].find(&needle) {
            let at = cursor + found;
            let before = &source[..at];
            if before.ends_with("external ") {
                cursor = at + needle.len();
                continue;
            }
            let (descriptor, params, _) = parse_signature(source, at + needle.len() - 1);
            return Some(KotlinFun {
                descriptor,
                params,
                jvm_static: has_jvm_static(before),
            });
        }
        None
    }

    /// Every `external fun` in a Kotlin file, as (name, JNI descriptor).
    ///
    /// Scans the whole source rather than line by line, because a declaration
    /// with several parameters is wrapped across lines.
    fn declared_externals(source: &str) -> Vec<(String, String)> {
        const MARKER: &str = "external fun ";
        let mut out = Vec::new();
        let mut cursor = 0usize;

        while let Some(found) = source[cursor..].find(MARKER) {
            let start = cursor + found + MARKER.len();
            let rest = &source[start..];
            let open = rest.find('(').expect("declaration has a parameter list");
            let name = rest[..open].trim().to_string();

            // Walk to the matching close paren so nested parens cannot end it early.
            let mut depth = 0usize;
            let mut close = None;
            for (i, ch) in rest[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let close = close.unwrap_or_else(|| panic!("{name} never closes its parameter list"));
            let params = &rest[open + 1..close];

            // An explicit return type follows as `: Type` before the line ends.
            let tail = &rest[close + 1..];
            let tail_line = tail.lines().next().unwrap_or("").trim();
            let ret = tail_line.strip_prefix(':').unwrap_or("").trim();

            let mut descriptor = String::from("(");
            for p in params.split(',') {
                let p = p.trim();
                if p.is_empty() {
                    continue;
                }
                let ty = p
                    .split(':')
                    .nth(1)
                    .unwrap_or_else(|| panic!("parameter {p:?} in {name} has no type annotation"));
                descriptor.push_str(&kotlin_type_to_descriptor(ty));
            }
            descriptor.push(')');
            descriptor.push_str(&kotlin_type_to_descriptor(ret));
            out.push((name, descriptor));

            cursor = start + close;
        }
        out
    }

    /// The defect this phase exists for: `JNI_OnLoad` registered `startSession`
    /// and `registerFrameReceiver` against `RDRust`, which declared no
    /// `external fun` at all. Registration would fail on a device while
    /// `JNI_OnLoad` still returned `JNI_VERSION_1_6`, so the library looked
    /// loaded and none of those entry points worked.
    #[test]
    fn every_registered_native_is_declared_in_kotlin() {
        let dir = kotlin_dir();
        let mut checked = 0usize;
        for binding in native_registrations() {
            let simple = binding
                .class
                .rsplit('/')
                .next()
                .expect("class name")
                .to_string();
            let path = dir.join(format!("{simple}.kt"));
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let declared = declared_externals(&source);

            for m in binding.methods {
                let found = declared.iter().find(|(n, _)| n == m.method);
                let (_, actual) = found.unwrap_or_else(|| {
                    panic!(
                        "{simple}.kt declares no `external fun {}` — RegisterNatives \
                         would fail for {}.{}",
                        m.method, binding.class, m.method
                    )
                });
                assert_eq!(
                    actual, m.signature,
                    "{simple}.{} descriptor mismatch: Kotlin declares {actual}, \
                     JNI registers {}",
                    m.method, m.signature
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "no native registrations were checked");
    }

    /// The Rust -> Kotlin direction. `call_static_method` resolves this by name
    /// and descriptor, so the Kotlin side must expose it as a `@JvmStatic`.
    #[test]
    fn agent2_callback_target_exists_as_a_jvm_static() {
        let source = std::fs::read_to_string(kotlin_dir().join("Agent2Bindings.kt"))
            .expect("Agent2Bindings.kt");
        assert!(
            source.contains("@JvmStatic"),
            "the callback target must be @JvmStatic for CallStaticVoidMethod to resolve it"
        );
        assert!(
            source.contains(&format!("fun {AGENT2_CALLBACK_METHOD}(json: String)")),
            "Agent2Bindings must declare {AGENT2_CALLBACK_METHOD}(json: String) to match {AGENT2_CALLBACK_SIG}"
        );
    }

    /// `Agent2Bindings.rd_on_agent2_command` dereferences `RDService.instance`,
    /// so that property has to exist or the Kotlin source does not compile.
    #[test]
    fn rdservice_exposes_the_instance_agent2_bindings_uses() {
        let bindings = std::fs::read_to_string(kotlin_dir().join("Agent2Bindings.kt"))
            .expect("Agent2Bindings.kt");
        if !bindings.contains("RDService.instance") {
            return; // contract not depended upon; nothing to uphold
        }
        let service =
            std::fs::read_to_string(kotlin_dir().join("RDService.kt")).expect("RDService.kt");
        assert!(
            service.contains("var instance"),
            "Agent2Bindings uses RDService.instance but RDService declares no such property"
        );
        assert!(
            service.contains("instance = this"),
            "RDService must publish itself in onCreate or the callback always no-ops"
        );
        assert!(
            service.contains("if (instance === this)"),
            "onDestroy must only clear `instance` when it still refers to this service, \
             or a restarted service is unregistered by its predecessor"
        );
    }

    /// A host command response is JSON and must reach the engine path intact.
    /// Wrap a payload the way the wire now carries it.
    ///
    /// The tests below used to hand `classify_inbound` bare bytes, which was
    /// the format before Block 10. Feeding it the real framing is the point:
    /// a test that still spoke the old wire would keep passing while the
    /// product could not talk to anything.
    fn framed(kind: wire::Kind, payload: &[u8]) -> Vec<u8> {
        wire::Envelope::new(kind, 0, payload.to_vec())
            .expect("test payload must be a valid envelope")
            .encode()
    }

    #[test]
    fn json_response_is_routed_as_a_command() {
        let mut r = FrameReassembler::new();
        let msg = classify_inbound(
            &mut r,
            &framed(wire::Kind::ControlJson, br#"{"type":"pong"}"#),
        );
        assert_eq!(
            msg,
            InboundMessage::Command(r#"{"type":"pong"}"#.to_string())
        );
    }

    /// The regression this routing exists for: chunks produced by the *real*
    /// producer (the same `chunk_frame` the host streams with) must reassemble
    /// into the original frame. The previous loop ran every message through
    /// `str::from_utf8` and dropped what failed, so chunks were silently
    /// discarded and no frame ever reached the client.
    #[test]
    fn real_producer_chunks_reassemble_into_the_original_frame() {
        // JPEG-shaped bytes: magic + a payload that is not valid UTF-8, which is
        // exactly what the old path could not carry.
        let mut payload = vec![0xFFu8, 0xD8, 0xFF];
        payload.extend((0..9000u32).map(|i| (i % 251) as u8));

        let chunks = chunk_frame(42, 1920, 1080, true, &payload, 4000);
        assert!(chunks.len() > 1, "test needs a multi-chunk frame");

        let mut r = FrameReassembler::new();
        let mut completed = None;
        for (i, c) in chunks.iter().enumerate() {
            let msg = classify_inbound(&mut r, &framed(wire::Kind::FrameChunkV1, c));
            assert_ne!(
                msg,
                InboundMessage::Unrecognized,
                "chunk {i} was not recognised as a stream chunk"
            );
            if let InboundMessage::Frame(f) = msg {
                completed = Some(f);
            }
        }

        let f = completed.expect("the last chunk must complete the frame");
        assert_eq!(
            f.data, payload,
            "reassembled bytes differ from the original"
        );
        assert_eq!((f.width, f.height), (1920, 1080));
        assert_eq!(f.seq, 42);
        assert!(f.keyframe);
    }

    /// A chunk tagged `0x01` but shorter than the 14-byte header is malformed.
    /// It must not be reported as a pending chunk (which would look like normal
    /// progress) nor guessed at as text.
    #[test]
    fn truncated_stream_chunk_is_rejected() {
        let mut r = FrameReassembler::new();
        let msg = classify_inbound(
            &mut r,
            &framed(
                wire::Kind::FrameChunkV1,
                &[stream_chunk::STREAM_TAG, 0x00, 0x00],
            ),
        );
        assert_eq!(msg, InboundMessage::Unrecognized);
    }

    /// Not a chunk and not text — dropped rather than guessed at.
    #[test]
    fn non_utf8_non_chunk_is_dropped() {
        let mut r = FrameReassembler::new();
        let msg = classify_inbound(&mut r, &framed(wire::Kind::ControlJson, br#"{"a":"b"}"#));
        assert_ne!(
            msg,
            InboundMessage::Unrecognized,
            "well-formed control JSON must route"
        );
        // Bytes that are not an envelope at all.
        assert_eq!(
            classify_inbound(&mut r, &[0xC3, 0x28, 0xA0]),
            InboundMessage::Unrecognized
        );
    }

    // ── Phase 2: the bounded command channel ─────────────────────────────
    //
    // `COMMAND_SINK` is process-global, so these serialize against each other.
    static SINK_LOCK: Mutex<()> = Mutex::new(());

    /// Leaves the registry empty regardless of how a previous test ended.
    fn clear_sink() {
        *COMMAND_SINK.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// The buffering that makes `recv()` cancel-safe. A frame that arrives in
    /// pieces must survive across reads: with the previous `read_exact`
    /// approach, a `select!` that cancelled `recv()` mid-frame discarded the
    /// bytes already consumed, desynchronizing framing and then Noise nonces.
    ///
    /// This exercises the buffer logic deterministically. It does not by itself
    /// prove the async cancellation path — the live loopback command test does
    /// that, by repeatedly dropping a pending `recv()` when the command branch
    /// of the session `select!` wins.
    #[test]
    fn partial_frames_survive_in_the_receive_buffer() {
        let mut buf: Vec<u8> = Vec::new();

        // Length prefix alone: not yet a frame, and nothing is consumed.
        buf.extend_from_slice(&5u32.to_be_bytes());
        assert!(PinnedNoiseSession::take_framed(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 4, "an incomplete frame must stay buffered");

        // Body arrives in two further pieces.
        buf.extend_from_slice(b"ab");
        assert!(PinnedNoiseSession::take_framed(&mut buf).unwrap().is_none());
        buf.extend_from_slice(b"cde");
        let frame = PinnedNoiseSession::take_framed(&mut buf)
            .unwrap()
            .expect("the frame completes once all bytes arrive");
        assert_eq!(frame, b"abcde");
        assert!(buf.is_empty(), "a consumed frame must be drained");

        // Two frames in one read are returned in order, not merged.
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(b"x");
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(b"yz");
        assert_eq!(
            PinnedNoiseSession::take_framed(&mut buf).unwrap().unwrap(),
            b"x"
        );
        assert_eq!(
            PinnedNoiseSession::take_framed(&mut buf).unwrap().unwrap(),
            b"yz"
        );
        assert!(PinnedNoiseSession::take_framed(&mut buf).unwrap().is_none());

        // Bounds are enforced on the declared length, before any allocation.
        let mut bad = (MAX_NOISE_FRAME as u32 + 1).to_be_bytes().to_vec();
        bad.push(0);
        assert!(PinnedNoiseSession::take_framed(&mut bad).is_err());
        let mut zero = 0u32.to_be_bytes().to_vec();
        zero.push(0);
        assert!(PinnedNoiseSession::take_framed(&mut zero).is_err());
    }

    #[test]
    fn command_is_refused_when_no_session_owns_the_channel() {
        let _g = SINK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_sink();
        assert_eq!(
            submit_session_command(r#"{"type":"ping"}"#),
            Err(CommandRejection::NoSession)
        );
        assert_eq!(request_session_shutdown(), Err(CommandRejection::NoSession));
    }

    /// Malformed and oversized commands must be rejected *before* they occupy a
    /// channel slot or consume a Noise nonce.
    #[test]
    fn malformed_and_oversized_commands_are_rejected_before_enqueue() {
        let _g = SINK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_sink();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        let generation = claim_session(tx).expect("claim");

        assert_eq!(submit_session_command(""), Err(CommandRejection::Empty));
        assert_eq!(submit_session_command("   "), Err(CommandRejection::Empty));
        // Valid JSON, but not an object.
        assert_eq!(
            submit_session_command("[1,2,3]"),
            Err(CommandRejection::NotJsonObject)
        );
        assert_eq!(
            submit_session_command("\"just a string\""),
            Err(CommandRejection::NotJsonObject)
        );
        assert_eq!(
            submit_session_command("{not json"),
            Err(CommandRejection::NotJsonObject)
        );
        // Oversized: rejected on length before the JSON parse cost.
        let huge = format!(
            r#"{{"type":"x","pad":"{}"}}"#,
            "a".repeat(MAX_COMMAND_PLAINTEXT)
        );
        assert_eq!(
            submit_session_command(&huge),
            Err(CommandRejection::TooLarge)
        );

        // Nothing reached the channel.
        assert!(
            rx.try_recv().is_err(),
            "a rejected command must never be enqueued"
        );
        release_session(generation);
    }

    /// A full channel fails fast. It must not block the caller (which may be
    /// Android's main thread) and must not grow to absorb the excess.
    #[test]
    fn saturated_channel_rejects_rather_than_blocking_or_growing() {
        let _g = SINK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_sink();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        let generation = claim_session(tx).expect("claim");

        for i in 0..COMMAND_CHANNEL_CAPACITY {
            assert_eq!(
                submit_session_command(r#"{"type":"ping"}"#),
                Ok(()),
                "command {i} should fit within the channel capacity"
            );
        }
        // Capacity reached: the next one is refused, promptly.
        let started = std::time::Instant::now();
        assert_eq!(
            submit_session_command(r#"{"type":"ping"}"#),
            Err(CommandRejection::ChannelFull)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(250),
            "a full channel must fail fast, not block the caller"
        );

        // Exactly capacity queued — no silent growth.
        let mut drained = 0usize;
        while rx.try_recv().is_ok() {
            drained += 1;
        }
        assert_eq!(drained, COMMAND_CHANNEL_CAPACITY);
        release_session(generation);
    }

    #[test]
    fn a_second_concurrent_session_is_refused() {
        let _g = SINK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_sink();
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        let first = claim_session(tx1).expect("first session claims the channel");

        let (tx2, _rx2) = tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        assert!(
            claim_session(tx2).is_none(),
            "a second concurrent session must be refused, not silently swapped in"
        );

        release_session(first);
        // Once the first releases, a new session may take over.
        let (tx3, _rx3) = tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        let third = claim_session(tx3).expect("channel is free again");
        release_session(third);
    }

    /// A slow teardown must not unregister whoever came after it. Android can
    /// restart a session while the previous one is still unwinding.
    #[test]
    fn stale_session_cleanup_cannot_unregister_a_newer_session() {
        let _g = SINK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        clear_sink();
        let (tx_old, _rx_old) =
            tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        let old = claim_session(tx_old).expect("old session");
        release_session(old);

        let (tx_new, mut rx_new) =
            tokio::sync::mpsc::channel::<SessionCommand>(COMMAND_CHANNEL_CAPACITY);
        let new = claim_session(tx_new).expect("new session");

        // The old generation unwinds late and tries to clean up again.
        release_session(old);

        assert_eq!(
            submit_session_command(r#"{"type":"ping"}"#),
            Ok(()),
            "the newer session's sender must survive the older one's cleanup"
        );
        assert!(
            rx_new.try_recv().is_ok(),
            "the command went to the new session"
        );
        release_session(new);
        assert_eq!(
            submit_session_command(r#"{"type":"ping"}"#),
            Err(CommandRejection::NoSession),
            "releasing the current generation must clear the sender"
        );
    }

    // ── Phase 3: the frame delivery path ─────────────────────────────────
    //
    // `ENGINE` is process-global, so every test that touches the frame path
    // serializes on this. Each holds it for its whole body.
    static ENGINE_LOCK: Mutex<()> = Mutex::new(());

    fn engine_guard() -> std::sync::MutexGuard<'static, ()> {
        ENGINE_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A freshly initialised session — the state `RDService.onCreate` produces —
    /// with no viewer attached.
    fn reset_engine() {
        let mut e = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        e.set_frame_receiver_registered(false);
        e.shutdown();
        e.init();
    }

    fn attach_receiver(registered: bool) {
        ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_frame_receiver_registered(registered);
    }

    fn engine_event(evt: APKSessionEvent) {
        ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .handle_event(evt);
    }

    fn queued() -> usize {
        ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .queued_frame_count()
    }

    fn sample_frame(seq: u32) -> stream_chunk::ReassembledFrame {
        stream_chunk::ReassembledFrame {
            seq,
            width: 1920,
            height: 1080,
            keyframe: seq == 1,
            data: vec![0xFF, 0xD8, 0xFF, seq as u8],
        }
    }

    /// The reassembler already knows the real sequence, size and keyframe flag.
    /// `FrameEnvelope` carried only `{timestamp, data}`, so all of it was thrown
    /// away one line before the queue. Nothing here may be a constant.
    #[test]
    fn reassembled_frame_metadata_survives_into_the_frame_envelope() {
        let _g = engine_guard();
        reset_engine();
        let src = stream_chunk::ReassembledFrame {
            seq: 4242,
            width: 1280,
            height: 720,
            keyframe: true,
            data: vec![0xFF, 0xD8, 0x01, 0x02],
        };
        deliver_video_frame(src.clone());

        let taken = ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .consume_latest_frame();
        let f = taken.expect("the frame reached the engine queue");
        assert_eq!(f.sequence, src.seq);
        assert_eq!(f.width, src.width);
        assert_eq!(f.height, src.height);
        assert_eq!(f.keyframe, src.keyframe);
        assert_eq!(f.data, src.data);
    }

    /// The engine paces against `frame_interval_hint` (16_000 for 16 ms), so the
    /// receipt stamp has to be **microseconds**. Milliseconds would put the
    /// pacing threshold at 8 seconds and the viewer would update once per 8 s.
    #[test]
    fn delivered_frames_are_stamped_in_microseconds() {
        let _g = engine_guard();
        reset_engine();
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_micros() as u64
        };
        let before = now();
        deliver_video_frame(sample_frame(1));
        let after = now();

        let taken = ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .consume_latest_frame();
        let ts = taken.expect("queued").timestamp;
        assert!(
            ts >= before && ts <= after,
            "timestamp {ts} is not a microsecond clock reading within [{before}, {after}]"
        );
    }

    /// No viewer attached: nothing is pushed at Kotlin.
    #[test]
    fn no_frame_is_delivered_without_a_registered_receiver() {
        let _g = engine_guard();
        reset_engine();
        deliver_video_frame(sample_frame(1));

        let mut delivered = 0usize;
        let dispatched = tick_and_dispatch_frame(|_| delivered += 1);
        assert!(!dispatched, "nothing may be dispatched with no receiver");
        assert_eq!(delivered, 0);
        assert_eq!(queued(), 1, "the frame stays in the engine's bounded queue");
    }

    /// And it stays bounded: frames must not accumulate waiting for a UI that
    /// may never attach.
    #[test]
    fn frames_stay_bounded_while_no_receiver_is_attached() {
        let _g = engine_guard();
        reset_engine();
        for i in 0..(MAX_FRAMES as u32 * 8) {
            deliver_video_frame(sample_frame(i));
        }
        let mut delivered = 0usize;
        for _ in 0..10 {
            tick_and_dispatch_frame(|_| delivered += 1);
        }
        assert_eq!(delivered, 0, "no receiver, no delivery");
        let q = queued();
        assert_eq!(
            q, MAX_FRAMES,
            "the queue must hold at its bound ({MAX_FRAMES}), not grow to {q}"
        );
    }

    #[test]
    fn a_registered_receiver_takes_the_queued_frame() {
        let _g = engine_guard();
        reset_engine();
        attach_receiver(true);
        deliver_video_frame(sample_frame(9));

        let mut seen: Vec<(u32, u16, u16, bool, Vec<u8>)> = Vec::new();
        let dispatched = tick_and_dispatch_frame(|f| {
            seen.push((f.sequence, f.width, f.height, f.keyframe, f.data.clone()))
        });
        assert!(dispatched);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, 9);
        assert_eq!((seen[0].1, seen[0].2), (1920, 1080));
        assert_eq!(seen[0].4, vec![0xFF, 0xD8, 0xFF, 9]);
        assert_eq!(queued(), 0, "the delivered frame left the queue");

        let again = tick_and_dispatch_frame(|_| panic!("nothing is queued"));
        assert!(!again, "an empty queue dispatches nothing");
    }

    /// The lock discipline, proven rather than asserted in a comment: the frame
    /// is taken while `ENGINE` is held and the callback runs after it is
    /// released. A JNI call made under `ENGINE` deadlocks the whole client the
    /// moment Kotlin re-enters any native method.
    #[test]
    fn the_callback_runs_with_the_engine_unlocked() {
        let _g = engine_guard();
        reset_engine();
        attach_receiver(true);
        deliver_video_frame(sample_frame(3));

        let mut unlocked = false;
        // std's Mutex is not reentrant, so `try_lock` here can only succeed if
        // the delivery path already released it.
        let dispatched = tick_and_dispatch_frame(|_| unlocked = ENGINE.try_lock().is_ok());
        assert!(dispatched);
        assert!(
            unlocked,
            "the Rust -> Kotlin callback must be invoked with ENGINE unlocked"
        );
    }

    #[test]
    fn service_shutdown_stops_delivery() {
        let _g = engine_guard();
        reset_engine();
        attach_receiver(true);
        deliver_video_frame(sample_frame(1));

        ENGINE.lock().unwrap_or_else(|p| p.into_inner()).shutdown();

        let mut delivered = 0usize;
        let dispatched = tick_and_dispatch_frame(|_| delivered += 1);
        assert!(!dispatched);
        assert_eq!(delivered, 0);

        deliver_video_frame(sample_frame(2));
        assert_eq!(queued(), 0, "a shut-down service must not queue frames");
    }

    /// `run_pinned_session` raises `TransportDisconnected` on every exit, which
    /// closes the session and clears the queue. A reconnect has to reopen the
    /// frame path or every later frame is silently dropped forever.
    #[test]
    fn a_reconnect_restores_frame_delivery() {
        let _g = engine_guard();
        reset_engine();
        attach_receiver(true);

        engine_event(APKSessionEvent::TransportDisconnected);
        deliver_video_frame(sample_frame(1));
        assert_eq!(queued(), 0, "a closed session drops frames");

        engine_event(APKSessionEvent::TransportConnected);
        deliver_video_frame(sample_frame(2));
        let mut seen = None;
        let dispatched = tick_and_dispatch_frame(|f| seen = Some(f.sequence));
        assert!(dispatched, "a reconnected session must deliver again");
        assert_eq!(seen, Some(2));
    }

    /// No JVM exists on this box, so both callback paths must be quiet no-ops
    /// rather than panics. A panic here would unwind the session thread — or
    /// the tick — and poison `ENGINE` for every later call.
    #[test]
    fn the_callbacks_are_safe_no_ops_without_a_jvm() {
        assert!(
            JAVA_VM.lock().unwrap_or_else(|p| p.into_inner()).is_none(),
            "this test only means anything with no JVM attached"
        );
        assert!(callback_class(FRAME_CALLBACK_CLASS).is_none());
        call_kotlin_on_frame(&FrameEnvelope {
            timestamp: 1,
            sequence: 1,
            width: 8,
            height: 8,
            keyframe: true,
            data: vec![0xFF, 0xD8],
        });
        call_kotlin_on_agent2_command(r#"{"type":"ping"}"#);
    }

    /// The same lock rule on the other callback. `Agent2Bindings` routes into
    /// `Agent2Router.handle`, which re-enters native methods that lock `ENGINE`
    /// (`rd_on_clipboard_update`, `rd_on_system_wake`, `rd_on_system_sleep`).
    /// std's Mutex is not reentrant, so dispatching this under `ENGINE` is a
    /// hard deadlock on a device — and the stuck thread would still hold the
    /// lock the tick path needs, freezing the viewer too.
    #[test]
    fn the_agent2_callback_also_runs_with_the_engine_unlocked() {
        let _g = engine_guard();
        reset_engine();

        let observed: std::sync::Arc<Mutex<Option<bool>>> = std::sync::Arc::new(Mutex::new(None));
        let sink = std::sync::Arc::clone(&observed);
        ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_agent2_callback(move |_json| {
                *sink.lock().unwrap_or_else(|p| p.into_inner()) = Some(ENGINE.try_lock().is_ok());
            });

        dispatch_agent2_command(r#"{"type":"ping"}"#);

        let seen = *observed.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            seen,
            Some(true),
            "the Agent2 callback must be invoked with ENGINE unlocked"
        );
    }

    /// Registering a viewer is not the same fact as having a transport. They
    /// shared one Boolean before this phase.
    #[test]
    fn receiver_registration_is_independent_of_the_transport() {
        let _g = engine_guard();
        reset_engine();
        attach_receiver(true);
        engine_event(APKSessionEvent::TransportDisconnected);

        let still_registered = ENGINE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_frame_receiver_registered();
        assert!(
            still_registered,
            "losing the transport must not unregister the viewer"
        );

        engine_event(APKSessionEvent::TransportConnected);
        attach_receiver(false);
        let e = ENGINE.lock().unwrap_or_else(|p| p.into_inner());
        assert!(!e.is_frame_receiver_registered());
        assert!(
            e.is_transport_connected(),
            "unregistering the viewer must not drop the transport"
        );
    }

    // ── Phase 3: the Rust -> Kotlin callback contract ────────────────────

    /// Both callbacks are resolved during `JNI_OnLoad`, so a missing or
    /// mistyped Kotlin declaration refuses to load the library instead of
    /// failing at the first frame.
    #[test]
    fn every_rust_to_kotlin_callback_is_a_matching_jvm_static() {
        let dir = kotlin_dir();
        let mut checked = 0usize;
        for cb in callback_registrations() {
            let simple = cb.class.rsplit('/').next().expect("class name");
            let path = dir.join(format!("{simple}.kt"));
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let declared = declared_fun(&source, cb.method).unwrap_or_else(|| {
                panic!(
                    "{simple}.kt declares no `fun {}` — JNI_OnLoad resolves it at \
                     load time and would refuse to load the library",
                    cb.method
                )
            });
            assert!(
                declared.jvm_static,
                "{simple}.{} must be @JvmStatic for CallStaticVoidMethod to resolve it",
                cb.method
            );
            assert_eq!(
                declared.descriptor, cb.signature,
                "{simple}.{} descriptor mismatch: Kotlin declares {}, Rust resolves {}",
                cb.method, declared.descriptor, cb.signature
            );
            checked += 1;
        }
        assert!(
            checked >= 2,
            "both the Agent2 and the frame callback must be in the fail-closed contract"
        );
    }

    #[test]
    fn the_frame_callback_is_in_the_fail_closed_contract() {
        assert_eq!(FRAME_CALLBACK_CLASS, "com/remotedexter/FrameReceiver");
        assert_eq!(FRAME_CALLBACK_METHOD, "rdOnFrame");
        assert_eq!(FRAME_CALLBACK_SIG, "([BJIIZ)V");
        assert!(
            callback_registrations().iter().any(|c| {
                c.class == FRAME_CALLBACK_CLASS
                    && c.method == FRAME_CALLBACK_METHOD
                    && c.signature == FRAME_CALLBACK_SIG
            }),
            "the frame callback must be resolved during JNI_OnLoad, not discovered \
             missing at the first frame"
        );
    }

    /// The shipping `FrameReceiver.kt` must expose exactly the method Rust
    /// invokes — name, `@JvmStatic`, parameter types **and** parameter order.
    #[test]
    fn frame_receiver_declares_the_exact_callback_signature() {
        let source = std::fs::read_to_string(kotlin_dir().join("FrameReceiver.kt"))
            .expect("FrameReceiver.kt must ship with the app");
        let declared =
            declared_fun(&source, FRAME_CALLBACK_METHOD).expect("FrameReceiver.rdOnFrame");
        assert!(declared.jvm_static, "rdOnFrame must be @JvmStatic");
        assert_eq!(declared.descriptor, FRAME_CALLBACK_SIG);
        let params: Vec<(&str, &str)> = declared
            .params
            .iter()
            .map(|(n, t)| (n.as_str(), t.as_str()))
            .collect();
        assert_eq!(
            params,
            vec![
                ("jpeg", "ByteArray"),
                ("sequence", "Long"),
                ("width", "Int"),
                ("height", "Int"),
                ("keyframe", "Boolean"),
            ],
            "the callback argument order is part of the wire contract"
        );
    }

    /// A partial frame reports progress without inventing a frame.
    #[test]
    fn incomplete_frame_reports_pending_not_a_frame() {
        let chunks = chunk_frame(7, 640, 480, true, &vec![0xABu8; 9000], 4000);
        assert!(chunks.len() >= 3);
        let mut r = FrameReassembler::new();
        let framed = |c: &[u8]| {
            wire::Envelope::new(wire::Kind::FrameChunkV1, 0, c.to_vec())
                .expect("a real chunk must fit its kind")
                .encode()
        };
        assert_eq!(
            classify_inbound(&mut r, &framed(&chunks[0])),
            InboundMessage::ChunkPending
        );
        assert_eq!(
            classify_inbound(&mut r, &framed(&chunks[1])),
            InboundMessage::ChunkPending
        );
    }

    /// **The migration, stated as a test.** Bare JSON and bare chunks were the
    /// wire before Block 10, and both must now be refused: accepting either
    /// would mean the client silently talks two protocols, which is exactly the
    /// downgrade the version bump exists to prevent.
    #[test]
    fn the_old_unframed_wire_is_no_longer_accepted() {
        let mut r = FrameReassembler::new();
        assert_eq!(
            classify_inbound(&mut r, br#"{"type":"pong"}"#),
            InboundMessage::Unrecognized,
            "bare JSON is the pre-Block-10 wire and must not be accepted"
        );
        let chunks = chunk_frame(1, 64, 64, true, &vec![0u8; 100], 4000);
        assert_eq!(
            classify_inbound(&mut r, &chunks[0]),
            InboundMessage::Unrecognized,
            "a bare stream chunk is the pre-Block-10 wire and must not be accepted"
        );
    }

    /// Input rides its own kind, so the host can bound it separately from
    /// control JSON — it is the highest-frequency thing on the link and the
    /// only one reaching the injection path.
    #[test]
    fn input_events_are_sent_as_their_own_kind() {
        assert_eq!(
            kind_for_command(br#"{"type":"input_event","window":1,"event":{}}"#),
            wire::Kind::InputV1
        );
        assert_eq!(
            kind_for_command(br#"{"type":"list_windows"}"#),
            wire::Kind::ControlJson
        );
    }

    /// Unparseable payloads take the STRICT branch: ControlJson runs the
    /// depth-bounded JSON check, so a malformed command is refused by our own
    /// encoder rather than waved through as opaque input bytes.
    #[test]
    fn an_unparseable_command_takes_the_checked_kind() {
        assert_eq!(kind_for_command(b"not json"), wire::Kind::ControlJson);
        assert_eq!(kind_for_command(b""), wire::Kind::ControlJson);
    }
}

/// Hand one frame to `FrameReceiver.rdOnFrame`. Always called with `ENGINE`
/// unlocked — see `tick_and_dispatch_frame`.
///
/// A failure here drops **that frame only**: the Noise session is untouched,
/// no exception is left pending for the next JNI call, and nothing is logged
/// but a reason (never frame bytes).
fn call_kotlin_on_frame(frame: &FrameEnvelope) {
    let guard = JAVA_VM.lock().unwrap();
    let vm = match guard.as_ref() {
        Some(v) => v,
        None => return, // JNI not initialised yet
    };
    // Safe even if this thread is already attached, which it is on the tick
    // path: `rd_tick` arrives from Kotlin.
    let mut env = match vm.attach_current_thread() {
        Ok(e) => e,
        Err(_) => {
            rd_log!("[rd_jni] frame dropped: could not attach thread");
            return;
        }
    };

    let class = match callback_class(FRAME_CALLBACK_CLASS) {
        Some(c) => c,
        None => return, // JNI_OnLoad has not run
    };

    // A local frame bounds the JNI references this call creates. The byte array
    // is released when the frame pops, including on the error path, so a 30 fps
    // stream cannot exhaust the local reference table.
    let result: std::result::Result<(), jni::errors::Error> = env.with_local_frame(4, |env| {
        let jpeg = env.byte_array_from_slice(&frame.data)?;
        env.call_static_method(
            &class,
            FRAME_CALLBACK_METHOD,
            FRAME_CALLBACK_SIG,
            &[
                jni::objects::JValue::Object(&jpeg),
                jni::objects::JValue::Long(frame.sequence as i64),
                jni::objects::JValue::Int(frame.width as i32),
                jni::objects::JValue::Int(frame.height as i32),
                jni::objects::JValue::Bool(u8::from(frame.keyframe)),
            ],
        )?;
        Ok(())
    });

    if let Err(e) = result {
        // Reason only — never the frame contents.
        rd_log!("[rd_jni] frame dropped: {e}");
        // A pending exception would poison the next JNI call on this thread.
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }
}

fn call_kotlin_on_agent2_command(json: &str) {
    let guard = JAVA_VM.lock().unwrap();
    let vm = match guard.as_ref() {
        Some(v) => v,
        None => return, // JNI not initialised yet
    };
    // attach_current_thread is safe even if already attached
    let mut env = match vm.attach_current_thread() {
        Ok(e) => e,
        Err(_) => return,
    };
    // The cached global ref, not `find_class`: this runs on the tokio session
    // thread, where `FindClass` sees only the system class loader and would
    // never resolve an application class.
    let class = match callback_class(AGENT2_CALLBACK_CLASS) {
        Some(c) => c,
        None => return, // JNI_OnLoad has not run
    };

    let result: std::result::Result<(), jni::errors::Error> = env.with_local_frame(4, |env| {
        let jstr = env.new_string(json)?;
        env.call_static_method(
            &class,
            AGENT2_CALLBACK_METHOD,
            AGENT2_CALLBACK_SIG,
            &[jni::objects::JValue::Object(&jstr.into())],
        )?;
        Ok(())
    });

    if let Err(e) = result {
        // Reason only — never the command body.
        rd_log!("[rd_jni] agent2 command dropped: {e}");
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }
}
