//! Bounded, deterministic fuzzing of every parser that reads bytes from a peer.
//!
//! Block 14 requires the invite, envelope, input and frame parsers fuzzed with
//! bounded corpora and zero crashes. This is that, and it is deliberately NOT
//! `cargo-fuzz`:
//!
//! * `cargo-fuzz` needs nightly and a separate toolchain, so it could not run in
//!   the ordinary gate — and a fuzz target nobody runs finds nothing.
//! * Its corpus is a directory of accumulated files, so reproducing a failure
//!   means still having that directory. Here every input comes from a **printed
//!   seed**: a failure is replayed with the seed and nothing has to be kept.
//!
//! Bounded on purpose — a fixed budget that runs in about a second, so it lives
//! in the gate rather than in a nightly job somebody has to remember.
//! `RD_FUZZ_ITERS` and `RD_FUZZ_SEED` raise or move it for a longer soak without
//! touching the code.
//!
//! ## What counts as a failure
//!
//! A panic. These parsers read bytes an unauthenticated or half-authenticated
//! peer controls, so `Ok` and `Err` are the only acceptable outcomes. An index
//! out of bounds, an unchecked slice, an overflow, or an allocation sized from
//! an attacker's length field are all crashes — and a crash before the handshake
//! completes is a denial of service that needs no credentials at all.
//!
//! ## Four parsers, honestly counted as three
//!
//! The plan names invite, envelope, input and **frame**. There is no separate
//! Rust frame parser: a frame chunk IS an envelope —
//! `Envelope::new(Kind::FrameChunkV1, 0, chunk)` — and reassembly happens in
//! Kotlin on the client. So the frame path is fuzzed as frame-shaped envelopes,
//! said plainly rather than counted as a fourth target that does not exist.

/// xorshift64*. Eight lines and no dependency: a fuzz harness that adds a crate
/// to the dependency-rows gate has to justify itself, and "I needed random
/// numbers" is not a justification.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Zero is a fixed point of xorshift — it would emit zeros forever and
        // give a green run over a single input.
        Rng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| (self.next_u64() & 0xFF) as u8).collect()
    }
}

fn iters() -> usize {
    std::env::var("RD_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// Fixed by default and printed either way: fixed so a green gate run means the
/// same thing twice, printed so anything a soak finds can be replayed exactly.
fn seed() -> u64 {
    let s = std::env::var("RD_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5EED_1234_ABCD_0001);
    eprintln!("[fuzz] seed={s:#018x} iters={}", iters());
    s
}

/// Mutate a valid encoding. Pure random bytes rarely survive the first length
/// check, so the interesting inputs are the *nearly* valid ones.
fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    match rng.below(5) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1u8 << rng.below(8);
        }
        1 if !v.is_empty() => {
            // Truncation catches every "read the header, then trust it" bug.
            let n = rng.below(v.len());
            v.truncate(n);
        }
        2 => {
            // A decoder that ignores trailing bytes accepts two different
            // messages as the same one.
            v.extend(rng.bytes(64));
        }
        3 if v.len() > 4 => {
            // Lie about a length field. The first bytes are where the envelope
            // keeps its own, and an attacker controls them.
            let i = rng.below(4);
            v[i] = (rng.next_u64() & 0xFF) as u8;
        }
        _ => {
            if v.len() > 2 {
                let a = rng.below(v.len());
                let b = rng.below(v.len());
                v.swap(a, b);
            }
        }
    }
    v
}

fn valid_envelopes() -> Vec<Vec<u8>> {
    use wire::{Envelope, Kind};
    let mut out = Vec::new();
    for kind in [
        Kind::ControlJson,
        Kind::InputV1,
        Kind::FrameChunkV1,
        Kind::Ping,
        Kind::Close,
    ] {
        for payload in [vec![], b"{}".to_vec(), vec![0xAB; 512]] {
            if let Ok(e) = Envelope::new(kind, 0, payload) {
                out.push(e.encode());
            }
        }
    }
    assert!(
        !out.is_empty(),
        "no valid envelope could be built to mutate"
    );
    out
}

/// The envelope decoder, which is also the frame path. Every byte a peer sends
/// after the handshake arrives here first — the largest attack surface here.
#[test]
fn envelope_decoder_never_panics() {
    let mut rng = Rng::new(seed());
    let corpus = valid_envelopes();
    let n = iters();

    for i in 0..n {
        let input = if i % 3 == 0 {
            rng.bytes(2048)
        } else {
            let base = &corpus[rng.below(corpus.len())];
            mutate(&mut rng, base)
        };

        if let Ok(env) = wire::decode_exact(&input) {
            // A decoder that accepts what it cannot reproduce has silently
            // discarded something.
            let re = env.encode();
            let again = wire::decode_exact(&re).unwrap_or_else(|e| {
                panic!("re-encode of an accepted envelope failed to decode: {e:?}")
            });
            assert_eq!(again.kind, env.kind, "round-trip changed the kind");
            assert_eq!(again.payload, env.payload, "round-trip changed the payload");
        }
    }
    eprintln!("[fuzz] envelope: {n} inputs, no panic");
}

/// The input decoder. Reached only with the input grant — but that grant is
/// given to a phone, and a phone is not a trusted computing base.
#[test]
fn input_decoder_never_panics() {
    let mut rng = Rng::new(seed() ^ 0x1111);
    let corpus: Vec<Vec<u8>> = [
        r#"{"MouseMove":{"mode":"Absolute","dx":0,"dy":0,"abs_x":10,"abs_y":10}}"#,
        r#"{"MouseButton":{"button":0,"action":"Down"}}"#,
        r#"{"MouseScroll":{"dx":0,"dy":1,"mode":"Lines"}}"#,
        r#"{"KeyEvent":{"scan_code":46,"action":"Down","modifiers":2}}"#,
        r#"{"TextInput":{"text":"hello"}}"#,
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let n = iters();

    for i in 0..n {
        let input = if i % 3 == 0 {
            rng.bytes(1024)
        } else {
            let pick = rng.below(corpus.len());
            mutate(&mut rng, &corpus[pick])
        };
        let _ = module10::decode::decode(&input);
    }
    eprintln!("[fuzz] input: {n} inputs, no panic");
}

/// The invite decoder. **Pre-authentication**: it runs on text scanned from a QR
/// code before any signature is checked, which makes it the parser an attacker
/// reaches most cheaply — print a QR, leave it somewhere.
#[test]
fn invite_decoder_never_panics() {
    let mut rng = Rng::new(seed() ^ 0x2222);
    let corpus: Vec<Vec<u8>> = [
        r#"{"v":4,"kind":"rdx-invite","host":"1.2.3.4:8080","fp":"aa","exp":99,"sig":"bb"}"#,
        r#"{"v":3,"kind":"rdx-invite","host":"1.2.3.4:8080","fp":"aa","exp":99}"#,
        r#"{}"#,
        r#"[]"#,
        r#"null"#,
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let n = iters();

    for i in 0..n {
        let bytes = if i % 3 == 0 {
            rng.bytes(1024)
        } else {
            let pick = rng.below(corpus.len());
            mutate(&mut rng, &corpus[pick])
        };
        // The decoder takes &str, so it must be fed lossily — otherwise every
        // non-UTF-8 mutation is discarded by the harness rather than by the
        // code under test, and the harness quietly does the rejecting.
        let text = String::from_utf8_lossy(&bytes);
        let _ = pairing::decode(&text);
    }
    eprintln!("[fuzz] invite: {n} inputs, no panic");
}

/// Shapes chosen by hand: the cases a random stream is unlikely to reach but an
/// attacker writes down first.
#[test]
fn the_adversarial_edges_are_handled() {
    for input in [vec![], vec![0u8], vec![0u8; 4], vec![0xFF; 4]] {
        let _ = wire::decode_exact(&input);
        let _ = module10::decode::decode(&input);
    }

    // A length field claiming far more than follows — the classic
    // allocate-what-they-said bug. If this ever hangs or exhausts memory, that
    // is the finding, not a flake.
    let mut lying = vec![0xFFu8, 0xFF, 0xFF, 0xFF];
    lying.extend_from_slice(b"short");
    assert!(
        wire::decode_exact(&lying).is_err(),
        "a length field larger than the message must be refused"
    );

    // Deep nesting: serde recurses, and recursion is stack.
    let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
    let _ = pairing::decode(&deep);
    let _ = module10::decode::decode(deep.as_bytes());

    // Truncated mid-string.
    let _ = module10::decode::decode(br#"{"TextInput":{"text":"#);

    eprintln!("[fuzz] adversarial edges: handled");
}
