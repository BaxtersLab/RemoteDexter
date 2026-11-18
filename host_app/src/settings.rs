//! What the host remembers between runs: `settings.json`.
//!
//! ## Why it exists
//!
//! Every choice this host makes used to live in the environment, so the only way
//! to configure it was a terminal. The operator launches it from the application
//! grid, and the grid's `.desktop` entry sets nothing — so the icon could never
//! offer the relay at all, and every capability grant died with the shell that
//! set it. A machine whose LAN address is not static needs the relay to be the
//! ordinary route, and that cannot live in a variable nobody sets.
//!
//! Design and the operator's decisions:
//! `constitution/planning/RELAY_DEFAULT_DESIGN_2026-09-15.md`.
//!
//! ## The rules this file follows
//!
//! * **Beside the identity, not in a config directory.** `data_dir()` is already
//!   the one directory the host owns and tightens to `0700`, and it already
//!   filters the snap-poisoned `XDG_DATA_HOME` that would otherwise file private
//!   state inside a snap revision. `$XDG_DATA_HOME` is honoured through that
//!   same function, so a real one moves this file with everything else.
//! * **Deny-by-default survives a restart.** A missing file grants nothing: no
//!   relay, no listener, no capability. A fresh install behaves exactly as it
//!   did before this file existed.
//! * **No secret is ever written here.** `auth` may only be `signing`, which
//!   proves the host with the identity it already holds. A bearer relay needs a
//!   token, and a token at rest is a credential the owner never chose to store.
//! * **A file that cannot be read must not stop the host.** It starts on
//!   defaults, says so where the owner can see it, and **leaves the file
//!   exactly as it is** so it can be fixed by hand rather than silently
//!   replaced.
//! * **Fields this build does not know are kept.** Downgrading a build must not
//!   quietly delete the settings a later one wrote.
//! * **The environment still wins, for that run, and visibly.** Development and
//!   every existing test set `RD_*`; those keep working, the file is never
//!   written from them, and the console names what was overridden.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The format this build writes. A later change is a migration, not a guess.
pub const VERSION: u32 = 1;

/// Where the settings live: `data_dir()/settings.json`.
pub fn path() -> PathBuf {
    crate::identity_store::data_dir().join("settings.json")
}

/// How the host proves itself to a relay. Only one value is allowed in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RelayAuth {
    /// The host signs the relay's challenge with the identity it already has.
    #[default]
    Signing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RelaySettings {
    /// `host:port` of the relay, or `None` when none is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default)]
    pub auth: RelayAuth,
    /// Dial the relay as soon as the host starts. **Never true by default:** a
    /// fresh install must ask before a machine announces itself to a relay.
    #[serde(default)]
    pub dial_on_start: bool,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// What KIND of pairing code this host shows.
///
/// **There is no stored interface or port here, and no `listen_on_start`.** P1
/// wrote a `lan` block for them and nothing ever read it; it is gone, and an
/// existing file's block survives untouched as an unknown section. A listener
/// is opened only by a click on Start — the operator kept that property when
/// asked (design §11) — and a remembered interface would make Start a reflex
/// rather than a decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PairingSettings {
    /// Mint the both-routes code (v6) when the host is serving BOTH routes.
    ///
    /// **Off by default:** only an app from this release can read a v6 code, so
    /// a host that turned this on by itself would hand the operator a code
    /// their phone refuses. Off, a host serving both routes shows the relay
    /// code, which every installed app reads. Ignored unless both routes are
    /// live: one route is still v4 or v5.
    #[serde(default)]
    pub dual_route_codes: bool,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// One capability, and when the owner allowed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Grant {
    #[serde(default)]
    pub granted: bool,
    /// RFC 3339, written when `granted` becomes true. Shown in the console, so
    /// a standing permission is never invisible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<String>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

impl Grant {
    /// Allow it, stamped now.
    pub fn allow(&mut self, now: String) {
        self.granted = true;
        self.granted_at = Some(now);
    }

    /// Withdraw it. The stamp goes with it: a revoked grant has no "since".
    pub fn revoke(&mut self) {
        self.granted = false;
        self.granted_at = None;
    }
}

/// The capabilities a host may be given, each deny-by-default and each its own
/// decision.
///
/// `input` never implies `clipboard`: a phone that may move the pointer has not
/// been allowed to read what is on the clipboard, which holds things that were
/// never on screen.
///
/// **There is no `file` grant here on purpose.** `RD_CAP_FILE` exists as a
/// variable and nothing in this build reads it, so storing it would be a
/// standing permission that enforces nothing — a setting that lies. It arrives
/// here when a file-transfer path does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Capabilities {
    #[serde(default)]
    pub capture: Grant,
    #[serde(default)]
    pub input: Grant,
    #[serde(default)]
    pub clipboard: Grant,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    #[serde(default)]
    pub relay: RelaySettings,
    #[serde(default)]
    pub pairing: PairingSettings,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

impl Default for Settings {
    /// Deny-by-default, in file form.
    fn default() -> Self {
        Settings {
            version: VERSION,
            relay: RelaySettings::default(),
            pairing: PairingSettings::default(),
            capabilities: Capabilities::default(),
            unknown: BTreeMap::new(),
        }
    }
}

/// A capability the owner can grant, and the one command family it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Capture,
    Input,
    Clipboard,
}

impl Capability {
    /// Every capability, in the order the console shows them.
    pub const ALL: [Capability; 3] = [
        Capability::Capture,
        Capability::Input,
        Capability::Clipboard,
    ];

    /// The environment variable that grants it for one run.
    pub fn env_var(self) -> &'static str {
        match self {
            Capability::Capture => "RD_CAP_SCREENSHOT",
            Capability::Input => "RD_CAP_INPUT",
            Capability::Clipboard => "RD_CAP_CLIPBOARD",
        }
    }

    /// The command family it gates, as the session loop names it.
    pub fn for_command(command: &str) -> Option<Capability> {
        match command {
            "screenshot_request" => Some(Capability::Capture),
            "input_event" => Some(Capability::Input),
            "clipboard" => Some(Capability::Clipboard),
            _ => None,
        }
    }

    /// What the console calls it.
    pub fn label(self) -> &'static str {
        match self {
            Capability::Capture => "Screen capture",
            Capability::Input => "Keyboard and pointer",
            Capability::Clipboard => "Clipboard",
        }
    }

    /// What allowing it actually permits, in the owner's words.
    pub fn detail(self) -> &'static str {
        match self {
            Capability::Capture => "A paired phone may see this screen once you share a window.",
            Capability::Input => {
                "A paired phone may move the pointer and type here. It does NOT give it the \
                 clipboard."
            }
            Capability::Clipboard => {
                "A paired phone may read and set this machine's clipboard, which holds things \
                 that were never on screen."
            }
        }
    }

    fn grant<'a>(self, settings: &'a Settings) -> &'a Grant {
        match self {
            Capability::Capture => &settings.capabilities.capture,
            Capability::Input => &settings.capabilities.input,
            Capability::Clipboard => &settings.capabilities.clipboard,
        }
    }

    fn grant_mut<'a>(self, settings: &'a mut Settings) -> &'a mut Grant {
        match self {
            Capability::Capture => &mut settings.capabilities.capture,
            Capability::Input => &mut settings.capabilities.input,
            Capability::Clipboard => &mut settings.capabilities.clipboard,
        }
    }
}

/// The settings this process is running on.
///
/// One copy, so a toggle in the console reaches the session loop's capability
/// checks at once rather than at the next restart. Written only by
/// [`allow`] / [`revoke`], which save the file in the same step: a permission
/// the console shows and the file does not carry would be a lie after a crash.
static ACTIVE: std::sync::OnceLock<std::sync::RwLock<Settings>> = std::sync::OnceLock::new();

fn active() -> &'static std::sync::RwLock<Settings> {
    ACTIVE.get_or_init(|| std::sync::RwLock::new(Settings::default()))
}

/// Make these settings the ones this process runs on.
pub fn set_active(settings: Settings) {
    *active().write().unwrap_or_else(|p| p.into_inner()) = settings;
}

/// A copy of the settings in force.
pub fn current() -> Settings {
    active().read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Is this capability allowed by the STORED settings? The environment is a
/// separate grant and is checked by the caller.
pub fn granted(cap: Capability) -> bool {
    cap.grant(&active().read().unwrap_or_else(|p| p.into_inner()))
        .granted
}

/// Why a change could not be made. Both variants are shown to the owner, so
/// both carry something that reads as an explanation rather than an error code.
#[derive(Debug)]
pub enum SaveError {
    /// The change itself was not allowed — the value is not an address, or the
    /// setting depends on one that is missing. **Nothing was written.**
    Refused(String),
    /// The change was fine and the file could not be written. **Nothing is in
    /// force either:** the file is the authority, so a setting the console
    /// showed and the disk did not carry would be a lie after a restart.
    Write(std::io::Error),
}

impl SaveError {
    /// One line, safe to show and to log.
    pub fn message(&self) -> String {
        match self {
            SaveError::Refused(why) => why.clone(),
            SaveError::Write(e) => format!("could not write the settings file: {}", e.kind()),
        }
    }
}

impl From<std::io::Error> for SaveError {
    fn from(e: std::io::Error) -> Self {
        SaveError::Write(e)
    }
}

/// Allow a capability from now on, and write it down.
///
/// The file is saved first: if the write fails, nothing is granted, so the
/// console never shows a permission the machine would forget.
pub fn allow(path: &Path, cap: Capability) -> Result<(), SaveError> {
    change(path, |s| {
        cap.grant_mut(s).allow(now_rfc3339());
        Ok(())
    })
}

/// Withdraw a capability now, and write it down.
pub fn revoke(path: &Path, cap: Capability) -> Result<(), SaveError> {
    change(path, |s| {
        cap.grant_mut(s).revoke();
        Ok(())
    })
}

/// Remember a relay address, or forget the stored one.
///
/// **Forgetting it also turns off `dial_on_start`.** A host told to dial on
/// start with nowhere to dial would spend every launch retrying nothing, and
/// the checkbox would be describing a relay that is not there.
pub fn set_relay_address(path: &Path, address: Option<&str>) -> Result<(), SaveError> {
    let address = match address {
        Some(raw) => Some(validated_relay_address(raw)?),
        None => None,
    };
    change(path, |s| {
        if address.is_none() {
            s.relay.dial_on_start = false;
        }
        s.relay.address = address.clone();
        Ok(())
    })
}

/// Turn "connect through the relay whenever RemoteDexter starts" on or off.
///
/// Turning it ON needs a stored address: the stored choice must describe
/// something real, and a checkbox that ticks with nothing behind it is how an
/// operator ends up believing their machine is reachable when it is not.
pub fn set_dial_on_start(path: &Path, on: bool) -> Result<(), SaveError> {
    change(path, |s| {
        if on {
            let Some(addr) = s.relay.address.as_deref() else {
                return Err(SaveError::Refused(
                    "there is no relay to connect to — set a relay address first".to_string(),
                ));
            };
            validated_relay_address(addr)?;
        }
        s.relay.dial_on_start = on;
        Ok(())
    })
}

/// Turn "pairing codes carry both routes" on or off.
///
/// No precondition: it describes what to mint when the host happens to be
/// serving both routes, and a host with one route keeps minting v4 or v5
/// whatever this says. Turning it on cannot expose anything — a code names
/// routes the host is already on.
pub fn set_dual_route_codes(path: &Path, on: bool) -> Result<(), SaveError> {
    change(path, |s| {
        s.pairing.dual_route_codes = on;
        Ok(())
    })
}

/// A relay address this host could actually dial, or why it could not.
///
/// A NAME is refused, deliberately. Resolving one means a DNS lookup at start,
/// which can hang, can be poisoned, and can return a different machine than the
/// one whose key this host has enrolled. The relay is named by address in the
/// invite, in `relayd`'s own configuration and in the deploy record.
pub fn validated_relay_address(raw: &str) -> Result<String, SaveError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SaveError::Refused(
            "a relay address looks like 203.0.113.9:9443".to_string(),
        ));
    }
    match trimmed.parse::<std::net::SocketAddr>() {
        Ok(addr) => Ok(addr.to_string()),
        Err(_) => Err(SaveError::Refused(format!(
            "`{trimmed}` is not an address and port — a relay looks like 203.0.113.9:9443, and a \
             name is not accepted because it would be resolved at every start"
        ))),
    }
}

fn change(
    path: &Path,
    f: impl FnOnce(&mut Settings) -> Result<(), SaveError>,
) -> Result<(), SaveError> {
    let mut next = current();
    f(&mut next)?;
    save_to(path, &next)?;
    set_active(next);
    Ok(())
}

/// `YYYY-MM-DDTHH:MM:SSZ` for right now, without pulling in a date library.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    rfc3339(secs)
}

/// Civil date from a Unix timestamp (Howard Hinnant's days-from-civil, run
/// backwards). Pure, so the formatting is provable without waiting for a date.
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let time = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        time / 3_600,
        (time % 3_600) / 60,
        time % 60
    )
}

/// What the console shows for one capability, and what its button does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    /// "Keyboard and pointer: allowed since 2026-09-15T10:03:00Z"
    pub headline: String,
    /// What allowing it permits, plus where the grant came from.
    pub detail: String,
    pub action: GrantAction,
}

/// What the owner can do about a capability right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAction {
    /// Not allowed: offer to allow it.
    Allow,
    /// Allowed by the stored settings: offer to withdraw it.
    Revoke,
    /// Granted by a variable for this run. There is nothing to revoke here —
    /// the button would not change what the session loop sees — so the console
    /// says where it came from instead of offering a control that does nothing.
    EnvironmentHolds,
}

/// One capability, as the console should show it.
pub fn grant_view(cap: Capability, settings: &Settings, env_grants: bool) -> GrantView {
    let grant = cap.grant(settings);
    let label = cap.label();
    match (env_grants, grant.granted) {
        (true, stored) => GrantView {
            headline: format!("{label}: allowed for this run"),
            detail: format!(
                "{} Granted by {} in the environment{}.",
                cap.detail(),
                cap.env_var(),
                if stored {
                    " as well as by your stored settings"
                } else {
                    ", not by your stored settings"
                }
            ),
            action: GrantAction::EnvironmentHolds,
        },
        (false, true) => GrantView {
            headline: match grant.granted_at.as_deref() {
                Some(when) => format!("{label}: allowed since {when}"),
                None => format!("{label}: allowed"),
            },
            detail: cap.detail().to_string(),
            action: GrantAction::Revoke,
        },
        (false, false) => GrantView {
            headline: format!("{label}: not allowed"),
            detail: cap.detail().to_string(),
            action: GrantAction::Allow,
        },
    }
}

/// What happened when the settings were read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// No file yet: defaults, and nothing was written to create it.
    Defaults,
    /// Read from the file.
    File,
    /// The file could not be read or parsed. **Defaults are in use and the file
    /// was left untouched.** The string is safe to show and to log.
    Unreadable(String),
}

/// Settings plus where they came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub settings: Settings,
    pub source: Source,
}

impl Loaded {
    /// One line for the console, naming the file either way.
    pub fn summary(&self, at: &Path) -> String {
        match &self.source {
            Source::Defaults => format!("Settings: defaults — no file yet ({})", at.display()),
            Source::File => format!("Settings: {}", at.display()),
            Source::Unreadable(why) => format!(
                "Settings: {} could not be read ({why}) — defaults are in use and the file was \
                 left as it is",
                at.display()
            ),
        }
    }
}

/// Read the settings, or fall back to defaults with the reason.
pub fn load_from(path: &Path) -> Loaded {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Loaded {
                settings: Settings::default(),
                source: Source::Defaults,
            }
        }
        Err(e) => {
            return Loaded {
                settings: Settings::default(),
                source: Source::Unreadable(e.kind().to_string()),
            }
        }
    };
    match serde_json::from_str::<Settings>(&text) {
        Ok(settings) if settings.version == VERSION => Loaded {
            settings,
            source: Source::File,
        },
        Ok(settings) => Loaded {
            settings: Settings::default(),
            source: Source::Unreadable(format!(
                "version {} — this build writes version {VERSION}",
                settings.version
            )),
        },
        Err(e) => Loaded {
            settings: Settings::default(),
            // serde names the line and the shape of the problem, never a value
            // out of the file: this string is shown and logged.
            source: Source::Unreadable(format!("line {}: {:?} json", e.line(), e.classify())),
        },
    }
}

/// Write the settings atomically, owner-only and durably — the path the device
/// list already proves: a temporary file beside the real one, then a rename, so
/// a crash leaves either the old file or the new one and never half of either.
///
/// The only writer is the console: its capability toggles and its relay
/// controls. Nothing else in the host writes this file.
pub fn save_to(path: &Path, settings: &Settings) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    crate::identity_store::write_owner_only(&tmp, format!("{text}\n").as_bytes())?;
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// A stored choice that the environment is overriding for this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub variable: &'static str,
    pub what: String,
}

/// What the environment says about the relay and the capabilities, and which
/// stored choices it is overriding.
///
/// The file is never written from the environment. `RD_*` keeps working for
/// development and for every test that sets it, and the console names what it
/// changed — a setting that is quietly ignored is worse than one that is absent.
pub fn overrides(settings: &Settings, var: impl Fn(&str) -> Option<String>) -> Vec<Override> {
    let mut out = Vec::new();
    if let Some(addr) = var("RD_RELAY") {
        if settings.relay.address.as_deref() != Some(addr.as_str()) {
            out.push(Override {
                variable: "RD_RELAY",
                what: format!("relay address {addr}"),
            });
        }
    }
    for (variable, granted, name) in [
        (
            "RD_CAP_SCREENSHOT",
            settings.capabilities.capture.granted,
            "screen capture",
        ),
        ("RD_CAP_INPUT", settings.capabilities.input.granted, "input"),
        (
            "RD_CAP_CLIPBOARD",
            settings.capabilities.clipboard.granted,
            "clipboard",
        ),
    ] {
        if var(variable).is_some() && !granted {
            out.push(Override {
                variable,
                what: format!("{name} allowed for this run"),
            });
        }
    }
    out
}

/// Serialises the tests that touch the process-wide active settings.
///
/// `ACTIVE` is one value for the whole process, exactly as it is in the running
/// host, so two tests setting it on different threads is a race — and it was:
/// the capability tests in `main` and these tests failed each other until this
/// existed. Anything taking both this and `main`'s `ENV_LOCK` takes ENV_LOCK
/// first.
#[cfg(test)]
pub(crate) static ACTIVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn active_guard() -> std::sync::MutexGuard<'static, ()> {
        ACTIVE_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rd-settings-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("settings.json")
    }

    #[test]
    fn no_file_means_deny_by_default_and_nothing_is_written() {
        let p = scratch("absent");
        let loaded = load_from(&p);
        assert_eq!(loaded.source, Source::Defaults);
        assert!(
            !loaded.settings.relay.dial_on_start,
            "a fresh install must not dial a relay"
        );
        assert!(loaded.settings.relay.address.is_none());
        assert!(
            !loaded.settings.pairing.dual_route_codes,
            "a fresh install must not mint codes only the newest app can read"
        );
        let c = &loaded.settings.capabilities;
        assert!(!c.capture.granted && !c.input.granted && !c.clipboard.granted);
        assert!(!p.exists(), "reading settings must not create them");
    }

    #[test]
    fn a_file_that_omits_a_field_still_denies_it() {
        // The OTHER default: serde's, used when a file exists but says nothing
        // about a setting. A mutant that flipped only this one passed every
        // test until this existed.
        let p = scratch("sparse");
        // Both shapes: sections absent entirely, and sections present but empty
        // — they take different paths (the struct's Default, and serde's
        // per-field default), and only the second exercises the field defaults.
        for text in [
            r#"{"version":1}"#,
            r#"{"version":1,"relay":{},"pairing":{},"capabilities":{"capture":{},"input":{},"clipboard":{},"file":{}}}"#,
        ] {
            std::fs::write(&p, text).unwrap();
            let loaded = load_from(&p);
            assert_eq!(loaded.source, Source::File, "{text}");
            let s = &loaded.settings;
            assert!(
                !s.relay.dial_on_start,
                "an omitted dial_on_start must not dial: {text}"
            );
            assert!(
                !s.pairing.dual_route_codes,
                "an omitted dual_route_codes must not mint v6: {text}"
            );
            assert_eq!(s.relay.auth, RelayAuth::Signing, "{text}");
            assert!(
                !s.capabilities.capture.granted
                    && !s.capabilities.input.granted
                    && !s.capabilities.clipboard.granted,
                "an omitted capability must not be granted: {text}"
            );
        }
        let loaded = load_from(&p);
        let s = &loaded.settings;
        assert!(
            !s.relay.dial_on_start,
            "an omitted dial_on_start must not dial"
        );
        assert!(
            !s.pairing.dual_route_codes,
            "an omitted dual_route_codes must not mint v6"
        );
        assert_eq!(s.relay.auth, RelayAuth::Signing);
        assert!(
            !s.capabilities.capture.granted
                && !s.capabilities.input.granted
                && !s.capabilities.clipboard.granted,
            "an omitted capability must not be granted"
        );
    }

    #[test]
    fn what_was_saved_is_what_comes_back() {
        let p = scratch("roundtrip");
        let mut s = Settings::default();
        s.relay.address = Some("198.51.100.9:9443".into());
        s.relay.dial_on_start = true;
        s.pairing.dual_route_codes = true;
        s.capabilities.input.allow("2026-09-15T10:03:00Z".into());
        save_to(&p, &s).unwrap();
        let back = load_from(&p);
        assert_eq!(back.source, Source::File);
        assert_eq!(back.settings, s);
        assert_eq!(
            back.settings.capabilities.input.granted_at.as_deref(),
            Some("2026-09-15T10:03:00Z")
        );
    }

    #[test]
    fn a_revoked_grant_keeps_no_since() {
        let mut g = Grant::default();
        g.allow("2026-09-15T10:03:00Z".into());
        g.revoke();
        assert!(!g.granted);
        assert_eq!(
            g.granted_at, None,
            "a revoked grant must not keep a date that reads as live"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("modes");
        save_to(&p, &Settings::default()).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "settings were world-readable");
        let dir = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir, 0o700, "the directory holding them was not tightened");
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let p = scratch("tmp");
        save_to(&p, &Settings::default()).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left {leftovers:?}");
    }

    #[test]
    fn a_broken_file_gives_defaults_and_is_not_rewritten() {
        let p = scratch("broken");
        let junk = "{ this is not json";
        std::fs::write(&p, junk).unwrap();
        let loaded = load_from(&p);
        assert!(
            matches!(loaded.source, Source::Unreadable(_)),
            "{:?}",
            loaded.source
        );
        assert_eq!(
            loaded.settings,
            Settings::default(),
            "a broken file must not grant anything"
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            junk,
            "the operator's file was rewritten; it must be left to be fixed by hand"
        );
        assert!(loaded.summary(&p).contains("left as it is"));
    }

    #[test]
    fn a_file_from_a_newer_build_is_refused_rather_than_guessed_at() {
        let p = scratch("newer");
        std::fs::write(&p, r#"{"version":99,"relay":{"dial_on_start":true}}"#).unwrap();
        let loaded = load_from(&p);
        match loaded.source {
            Source::Unreadable(ref why) => assert!(why.contains("version 99"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert!(
            !loaded.settings.relay.dial_on_start,
            "a version this build cannot read granted something"
        );
    }

    #[test]
    fn fields_this_build_does_not_know_survive_a_save() {
        let p = scratch("unknown");
        std::fs::write(
            &p,
            r#"{"version":1,"relay":{"address":"198.51.100.9:9443","future_knob":7},"tomorrow":{"a":1}}"#,
        )
        .unwrap();
        let loaded = load_from(&p);
        assert_eq!(loaded.source, Source::File);
        save_to(&p, &loaded.settings).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("future_knob"),
            "a newer build's setting was deleted: {text}"
        );
        assert!(
            text.contains("tomorrow"),
            "a newer build's section was deleted: {text}"
        );
    }

    /// **The `lan` block P1 wrote is gone, and a file that has one keeps it.**
    /// Nothing ever read it, so removing it is not a migration — but deleting
    /// an existing file's section would throw away settings a later build may
    /// still want, and `listen_on_start` must not come back by accident.
    #[test]
    fn the_unread_lan_block_is_kept_as_an_unknown_section_and_acted_on_by_nothing() {
        let _g = active_guard();
        let p = scratch("lan-block");
        std::fs::write(
            &p,
            r#"{"version":1,"lan":{"interface":"wlan0","port":8082,"listen_on_start":true},"relay":{"address":"198.51.100.9:9443"}}"#,
        )
        .unwrap();
        let loaded = load_from(&p);
        assert_eq!(loaded.source, Source::File);
        assert_eq!(
            loaded.settings.relay.address.as_deref(),
            Some("198.51.100.9:9443"),
            "the rest of the file must still be read"
        );
        assert!(
            loaded.settings.unknown.contains_key("lan"),
            "the lan block was dropped instead of kept: {:?}",
            loaded.settings.unknown
        );
        save_to(&p, &loaded.settings).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.contains("listen_on_start"),
            "the lan block was deleted: {text}"
        );
    }

    /// The code format is the operator's choice, it persists, and it starts off.
    #[test]
    fn pairing_codes_carry_both_routes_only_once_it_is_turned_on() {
        let _g = active_guard();
        let p = scratch("dual-codes");
        set_active(Settings::default());
        assert!(!current().pairing.dual_route_codes, "it must start off");

        set_dual_route_codes(&p, true).expect("turning it on");
        assert!(
            current().pairing.dual_route_codes,
            "the running host did not see it"
        );
        assert!(
            load_from(&p).settings.pairing.dual_route_codes,
            "it did not survive a restart"
        );

        set_dual_route_codes(&p, false).expect("turning it off");
        assert!(!current().pairing.dual_route_codes);
        assert!(!load_from(&p).settings.pairing.dual_route_codes);
    }

    #[test]
    fn the_environment_overrides_the_file_and_says_so() {
        let mut s = Settings::default();
        s.relay.address = Some("198.51.100.9:9443".into());
        let env = |k: &str| match k {
            "RD_RELAY" => Some("203.0.113.1:9443".to_string()),
            "RD_CAP_INPUT" => Some("1".to_string()),
            _ => None,
        };
        let got = overrides(&s, env);
        assert!(got
            .iter()
            .any(|o| o.variable == "RD_RELAY" && o.what.contains("203.0.113.1:9443")));
        assert!(got
            .iter()
            .any(|o| o.variable == "RD_CAP_INPUT" && o.what.contains("input")));
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn an_environment_that_agrees_with_the_file_is_not_reported_as_an_override() {
        let mut s = Settings::default();
        s.relay.address = Some("203.0.113.1:9443".into());
        s.capabilities.input.allow("2026-09-15T10:03:00Z".into());
        let env = |k: &str| match k {
            "RD_RELAY" => Some("203.0.113.1:9443".to_string()),
            "RD_CAP_INPUT" => Some("1".to_string()),
            _ => None,
        };
        assert!(overrides(&s, env).is_empty());
    }

    #[test]
    fn a_stored_grant_is_what_the_session_loop_sees_and_a_revoke_lands_at_once() {
        let _lock = active_guard();
        let p = scratch("grants");
        set_active(Settings::default());
        assert!(!granted(Capability::Input), "deny-by-default");
        allow(&p, Capability::Input).unwrap();
        assert!(
            granted(Capability::Input),
            "an allowed capability must take effect now"
        );
        assert!(
            !granted(Capability::Clipboard),
            "input must not imply clipboard"
        );
        assert!(
            !granted(Capability::Capture),
            "input must not imply capture"
        );
        // It is on disk, not only in memory.
        let back = load_from(&p);
        assert!(back.settings.capabilities.input.granted);
        assert!(back.settings.capabilities.input.granted_at.is_some());
        revoke(&p, Capability::Input).unwrap();
        assert!(
            !granted(Capability::Input),
            "a revoke must land without a restart"
        );
        assert!(
            !load_from(&p).settings.capabilities.input.granted,
            "the revoke was not written"
        );
        set_active(Settings::default());
    }

    #[test]
    fn a_grant_that_cannot_be_written_is_not_granted() {
        // A directory where the file should be: saving fails, so nothing may be
        // granted — the console must never show a permission the machine forgets.
        let _lock = active_guard();
        let p = scratch("unwritable");
        std::fs::create_dir_all(&p).unwrap();
        set_active(Settings::default());
        assert!(allow(&p, Capability::Capture).is_err());
        assert!(
            !granted(Capability::Capture),
            "granted despite the write failing"
        );
        set_active(Settings::default());
    }

    #[test]
    fn the_console_shows_where_a_capability_came_from() {
        let mut s = Settings::default();
        let off = grant_view(Capability::Input, &s, false);
        assert_eq!(off.headline, "Keyboard and pointer: not allowed");
        assert_eq!(off.action, GrantAction::Allow);

        s.capabilities.input.allow("2026-09-15T10:03:00Z".into());
        let on = grant_view(Capability::Input, &s, false);
        assert_eq!(
            on.headline,
            "Keyboard and pointer: allowed since 2026-09-15T10:03:00Z"
        );
        assert_eq!(on.action, GrantAction::Revoke);
        assert!(on.detail.contains("does NOT give it the clipboard"));

        let env = grant_view(Capability::Clipboard, &Settings::default(), true);
        assert_eq!(env.headline, "Clipboard: allowed for this run");
        assert_eq!(env.action, GrantAction::EnvironmentHolds);
        assert!(env.detail.contains("RD_CAP_CLIPBOARD"));
        assert!(env.detail.contains("not by your stored settings"));
    }

    #[test]
    fn every_capability_names_the_command_it_gates() {
        assert_eq!(
            Capability::for_command("screenshot_request"),
            Some(Capability::Capture)
        );
        assert_eq!(
            Capability::for_command("input_event"),
            Some(Capability::Input)
        );
        assert_eq!(
            Capability::for_command("clipboard"),
            Some(Capability::Clipboard)
        );
        assert_eq!(
            Capability::for_command("file_transfer"),
            None,
            "nothing reads RD_CAP_FILE yet"
        );
        assert_eq!(Capability::for_command("stream_start"), None);
    }

    #[test]
    fn the_date_stamp_is_a_real_utc_date() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // 2026-09-15T10:03:00Z, the day this was written.
        assert_eq!(rfc3339(1_789_466_580), "2026-09-15T10:03:00Z");
        // A leap day, where a wrong algorithm slips by a day.
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert!(now_rfc3339().starts_with("20"), "{}", now_rfc3339());
    }

    #[test]
    fn the_path_sits_beside_the_identity_and_follows_xdg_data_home() {
        let p = path();
        assert_eq!(p.file_name().unwrap(), "settings.json");
        assert_eq!(
            p.parent(),
            Some(crate::identity_store::data_dir().as_path())
        );
    }

    #[test]
    fn only_signing_is_a_storable_relay_credential() {
        // A token in a settings file is a credential at rest the owner never
        // chose to store, so the type cannot express one.
        let s: Settings = serde_json::from_str(r#"{"version":1,"relay":{"auth":"bearer"}}"#)
            .map(|s: Settings| s)
            .unwrap_or_default();
        assert_eq!(s.relay.auth, RelayAuth::Signing);
        assert_eq!(
            serde_json::to_string(&RelayAuth::Signing).unwrap(),
            "\"signing\""
        );
    }

    /// **A relay is named by address, never by name.**
    ///
    /// A hostname would be resolved at every start: it can hang, it can be
    /// answered by whatever the current network's resolver says, and the host
    /// has pinned the KEY of one particular relay. Refusing it here is what
    /// keeps that from being discovered on a hotel network.
    #[test]
    fn a_relay_address_is_an_address_and_port_or_it_is_refused() {
        for good in [
            "203.0.113.9:9443",
            " 203.0.113.9:9443 ",
            "[2001:db8::1]:9443",
        ] {
            assert!(
                validated_relay_address(good).is_ok(),
                "a real relay address was refused: {good}"
            );
        }
        for bad in ["", "   ", "relay.example.com:9443", "203.0.113.9", "9443"] {
            let refused = validated_relay_address(bad);
            assert!(
                matches!(refused, Err(SaveError::Refused(_))),
                "this was accepted as a relay address: {bad:?}"
            );
        }
        // Stored in one canonical spelling, so "is this the stored one" is a
        // string comparison the console can trust.
        assert_eq!(
            validated_relay_address(" 203.0.113.9:9443 ").unwrap(),
            "203.0.113.9:9443"
        );
    }

    /// **"Connect on start" cannot be turned on with nowhere to connect.**
    ///
    /// A ticked box with no relay behind it is an operator who believes their
    /// machine is reachable from outside when it is not — and who finds out
    /// when they are away from it.
    #[test]
    fn connecting_on_start_needs_a_relay_to_connect_to() {
        let _env = active_guard();
        let p = scratch("dial-needs-relay");
        set_active(Settings::default());

        let refused = set_dial_on_start(&p, true);
        assert!(
            matches!(refused, Err(SaveError::Refused(_))),
            "connect-on-start was allowed with no relay stored"
        );
        assert!(
            !p.exists(),
            "a refused change wrote the settings file anyway"
        );
        assert!(
            !current().relay.dial_on_start,
            "a refused change took effect in this run"
        );

        set_relay_address(&p, Some("203.0.113.9:9443")).unwrap();
        set_dial_on_start(&p, true).unwrap();
        assert!(load_from(&p).settings.relay.dial_on_start);
    }

    /// **Forgetting the relay stops connecting on start.**
    ///
    /// Otherwise the file keeps a standing instruction to dial nothing, every
    /// launch spends its life retrying, and the console shows a checkbox
    /// describing a relay that is not there.
    #[test]
    fn forgetting_the_relay_also_turns_off_connecting_on_start() {
        let _env = active_guard();
        let p = scratch("forget-relay");
        set_active(Settings::default());

        set_relay_address(&p, Some("203.0.113.9:9443")).unwrap();
        set_dial_on_start(&p, true).unwrap();
        set_relay_address(&p, None).unwrap();

        let stored = load_from(&p).settings;
        assert!(
            stored.relay.address.is_none(),
            "the relay address was not forgotten"
        );
        assert!(
            !stored.relay.dial_on_start,
            "the host was left told to connect on start with nowhere to connect"
        );
        assert!(!current().relay.dial_on_start);
    }

    /// A relay setting that could not be written is not in force either. The
    /// file is the authority, and a choice the console showed and the disk did
    /// not carry would be a lie after the next restart.
    #[test]
    fn a_relay_that_cannot_be_written_is_not_remembered() {
        let _env = active_guard();
        set_active(Settings::default());
        // A path whose PARENT is a file. A merely missing directory is not
        // unwritable — the writer creates one — so a test using that proves
        // nothing about this.
        let blocker = scratch("unwritable").with_file_name("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let p = blocker.join("settings.json");

        let failed = set_relay_address(&p, Some("203.0.113.9:9443"));
        assert!(
            matches!(failed, Err(SaveError::Write(_))),
            "an unwritable settings file did not report a write failure"
        );
        assert!(
            current().relay.address.is_none(),
            "a relay that could not be written was remembered anyway"
        );
    }
}
