//! The optional `/dev/uinput` grant, as the host console sees it.
//!
//! ## What this replaces
//!
//! Until Block 7 the answer to "RemoteDexter cannot inject input" was a line on
//! stderr telling the user to run `usermod -aG input`. Nobody reads stderr, and
//! the advice was worse than useless: the `input` group also owns
//! `/dev/input/event*`, so taking it hands every process running as that user a
//! live keylogger — permanently, whether RemoteDexter is running or not. A
//! remote-control app should not be the reason a machine gains that property.
//!
//! What replaces it is one udev rule tagging `/dev/uinput` with `uaccess`, so
//! logind grants the device to whoever is sitting at the machine and takes it
//! back when they log out. The rule ships as inert package data and reaches
//! `/etc/udev/rules.d` only when the user presses **Enable input**.
//!
//! ## What this module is allowed to do
//!
//! Build a command line and read `key=value` lines back. It holds no privilege
//! of its own, opens no socket, writes no file, and knows exactly one program
//! name and one action word. Everything dangerous lives in the root-owned
//! helper, which takes no path and no rule text from anybody.
//!
//! ## Redaction
//!
//! Nothing the helper prints is forwarded to a widget verbatim. Every reason is
//! mapped onto a closed enum here, and an unrecognised one becomes
//! [`FailureReason::UnreadableOutput`] rather than a string on screen. A UI that
//! renders whatever a subprocess printed is a UI that will eventually render
//! something it should not have.
//!
//! See `packaging/linux/README.md` for the design and `scripts/test-uinput-install.sh`
//! for the proof against real udev and real logind.

#![allow(dead_code)] // Windows builds compile this module without the UI path.

use std::collections::BTreeMap;

/// Root-owned, fixed. The console never builds this path from anything.
pub const HELPER: &str = "/usr/libexec/remotedexter/remotedexter-enable-input";

/// Ordinary administrator authentication. There is no RemoteDexter polkit
/// policy: with none installed, `pkexec` falls back to
/// `org.freedesktop.policykit.exec` and asks every time. A shipped policy
/// saying `allow_active=yes` would make the grant standing and silent, which is
/// the thing this whole block exists to avoid.
pub const AUTH: &str = "pkexec";

/// The device the grant is about. Probed directly for the "already available"
/// case, because the cheapest honest answer to "can we inject?" is to try to
/// open it. Opening creates no device — `uinput` materialises one only after
/// `UI_DEV_CREATE`.
pub const UINPUT: &str = "/dev/uinput";

/// The three words the helper accepts. Anything else is refused by the helper
/// before it looks at the filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Enable,
    Disable,
    Status,
}

impl Action {
    pub fn arg(self) -> &'static str {
        match self {
            Action::Enable => "enable",
            Action::Disable => "disable",
            Action::Status => "status",
        }
    }
}

/// Why the helper refused to touch what is at the rule path.
///
/// Every one of these is a case where overwriting or deleting would destroy
/// something RemoteDexter did not create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsafeReason {
    Symlink,
    Directory,
    NotRegular,
    WrongOwner,
    UnsafeMode,
    ForeignContent,
    NoReference,
}

impl UnsafeReason {
    pub fn label(self) -> &'static str {
        match self {
            UnsafeReason::Symlink => "it is a symbolic link",
            UnsafeReason::Directory => "it is a directory",
            UnsafeReason::NotRegular => "it is not a regular file",
            UnsafeReason::WrongOwner => "it is not owned by root",
            UnsafeReason::UnsafeMode => "its permissions are writable by others",
            UnsafeReason::ForeignContent => "it holds rules RemoteDexter did not write",
            UnsafeReason::NoReference => "the packaged rule is missing, so it cannot be compared",
        }
    }

    fn parse(v: &str) -> Option<Self> {
        Some(match v {
            "symlink" => UnsafeReason::Symlink,
            "directory" => UnsafeReason::Directory,
            "not_regular" => UnsafeReason::NotRegular,
            "wrong_owner" => UnsafeReason::WrongOwner,
            "unsafe_mode" => UnsafeReason::UnsafeMode,
            "foreign_content" => UnsafeReason::ForeignContent,
            "unknown_no_reference" => UnsafeReason::NoReference,
            _ => return None,
        })
    }
}

/// Why an attempt failed. Closed on purpose: an unmapped reason becomes
/// [`FailureReason::UnreadableOutput`] instead of reaching the screen as text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    /// The package data is not installed.
    MissingPackagedRule,
    /// The rule could not be written or renamed into place.
    InstallFailed,
    /// The rule could not be removed.
    RemoveFailed,
    /// The rule changed but udev would not reload or retrigger.
    UdevRefreshFailed,
    /// The helper ran without privilege. A bug in how it was invoked.
    NotRoot,
    /// The helper rejected the arguments. A bug here, not user error.
    BadArguments,
    /// `pkexec` or the helper is not installed.
    HelperMissing,
    /// The helper produced something this parser does not understand.
    UnreadableOutput,
}

impl FailureReason {
    pub fn label(self) -> &'static str {
        match self {
            FailureReason::MissingPackagedRule => {
                "the packaged udev rule is missing — reinstall RemoteDexter"
            }
            FailureReason::InstallFailed => "the rule could not be written to /etc/udev/rules.d",
            FailureReason::RemoveFailed => "the rule could not be removed",
            FailureReason::UdevRefreshFailed => {
                "the rule changed but udev would not reload — log out and back in"
            }
            FailureReason::NotRoot => "the helper did not run with administrator privilege",
            FailureReason::BadArguments => "the helper rejected the request",
            FailureReason::HelperMissing => {
                "the input helper is not installed — install the RemoteDexter package"
            }
            FailureReason::UnreadableOutput => "the input helper gave an unrecognised answer",
        }
    }
}

/// Why the grant does not apply at all on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// Windows injects through `SendInput` and needs no device grant.
    NotLinux,
}

/// Everything the console may say about input access. Each variant is a
/// distinct thing that is true; none of them is "something went wrong".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputGrantState {
    /// Not asked yet.
    Unknown,
    /// An administrator prompt is on screen, or the helper is running.
    Working(Action),
    /// `/dev/uinput` is writable now. Injection will work.
    Available,
    /// The optional rule is not installed and the device is not writable.
    NotEnabled,
    /// The administrator prompt was dismissed or the password was refused.
    Cancelled,
    /// Something RemoteDexter did not write is at the rule path.
    RefusedUnsafe(UnsafeReason),
    /// The rule is installed, but logind has not granted this session access.
    NeedsSessionRefresh,
    /// Enable finished and access is live.
    Enabled,
    /// Disable finished; the grant is gone.
    Disabled,
    /// Disable removed the rule, but this session can still write to the
    /// device. Two ways to land here: the machine has no `setfacl` for the
    /// helper to clear the ACL with, or access comes from somewhere else
    /// entirely — most often an account that is a member of `input`, where no
    /// udev rule RemoteDexter installs or removes can change anything.
    DisabledPendingSignOut,
    /// The attempt failed, with a reason the user can act on.
    Failed(FailureReason),
    /// This platform does not use the grant.
    Unsupported(UnsupportedReason),
}

impl InputGrantState {
    /// One short line: what is true right now.
    pub fn headline(&self) -> &'static str {
        match self {
            InputGrantState::Unknown => "Input access: checking…",
            InputGrantState::Working(Action::Enable) => "Input access: waiting for administrator…",
            InputGrantState::Working(Action::Disable) => "Input access: waiting for administrator…",
            InputGrantState::Working(Action::Status) => "Input access: checking…",
            InputGrantState::Available => "Input access: available",
            InputGrantState::NotEnabled => "Input access: not enabled",
            InputGrantState::Cancelled => "Input access: not enabled — cancelled",
            InputGrantState::RefusedUnsafe(_) => "Input access: refused",
            InputGrantState::NeedsSessionRefresh => "Input access: enabled — sign out to finish",
            InputGrantState::Enabled => "Input access: enabled",
            InputGrantState::Disabled => "Input access: disabled",
            InputGrantState::DisabledPendingSignOut => {
                "Input access: rule removed — still granted until you sign out"
            }
            InputGrantState::Failed(_) => "Input access: failed",
            InputGrantState::Unsupported(_) => "Input access: not needed on this platform",
        }
    }

    /// The sentence under it. Redacted by construction: every branch returns a
    /// fixed string or a fixed string plus a closed enum's own label.
    pub fn detail(&self) -> String {
        match self {
            InputGrantState::Unknown => "Asking the system whether /dev/uinput is writable.".into(),
            InputGrantState::Working(_) => {
                "An administrator prompt is open. RemoteDexter is waiting for it.".into()
            }
            InputGrantState::Available => {
                "RemoteDexter can move the pointer and type on this machine.".into()
            }
            InputGrantState::NotEnabled => {
                "RemoteDexter cannot inject input yet. Enable input installs one udev rule \
                 granting this seat write access to /dev/uinput. It does not join the 'input' \
                 group and does not make keyboards or mice readable."
                    .into()
            }
            InputGrantState::Cancelled => {
                "The administrator prompt was dismissed. Nothing was changed.".into()
            }
            InputGrantState::RefusedUnsafe(r) => format!(
                "There is already a file at /etc/udev/rules.d/70-remotedexter-uinput.rules and \
                 {}. RemoteDexter will not overwrite or delete it. Inspect it yourself, then try \
                 again.",
                r.label()
            ),
            InputGrantState::NeedsSessionRefresh => {
                "The rule is installed, but this login session does not have access yet. Sign out \
                 and back in — or reboot — to finish."
                    .into()
            }
            InputGrantState::Enabled => {
                "The rule is installed and this seat can write to /dev/uinput. Physical keyboards \
                 and mice are still unreadable."
                    .into()
            }
            InputGrantState::Disabled => {
                "The rule is removed. RemoteDexter can no longer inject input.".into()
            }
            InputGrantState::DisabledPendingSignOut => {
                "The rule is removed, but this session can still write to /dev/uinput. Sign out \
                 and back in to be sure. If access persists after that, this account is a member \
                 of the 'input' group and no RemoteDexter setting can change that."
                    .into()
            }
            InputGrantState::Failed(r) => format!("Nothing was changed: {}.", r.label()),
            InputGrantState::Unsupported(UnsupportedReason::NotLinux) => {
                "This platform injects input without a device grant.".into()
            }
        }
    }

    /// Offering Enable when it cannot help is its own small lie.
    pub fn can_enable(&self) -> bool {
        matches!(
            self,
            InputGrantState::NotEnabled
                | InputGrantState::Cancelled
                | InputGrantState::Disabled
                | InputGrantState::DisabledPendingSignOut
                | InputGrantState::Failed(_)
        )
    }

    pub fn can_disable(&self) -> bool {
        matches!(
            self,
            InputGrantState::Available
                | InputGrantState::Enabled
                | InputGrantState::NeedsSessionRefresh
        )
    }

    pub fn is_working(&self) -> bool {
        matches!(self, InputGrantState::Working(_))
    }
}

/// Split `key=value` lines. Later keys win, which matters because the helper
/// prints `rule_state` once per run and `result` last.
fn fields(stdout: &str) -> BTreeMap<&str, &str> {
    let mut map = BTreeMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.trim().split_once('=') {
            map.insert(k.trim(), v.trim());
        }
    }
    map
}

/// Turn one helper run into one state.
///
/// `code` is `None` when the process was killed by a signal — treated as
/// unreadable rather than as any kind of success.
pub fn parse_helper_output(action: Action, code: Option<i32>, stdout: &str) -> InputGrantState {
    // pkexec's own codes, before the helper is even reached. The helper never
    // exits with either, so there is no ambiguity to resolve.
    match code {
        Some(126) => return InputGrantState::Cancelled,
        Some(127) => return InputGrantState::Failed(FailureReason::HelperMissing),
        None => return InputGrantState::Failed(FailureReason::UnreadableOutput),
        _ => {}
    }

    let f = fields(stdout);
    let result = f.get("result").copied().unwrap_or("");
    let reason = f.get("reason").copied().unwrap_or("");
    let rule_state = f.get("rule_state").copied().unwrap_or("");
    let access = f.get("access_now").copied().unwrap_or("");
    let refresh = f.get("session_refresh_required").copied().unwrap_or("");

    match result {
        "refused_unsafe_existing_state" => {
            return match UnsafeReason::parse(reason) {
                Some(r) => InputGrantState::RefusedUnsafe(r),
                None => InputGrantState::Failed(FailureReason::UnreadableOutput),
            }
        }
        "refused_bad_arguments" => return InputGrantState::Failed(FailureReason::BadArguments),
        "refused_not_root" => return InputGrantState::Failed(FailureReason::NotRoot),
        "failed" => {
            return InputGrantState::Failed(match reason {
                "missing_packaged_rule" => FailureReason::MissingPackagedRule,
                "write_failed" | "install_failed" => FailureReason::InstallFailed,
                "remove_failed" => FailureReason::RemoveFailed,
                "udev_refresh_failed" => FailureReason::UdevRefreshFailed,
                _ => FailureReason::UnreadableOutput,
            })
        }
        "ok" => {}
        _ => return InputGrantState::Failed(FailureReason::UnreadableOutput),
    }

    // result=ok. What is actually true now depends on what was asked and on
    // whether logind has caught up — never on the fact that a file was written.
    match action {
        Action::Disable => match (rule_state, access) {
            // Removing the rule is not the same as removing the access. Only
            // the device gets to say which happened.
            ("removed" | "absent", "granted") => InputGrantState::DisabledPendingSignOut,
            ("removed" | "absent", _) => InputGrantState::Disabled,
            _ => InputGrantState::Failed(FailureReason::UnreadableOutput),
        },
        Action::Enable => match (rule_state, access, refresh) {
            ("installed" | "unchanged", "granted", _) => InputGrantState::Enabled,
            ("installed" | "unchanged", _, "yes" | "unknown") => {
                InputGrantState::NeedsSessionRefresh
            }
            _ => InputGrantState::Failed(FailureReason::UnreadableOutput),
        },
        Action::Status => match (rule_state, access) {
            (_, "granted") => InputGrantState::Available,
            ("ours" | "unchanged" | "installed", _) => InputGrantState::NeedsSessionRefresh,
            ("absent", _) => InputGrantState::NotEnabled,
            (other, _) => match UnsafeReason::parse(other) {
                Some(r) => InputGrantState::RefusedUnsafe(r),
                None => InputGrantState::Failed(FailureReason::UnreadableOutput),
            },
        },
    }
}

/// Can this process write `/dev/uinput` right now?
///
/// Deliberately an open, not an ACL inspection: `access(2)`-style reasoning
/// about ACLs, capabilities and group membership gets the answer wrong in
/// exactly the cases that matter. Opening for write creates no device.
#[cfg(target_os = "linux")]
pub fn uinput_is_writable() -> bool {
    std::fs::OpenOptions::new().write(true).open(UINPUT).is_ok()
}

#[cfg(not(target_os = "linux"))]
pub fn uinput_is_writable() -> bool {
    false
}

/// The state to show before anything has been asked of the helper.
#[cfg(target_os = "linux")]
pub fn initial_state() -> InputGrantState {
    if uinput_is_writable() {
        InputGrantState::Available
    } else {
        InputGrantState::NotEnabled
    }
}

#[cfg(not(target_os = "linux"))]
pub fn initial_state() -> InputGrantState {
    InputGrantState::Unsupported(UnsupportedReason::NotLinux)
}

/// Run one helper action, blocking. Callers put this on a thread: the
/// administrator prompt is modal and can sit there for as long as the user
/// takes, and the GUI must keep painting.
#[cfg(target_os = "linux")]
pub fn run_action(action: Action) -> InputGrantState {
    use std::process::Command;

    // The command line is built from constants only. There is no interpolation
    // point here for a caller to reach.
    let out = Command::new(AUTH).arg(HELPER).arg(action.arg()).output();
    match out {
        Ok(o) => {
            let state =
                parse_helper_output(action, o.status.code(), &String::from_utf8_lossy(&o.stdout));
            // Trust the device over the report. If the helper said a refresh is
            // needed but the device is already open to us, say so.
            if matches!(state, InputGrantState::NeedsSessionRefresh) && uinput_is_writable() {
                return InputGrantState::Enabled;
            }
            state
        }
        Err(_) => InputGrantState::Failed(FailureReason::HelperMissing),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run_action(_action: Action) -> InputGrantState {
    InputGrantState::Unsupported(UnsupportedReason::NotLinux)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_LINE: &str = r#"KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess""#;

    fn packaged(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../packaging/linux")
            .join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
    }

    // ── the packaged artefacts ──────────────────────────────────────────

    /// The rule must say exactly one thing. A second directive in this file is
    /// a second grant nobody reviewed.
    #[test]
    fn packaged_rule_is_exactly_one_uaccess_line() {
        let text = packaged("70-remotedexter-uinput.rules");
        let directives: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(
            directives,
            vec![RULE_LINE],
            "the rule file must contain exactly the reviewed rule"
        );
    }

    /// The narrow grant is the entire point. A rule that also set GROUP,
    /// OWNER or MODE, or that matched an event device, would quietly restore
    /// the broad access this block removes.
    #[test]
    fn packaged_rule_grants_nothing_beyond_uinput_uaccess() {
        let text = packaged("70-remotedexter-uinput.rules");
        for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            for forbidden in [
                "GROUP=", "OWNER=", "MODE=", "event", "RUN", "IMPORT", "PROGRAM",
            ] {
                assert!(
                    !line.contains(forbidden),
                    "rule line {line:?} contains {forbidden:?}; the grant must be uaccess on uinput and nothing else"
                );
            }
        }
    }

    /// `postrm purge` cannot call the helper — dpkg has already deleted it —
    /// so it carries its own copy of the expected bytes. If the two drift, the
    /// purge silently stops recognising the file it is supposed to remove.
    #[test]
    fn postrm_expects_the_packaged_rule_byte_for_byte() {
        let rule = packaged("70-remotedexter-uinput.rules");
        let postrm = packaged("debian/postrm");
        let start = postrm
            .find("<<'RDX_RULE_EOF'\n")
            .expect("postrm must carry the expected rule in a quoted heredoc")
            + "<<'RDX_RULE_EOF'\n".len();
        let end = postrm[start..]
            .find("\nRDX_RULE_EOF\n")
            .expect("unterminated heredoc in postrm")
            + start
            + 1;
        assert_eq!(
            &postrm[start..end],
            rule,
            "postrm's expected rule has drifted from the packaged rule"
        );
    }

    /// Installation must grant nothing. This is the property
    /// scripts/test-uinput-install.sh check 1 proves on a real machine; this
    /// test is the cheap version that fails in a second rather than in a VM.
    #[test]
    fn postinst_grants_nothing() {
        let postinst = packaged("debian/postinst");
        let body: String = postinst
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "usermod",
            "gpasswd",
            "adduser",
            "setfacl",
            "udevadm",
            "systemctl",
            "/etc/udev/rules.d",
            "chmod",
            "chown",
        ] {
            assert!(
                !body.contains(forbidden),
                "postinst must not {forbidden:?}: installation grants nothing"
            );
        }
    }

    /// Ordinary removal keeps the user's choice; only purge revokes it.
    #[test]
    fn postrm_revokes_only_on_purge() {
        let postrm = packaged("debian/postrm");
        let case_start = postrm
            .find("case \"$1\" in")
            .expect("postrm dispatches on $1");
        let purge = postrm[case_start..]
            .find("purge)")
            .expect("postrm handles purge");
        let remove = postrm[case_start..]
            .find("remove|upgrade")
            .expect("postrm handles remove");
        assert!(
            purge < remove,
            "purge must be its own branch, ahead of the no-op branch"
        );
        let noop_branch = &postrm[case_start + remove..];
        assert!(
            !noop_branch.contains("purge_optional_rule"),
            "an ordinary remove must not revoke a grant the user turned on"
        );
    }

    // ── the helper's shape ──────────────────────────────────────────────

    fn helper() -> String {
        packaged("remotedexter-enable-input")
    }

    fn helper_code() -> String {
        helper()
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every path the helper touches is a literal. An environment override
    /// would be a caller-supplied destination wearing a different hat.
    #[test]
    fn helper_paths_are_literal_constants() {
        let code = helper_code();
        for name in [
            "DEST=",
            "SRC=",
            "TMP_PREFIX=",
            "RULE_DIR=",
            "UINPUT_DEV=",
            "UINPUT_SYSPATH=",
        ] {
            let line = code
                .lines()
                .find(|l| l.trim_start().starts_with(name))
                .unwrap_or_else(|| panic!("helper must define {name}"));
            let value = line.split_once('=').unwrap().1;
            assert!(
                value.starts_with('\'') && !value.contains('$'),
                "{name} must be a single-quoted literal with no expansion, got {line:?}"
            );
        }
    }

    /// Arguments are checked before privilege, before the filesystem, before
    /// anything. `--path /etc/passwd` must die above all of it.
    #[test]
    fn helper_validates_arguments_before_any_privileged_work() {
        let code = helper_code();
        let gate = code
            .find("refused_bad_arguments")
            .expect("helper must refuse unknown arguments");
        for privileged in [
            "udevadm", "runuser", "mv -f", "rm -f", "chown", "id -u", "loginctl",
        ] {
            let first = code
                .find(privileged)
                .unwrap_or_else(|| panic!("helper should still use {privileged}"));
            assert!(
                gate < first,
                "argument validation must precede {privileged:?}"
            );
        }
    }

    /// The broad grant must not come back through the side door.
    #[test]
    fn helper_never_widens_access() {
        let code = helper_code();
        for forbidden in [
            "usermod",
            "gpasswd",
            "adduser",
            "/dev/input/event",
            "chmod 0666",
            "systemctl",
        ] {
            assert!(
                !code.contains(forbidden),
                "the helper must never {forbidden:?}"
            );
        }
    }

    /// `setfacl` earns its place only by taking access away. Removing the rule
    /// does not remove the ACL uaccess already set, so disable has to clear it
    /// — but the helper must never be able to hand an ACL entry to anyone.
    #[test]
    fn the_helper_uses_setfacl_only_to_remove_access() {
        let code = helper_code();
        let calls: Vec<&str> = code.lines().filter(|l| l.contains("setfacl ")).collect();
        assert!(
            !calls.is_empty(),
            "disable must actually revoke the ACL it caused"
        );
        for line in calls {
            assert!(
                line.contains("setfacl -b") || line.contains("command -v setfacl"),
                "setfacl must only be used to clear entries, never to add one: {line:?}"
            );
            assert!(
                !line.contains("-m ") && !line.contains("--set"),
                "setfacl must never grant: {line:?}"
            );
        }
    }

    /// Same property in the maintainer script, which cannot call the helper.
    #[test]
    fn purge_revokes_the_acl_it_cannot_leave_behind() {
        let postrm = packaged("debian/postrm");
        assert!(
            postrm.contains("setfacl -b /dev/uinput"),
            "purge must clear the uaccess ACL, not just delete the rule"
        );
        assert!(
            !postrm.contains("setfacl -m"),
            "purge must never grant an ACL entry"
        );
        // Ordering, not just presence. `udevadm control --reload-rules` is
        // asynchronous: clearing the ACL before the retrigger loses the race
        // and the old rule set hands the grant straight back. Both the helper
        // and this script had that bug, and both were caught only by a real
        // machine.
        let clear = postrm.find("setfacl -b /dev/uinput").unwrap();
        let reload = postrm.find("udevadm control --reload-rules").unwrap();
        let last_trigger = postrm.rfind("udevadm trigger").unwrap();
        assert!(
            reload < clear,
            "purge must reload rules before clearing the ACL"
        );
        assert!(
            clear < last_trigger,
            "purge must retrigger after clearing, so another rule can re-apply its own grant"
        );
    }

    /// The same ordering, in the helper.
    #[test]
    fn disable_reloads_before_it_clears_and_retriggers_after() {
        let code = helper_code();
        let disable = code
            .find("    disable)")
            .expect("helper has a disable branch");
        let body = &code[disable..];
        let reload = body
            .find("reload_and_trigger")
            .expect("disable must reload");
        let clear = body
            .find("revoke_acl")
            .expect("disable must revoke the ACL");
        let recheck = body
            .find("retrigger '_recheck'")
            .expect("disable must retrigger after clearing");
        assert!(
            reload < clear,
            "clearing the ACL before the reload loses the race and the grant comes back"
        );
        assert!(
            clear < recheck,
            "the re-derive pass must come after the clear"
        );
    }

    /// A trigger with no filter re-runs rules for every device on the machine.
    /// Every trigger the helper issues must name the one device, either
    /// literally or through the sysfs-path constant — which is itself checked
    /// to be a literal ending in `uinput`.
    #[test]
    fn helper_triggers_only_uinput() {
        let code = helper_code();
        let syspath = code
            .lines()
            .find(|l| l.trim_start().starts_with("UINPUT_SYSPATH="))
            .expect("helper must define UINPUT_SYSPATH")
            .split_once('=')
            .unwrap()
            .1
            .trim()
            .trim_matches('\'');
        assert!(
            syspath.ends_with("/uinput"),
            "UINPUT_SYSPATH must name the uinput device, got {syspath:?}"
        );
        let triggers: Vec<&str> = code
            .lines()
            .filter(|l| l.contains("udevadm trigger"))
            .collect();
        assert!(
            !triggers.is_empty(),
            "the helper must retrigger the device it grants"
        );
        for line in triggers {
            assert!(
                line.contains("uinput") || line.contains("UINPUT_SYSPATH"),
                "unscoped udevadm trigger: {line:?}"
            );
        }
    }

    // ── parsing ─────────────────────────────────────────────────────────

    fn ok_enable(rule_state: &str, access: &str, refresh: &str) -> String {
        format!(
            "rd_helper_version=1\naction=enable\nrule_path=/etc/udev/rules.d/70-remotedexter-uinput.rules\n\
             target_uid=1000\ntarget_uid_source=active_seat\nrule_state={rule_state}\n\
             udev_reload=ok\nudev_trigger=ok\nuinput_present=yes\naccess_now={access}\n\
             session_refresh_required={refresh}\nresult=ok\n"
        )
    }

    #[test]
    fn enable_that_took_effect_reads_as_enabled() {
        assert_eq!(
            parse_helper_output(
                Action::Enable,
                Some(0),
                &ok_enable("installed", "granted", "no")
            ),
            InputGrantState::Enabled
        );
    }

    /// The state this design exists to tell the truth about: the file is there,
    /// and the user still cannot inject.
    #[test]
    fn enable_that_logind_has_not_applied_reads_as_needing_a_refresh() {
        assert_eq!(
            parse_helper_output(
                Action::Enable,
                Some(0),
                &ok_enable("installed", "denied", "yes")
            ),
            InputGrantState::NeedsSessionRefresh
        );
    }

    /// Enable twice is one enable. The second run must not report a failure or
    /// invent a second grant.
    #[test]
    fn repeated_enable_is_reported_as_the_same_success() {
        assert_eq!(
            parse_helper_output(
                Action::Enable,
                Some(0),
                &ok_enable("unchanged", "granted", "no")
            ),
            InputGrantState::Enabled
        );
    }

    #[test]
    fn disable_reports_disabled_whether_or_not_a_rule_was_there() {
        for state in ["removed", "absent"] {
            let out = format!("action=disable\nrule_state={state}\naccess_now=denied\nsession_refresh_required=no\nresult=ok\n");
            assert_eq!(
                parse_helper_output(Action::Disable, Some(0), &out),
                InputGrantState::Disabled,
                "rule_state={state}"
            );
        }
    }

    /// Measured in the harness on 2026-08-23: after `disable`, /dev/uinput
    /// still carried `user:baxter:rw-` and the seat user could still open it.
    /// The rule being gone is not the user losing access, and the console must
    /// not claim otherwise — an operator who reads "disabled" and walks away
    /// has been told something false about their own machine.
    #[test]
    fn a_disable_that_did_not_actually_revoke_says_so() {
        let out = "action=disable\nrule_state=removed\nacl_reset=unavailable\naccess_now=granted\nsession_refresh_required=no\nresult=ok\n";
        assert_eq!(
            parse_helper_output(Action::Disable, Some(0), out),
            InputGrantState::DisabledPendingSignOut
        );
    }

    #[test]
    fn every_unsafe_refusal_reaches_the_user_as_itself() {
        let cases = [
            ("symlink", UnsafeReason::Symlink),
            ("directory", UnsafeReason::Directory),
            ("not_regular", UnsafeReason::NotRegular),
            ("wrong_owner", UnsafeReason::WrongOwner),
            ("unsafe_mode", UnsafeReason::UnsafeMode),
            ("foreign_content", UnsafeReason::ForeignContent),
            ("unknown_no_reference", UnsafeReason::NoReference),
        ];
        for (wire, want) in cases {
            let out = format!("action=enable\nrule_state={wire}\nresult=refused_unsafe_existing_state\nreason={wire}\n");
            assert_eq!(
                parse_helper_output(Action::Enable, Some(3), &out),
                InputGrantState::RefusedUnsafe(want),
                "wire reason {wire}"
            );
        }
    }

    /// A dismissed password prompt is not a failure, and must never be shown
    /// as one — the user made a choice and nothing changed.
    #[test]
    fn a_dismissed_administrator_prompt_is_cancelled_not_failed() {
        assert_eq!(
            parse_helper_output(Action::Enable, Some(126), ""),
            InputGrantState::Cancelled
        );
    }

    #[test]
    fn a_missing_helper_is_named_as_a_missing_helper() {
        assert_eq!(
            parse_helper_output(Action::Enable, Some(127), ""),
            InputGrantState::Failed(FailureReason::HelperMissing)
        );
    }

    #[test]
    fn bad_arguments_and_missing_privilege_are_distinct_failures() {
        assert_eq!(
            parse_helper_output(
                Action::Enable,
                Some(2),
                "result=refused_bad_arguments\nreason=unknown_action\n"
            ),
            InputGrantState::Failed(FailureReason::BadArguments)
        );
        assert_eq!(
            parse_helper_output(Action::Enable, Some(5), "result=refused_not_root\n"),
            InputGrantState::Failed(FailureReason::NotRoot)
        );
    }

    #[test]
    fn each_named_failure_reason_survives_the_round_trip() {
        let cases = [
            ("missing_packaged_rule", FailureReason::MissingPackagedRule),
            ("write_failed", FailureReason::InstallFailed),
            ("install_failed", FailureReason::InstallFailed),
            ("remove_failed", FailureReason::RemoveFailed),
            ("udev_refresh_failed", FailureReason::UdevRefreshFailed),
        ];
        for (wire, want) in cases {
            let out = format!("action=enable\nresult=failed\nreason={wire}\n");
            assert_eq!(
                parse_helper_output(Action::Enable, Some(4), &out),
                InputGrantState::Failed(want),
                "wire reason {wire}"
            );
        }
    }

    /// The redaction rule, stated as a test: anything unrecognised becomes a
    /// fixed label, never text from the subprocess.
    #[test]
    fn an_unrecognised_reason_is_redacted_rather_than_forwarded() {
        // A path-shaped secret, deliberately not written as a real home
        // directory: scripts/check_host_paths.py scans source for
        // host-specific absolute paths, and a test fixture that trips it is a
        // fixture arguing with a different gate. The redaction proven here does
        // not care what shape the text is.
        let hostile = "action=enable\nresult=failed\nreason=SECRETS_DIR/id_ed25519 is unreadable\n";
        let state = parse_helper_output(Action::Enable, Some(4), hostile);
        assert_eq!(
            state,
            InputGrantState::Failed(FailureReason::UnreadableOutput)
        );
        assert!(
            !state.detail().contains("id_ed25519"),
            "subprocess text must never reach the screen: {}",
            state.detail()
        );
    }

    #[test]
    fn truncated_or_empty_output_is_never_read_as_success() {
        for out in [
            "",
            "rd_helper_version=1\n",
            "garbage without an equals sign\n",
            "result=\n",
        ] {
            assert!(
                matches!(
                    parse_helper_output(Action::Enable, Some(0), out),
                    InputGrantState::Failed(FailureReason::UnreadableOutput)
                ),
                "accepted {out:?}"
            );
        }
    }

    /// A signal kill leaves no exit code. It must not fall through to a
    /// success path.
    #[test]
    fn a_killed_helper_is_a_failure_not_a_silence() {
        assert_eq!(
            parse_helper_output(
                Action::Enable,
                None,
                "result=ok\nrule_state=installed\naccess_now=granted\n"
            ),
            InputGrantState::Failed(FailureReason::UnreadableOutput)
        );
    }

    #[test]
    fn status_distinguishes_available_from_not_enabled_from_pending() {
        let s = |rule: &str, access: &str| {
            parse_helper_output(
                Action::Status,
                Some(0),
                &format!("action=status\nrule_state={rule}\naccess_now={access}\nsession_refresh_required=no\nresult=ok\n"),
            )
        };
        assert_eq!(s("ours", "granted"), InputGrantState::Available);
        assert_eq!(s("ours", "denied"), InputGrantState::NeedsSessionRefresh);
        assert_eq!(s("absent", "denied"), InputGrantState::NotEnabled);
        // Already writable with no rule of ours: someone else granted it, and
        // saying "not enabled" would be false.
        assert_eq!(s("absent", "granted"), InputGrantState::Available);
        assert_eq!(
            s("symlink", "denied"),
            InputGrantState::RefusedUnsafe(UnsafeReason::Symlink)
        );
    }

    /// The buttons must not offer an action that cannot change anything.
    #[test]
    fn offered_actions_match_what_the_state_can_actually_change() {
        assert!(InputGrantState::NotEnabled.can_enable());
        assert!(InputGrantState::Cancelled.can_enable());
        assert!(InputGrantState::Disabled.can_enable());
        assert!(!InputGrantState::Available.can_enable());
        assert!(!InputGrantState::Enabled.can_enable());
        assert!(!InputGrantState::Working(Action::Enable).can_enable());
        assert!(!InputGrantState::RefusedUnsafe(UnsafeReason::Symlink).can_enable());

        assert!(InputGrantState::Available.can_disable());
        assert!(InputGrantState::Enabled.can_disable());
        assert!(InputGrantState::NeedsSessionRefresh.can_disable());
        assert!(!InputGrantState::NotEnabled.can_disable());
        assert!(!InputGrantState::Working(Action::Disable).can_disable());
    }

    /// Every state must render. A `todo!()` in a match arm here is a panic in
    /// the GUI thread.
    #[test]
    fn every_state_renders_a_headline_and_a_detail() {
        let all = [
            InputGrantState::Unknown,
            InputGrantState::Working(Action::Enable),
            InputGrantState::Working(Action::Disable),
            InputGrantState::Working(Action::Status),
            InputGrantState::Available,
            InputGrantState::NotEnabled,
            InputGrantState::Cancelled,
            InputGrantState::RefusedUnsafe(UnsafeReason::ForeignContent),
            InputGrantState::NeedsSessionRefresh,
            InputGrantState::Enabled,
            InputGrantState::Disabled,
            InputGrantState::DisabledPendingSignOut,
            InputGrantState::Failed(FailureReason::UdevRefreshFailed),
            InputGrantState::Unsupported(UnsupportedReason::NotLinux),
        ];
        for s in all {
            assert!(!s.headline().is_empty(), "{s:?} has no headline");
            assert!(s.detail().len() > 20, "{s:?} has no usable detail");
        }
    }

    /// The advice that started this block. It must never come back.
    #[test]
    fn no_user_facing_text_tells_anyone_to_join_the_input_group() {
        let all = [
            InputGrantState::NotEnabled,
            InputGrantState::NeedsSessionRefresh,
            InputGrantState::Enabled,
            InputGrantState::Failed(FailureReason::MissingPackagedRule),
        ];
        for s in all {
            let text = format!("{} {}", s.headline(), s.detail());
            assert!(
                !text.contains("-aG input") && !text.contains("usermod"),
                "user-facing text tells the user to widen access: {text}"
            );
        }
    }

    #[test]
    fn the_helper_action_words_are_the_three_the_helper_accepts() {
        assert_eq!(Action::Enable.arg(), "enable");
        assert_eq!(Action::Disable.arg(), "disable");
        assert_eq!(Action::Status.arg(), "status");
        let code = helper_code();
        assert!(
            code.contains("enable|disable|status)"),
            "the helper's accepted set must match Action"
        );
    }
}
