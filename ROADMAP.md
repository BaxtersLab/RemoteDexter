# ROADMAP — declared stubs and deliberate refusals

Article VII.2: a stub must be marked in code, listed here, and never left
undocumented. This file is short on purpose. It is not a backlog — the
architecture plan is the backlog — it is the list of places where the product
*deliberately declines to do something it appears able to do*, so that nobody
mistakes a refusal for a bug or a placeholder for a feature.

## Open

Nothing. Block 4 closed the one entry that was here.

## Closed

- [x] ~~**REFUSAL: `HostCommand::CreateInvite`**~~ — **closed in Block 4.** It is
      now the real `crates/pairing` service: a signed v4 invite with a 256-bit
      one-use token, a 60-second expiry, an in-memory QR, and hash-only
      retention. `modules/module17_bootstrap_invite`,
      `modules/module23_wifi_beacon` and `modules/module22_nfc_writer` are
      deleted, so the UDP token broadcast, the process-wide token event, the
      public routing probe, the external image viewer and the NFC/BLE/RFID
      claims no longer exist to be re-enabled.

- [x] ~~`module25_windows_ui`~~ — **deleted in Block 3.** It printed
      `[Module25] Windows UI placeholder active`, subscribed to a telemetry
      channel, ticked `[UI] Event loop maintenance tick` every five seconds, and
      drew nothing. Replaced by `crates/host_controller` + `host_app/src/ui.rs`.
- [x] ~~`modules/launcher_shim`~~ — **deleted in Block 3.** Its entire job was to
      print "Launching Module 25 UI…", spawn a task that printed
      "Module 25 UI launched (placeholder)", and then `sleep(1)` forever.

Both remain recoverable from git history at `d7f8467`.
