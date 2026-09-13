# RemoteDexter Modules

## Logging Status

As of 2026-03-02, debug logging has been gated behind the workspace "debug-logs" feature flag. All println!, eprintln!, and similar debug outputs are now conditional on `#[cfg(feature = "debug-logs")]`. This ensures clean builds and test execution by default, while allowing debug output when explicitly enabled.

### Affected Modules
- multiplexer
- session_manager
- module6
- scp_consumer
- qr_bootstrap
- file_transfer

### Usage
To enable debug logs during development:
```bash
cargo build --features debug-logs
cargo test --features debug-logs
```

Without the feature, builds are clean and tests run without debug output.