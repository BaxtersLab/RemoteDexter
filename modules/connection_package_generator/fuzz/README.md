cargo-fuzz scaffolding for `connection_package_generator`.

How to run locally (recommended on Linux/macOS):

1. Install system deps (Linux example):

   sudo apt-get update && sudo apt-get install -y clang llvm-dev libclang-dev build-essential

2. Install `cargo-fuzz`:

   cargo install cargo-fuzz

3. Run a short fuzz session (coverage-guided, keeps corpus/artifacts under `fuzz/`):

   cd modules/connection_package_generator
   cargo fuzz run parse_connection_package -- -runs=100

Notes:
- The `fuzz/` directory contains the fuzz target and an initial seed corpus.
- For CI, we run a short campaign to catch obvious regressions; for local hardening run longer (hours/days).
