Session Manager (Module 4)
==========================

Purpose
-------
`session_manager` is a lightweight scaffold demonstrating how higher-level
components can consume SCP payloads, verify them using `scp_consumer`, and
operate on the parsed `ScpMessage` values. It intentionally keeps behavior
minimal so it can be adapted to your transport and session lifecycle needs.

Quick start
-----------
- Build the workspace: `cargo build`
- Use `SessionManager::handle_raw_package(raw_bytes)` to parse and verify incoming
  `ConnectionPackage` wire bytes. The function returns a `ScpMessage` on success.
