# Module 2 — Connection Package Generator

This module consumes `HandshakeResult` from the QR handshake and produces canonical connection packages to be consumed by signaling and transport modules. It is intentionally isolated from network I/O; it only composes deterministic packages.
