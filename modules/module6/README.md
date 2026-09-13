# Module6 — Connection Maintenance (scaffold)

Module6 is the connection-maintenance layer sitting above sealed Module5.

Responsibilities (scaffold):
- Liveness monitoring (PING/PONG)
- Rekeying triggers (messages/bytes/time)
- Reconnect orchestration using Module4 + Module5
- Logical session abstraction (`Healthy` / `Degraded` / `Reconnecting` / `Dead`)

Constraints:
- Module5 is sealed and must not be mutated or internally inspected.
- Module6 must not implement crypto, signaling, or transport selection.

This crate contains only skeletons and trait interfaces; implementation
work will follow design approval.
