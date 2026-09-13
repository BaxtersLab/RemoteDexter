/// Module 9 — Super‑Block 1: File Transfer Stream (Documentation Only)
///
/// Purpose of the File Transfer Stream
///
/// - Provide a reliable, ordered, application-level stream abstraction for
///   transferring file contents (or file-like byte sequences) between peers.
///
/// Responsibilities
///
/// - Define the high-level lifecycle and message roles for negotiating and
///   transporting file data.
/// - Describe the expected sequence of interactions (offer, accept, chunking,
///   completion, resume, abort) without prescribing wire-format details.
/// - Clarify error and completion semantics at a conceptual level.
///
/// Non-responsibilities
///
/// - This module does not define wire encodings, framing bytes, or transport
///   layer reliability mechanisms; those are out-of-scope for the conceptual
///   specification here.
/// - It does not implement any buffering, concurrency primitives, or actual
///   I/O — those belong in implementation-specific modules.
///
/// High-level message model (names only)
///
/// - `Offer` — propose a file (or resource) to send, with metadata (name, size,
///   optionally checksum and resume token).
/// - `Accept` — accept an offered file, enabling chunk transfer.
/// - `Reject` — decline an offer with an optional reason.
/// - `Chunk` — carry a contiguous segment of file bytes (with an offset index
///   or implicit sequencing).
/// - `Complete` — indicate successful end-of-file and integrity confirmation.
/// - `ResumeOffer` — request resumption from a specific offset (or with token).
/// - `Abort` — cancel an in-progress transfer and release associated resources.
///
/// File transfer lifecycle (conceptual sequence)
///
/// - `offer` → `accept` or `reject`
/// - if `accept`: `chunks` → `complete`
/// - if interrupted and resumable: `resume` → `chunks` → `complete`
/// - at any time: `abort`
///
/// Notes
///
/// - This file intentionally contains only conceptual documentation for
///   Module 9 Super‑Block 1. Implementation details (data structures, wire
///   formats, error codes) belong in separate modules and are not included
///   here.
