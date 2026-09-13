/// Module 9 — Super‑Block 2: File Transfer Messages & Negotiation (Documentation Only)
///
/// Purpose
///
/// - Describe the high-level message roles and negotiation semantics used by
///   the File Transfer Stream: how peers propose, agree, and coordinate
///   transfers without prescribing wire encodings.
///
/// Responsibilities
///
/// - Enumerate the conceptual message types and the order in which they are
///   expected to occur during normal and exceptional flows.
/// - Clarify negotiation semantics (offer/accept/reject), resumability hints,
///   and the responsibilities of sender and receiver at each stage.
/// - Identify which side is authoritative for offsets, checksums, and resume
///   tokens during a resumed transfer.
///
/// Non‑responsibilities
///
/// - This document does not specify binary frame layouts, low-level framing
///   rules, transport-level retransmission, or congestion control behavior.
/// - It does not mandate concrete data structures or APIs; implementers may
///   map conceptual messages to crate-specific types and functions.
///
/// High‑level message model (names only)
///
/// - `Offer` — sender proposes a transfer with metadata (filename, size,
///   optional checksum, resumable flag, resume token).
/// - `Accept` — receiver confirms willingness to receive, optionally indicating
///   accepted resume offset or desired chunk size.
/// - `Reject` — receiver declines the offer with an optional reason code.
/// - `Chunk` — carries file payload bytes and associated sequencing/offset info.
/// - `Complete` — sender indicates end-of-file and (optionally) provides
///   a final integrity marker (checksum/manifest).
/// - `ResumeRequest` — receiver or sender proposes resuming from a known offset
///   or using a resume token to reconcile state.
/// - `Abort` — either side cancels the transfer and requests resource cleanup.
/// - `Status` — out-of-band or in-band informational events (progress, rate,
///   partial checksums) used for UX and diagnostics.
///
/// Negotiation & coordination notes
///
/// - Offers may be conditional: an `Offer` can include suggested chunk sizing
///   and preferred concurrency (single stream vs parallel chunking).
/// - `Accept` may include constraints (max concurrent chunks, start offset).
/// - Resumability requires both sides to agree on a resume token or offset and
///   to validate partial integrity before continuing.
///
/// Failure & abort semantics
///
/// - `Abort` indicates an intentional cancellation; it does not imply data
///   integrity for previously-received chunks unless followed by `Complete`.
/// - On transient errors, peers should prefer `ResumeRequest` flows rather than
///   unconditional `Abort` to enable efficient recovery.
///
/// Lifecycle (negotiation-focused)
///
/// - `Offer` → (`Accept` | `Reject`)
/// - on `Accept`: begin `Chunk` transfer → `Complete`
/// - interruption: `ResumeRequest` → negotiate offset/token → resume `Chunk`s → `Complete`
/// - immediate stop: `Abort`
///
/// Notes
///
/// - This file is documentation-only for Super‑Block 2. Implementation details
///   (types, encodings, APIs) will be specified in later blocks and modules.
