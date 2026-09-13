Metadata format (Module scp_consumer) — v1
=====================================

Module 3 provides the canonicalization and signature layer used by higher-level components (e.g., SCP metadata and session descriptors), ensuring integrity and authenticity across the system.

Overview
--------
This document defines the canonical, versioned metadata format used by `scp_consumer` for
signing and verifying `ConnectionPackage` payloads.

Motivation
----------
The `ConnectionPackage::metadata` field is opaque to lower-level framing but must carry
authentication material. Making the format explicit and versioned ensures parsers and
verifiers remain compatible and can evolve safely.

Format: metadata v1
-------------------
Layout (bytes, in order):

- `version` (1 byte) = `0x01`
- `claims` (variable length) — opaque claim bytes consumed by the application-level trust logic
- `public_key` (32 bytes) — Ed25519 public key in raw compressed form
- `signature` (64 bytes) — Ed25519 signature of the canonical serialization (see below)

In TL;DR form: `[u8 version || claims... || pk(32) || sig(64)]`.

Signing / Verification Canonicalization
--------------------------------------
- When creating the signature, the signer computes the canonical serialization of the
  `ConnectionPackage` as implemented by `connection_package_generator::serialize_without_signature` *with the `metadata` field set to the `claims` bytes only* (i.e. metadata without the trailing pk+sig).
- The signer then signs those bytes using Ed25519 and appends `pk || sig` to the original `claims` to form the full metadata v1 blob.
- The verifier parses metadata v1, extracts `claims`, `pk`, and `sig`, rebuilds the canonical bytes with `metadata = claims`, and verifies the signature with the extracted public key.

API helpers
-----------
- `scp_consumer::build_metadata_v1(claims, pk, sig)` -- construct a v1 metadata value.
- `scp_consumer::parse_metadata(bytes)` -- parse a v1 blob into `(claims, &pk, &sig)` (returns an error for unknown version or malformed length).

### Claims Region (v1)

In metadata v1, the *claims* section is an opaque byte slice supplied by the producer.
Module 3 treats this region as canonical input: it is included in the bytes that are
signed and later verified by the consumer. The public‑key + signature trailer is
excluded from canonicalization. Future metadata versions may structure claims
(e.g., TLV or length‑prefixed fields), but v1 intentionally leaves them
application‑defined.

This gives readers the conceptual contract without locking the project into a
particular schema.

Security notes
--------------
- The verifier must only accept the exact shape defined above; any malformed length, missing bytes, or incorrect version must fail fast.
- Keep the `claims` semantics application-defined. The verifier only guarantees cryptographic authenticity — not claim structure or semantic validity.
- For forward compatibility, consumers should prefer the version byte and treat unknown versions as unsupported rather than guessing structure.

Versioning and evolution
------------------------
- This is `v1` (value `1`). Future versions should start with a different version byte and include explicit length or TLV fields to avoid ambiguity.
- When migrating, implement parsers for both v1 and the new version and prefer the latest stable format for new messages.

### Versioning Notes

Metadata v1 is intentionally minimal: it defines only the canonicalization rules
and the public‑key + signature trailer. Future versions may introduce structured
claims or additional fields, but v1 keeps the surface area small and stable.
This minimalism is a deliberate design choice to reduce interoperability surface
area for early implementations.

See [tests](modules/scp_consumer/tests) for additional examples of signing,
verification, and negative‑path cases.

Example (high level)
---------------------
- Signer: compute `payload = serialize_without_signature(pkg_with_metadata_set_to_claims)` → `sig = ed25519_sign(sk, payload)` → `metadata = build_metadata_v1(claims, pk, sig)` → write `metadata` into `ConnectionPackage` and transmit.
- Verifier: parse package → `parsed = parse_metadata(package.metadata)` → rebuild payload with `claims` → `verify_ed25519(parsed.pk, payload, parsed.sig)`.

### How the sign/verify flow works

1. Canonicalize the SCP fields into a stable byte sequence.
2. Sign that sequence with the producer's private key.
3. Attach the public key + signature as the metadata trailer.
4. On the consumer side, canonicalize again and verify the signature.

See tests in `modules/scp_consumer/tests` (ed25519 roundtrip and negative tests) for concrete examples.

Example: `sign_verify` (small runnable example)
---------------------------------------------
There is a simple example that demonstrates an end-to-end sign and verify flow using
metadata v1. It builds a deterministic ed25519 keypair, signs the canonicalized
`ConnectionPackage` where `metadata == claims`, constructs a v1 metadata blob,
attaches it to the package, and then parses and verifies the package using
`scp_consumer::Ed25519MetadataVerifier`.

Run the example (from the workspace root):

```powershell
cd C:\RemoteDexter
cargo run -p scp_consumer --example sign_verify
```

Expected outcome: the program prints a verified `ScpMessage` and exits with code 0.

File: [modules/scp_consumer/examples/sign_verify.rs](modules/scp_consumer/examples/sign_verify.rs)

### Example Output

Running the `sign_verify` example prints a verified SCP structure, for example:

Verified SCP:
  version: 1
  ports: [443]
  metadata claims: ["example:scp:claims"]
  signature: valid

(Exact formatting may vary; this snippet is illustrative.)

Note: The example uses a deterministic, hard‑coded keypair purely for demonstration; real integrations should generate and manage keys securely.

### Security Notes

The `sign_verify` example is demonstration‑only: it uses a deterministic,
hard‑coded keypair and does not perform any key management. Real integrations
should generate keys securely, store them appropriately for the platform, and
treat private keys as sensitive material. The example focuses solely on the
canonicalization and signature flow.
