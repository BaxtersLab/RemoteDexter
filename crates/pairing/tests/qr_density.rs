//! How big the pairing QR actually is, measured from the encoder.
//!
//! WHY THIS TEST EXISTS
//!
//! The pairing code's density was diagnosed from a PHOTOGRAPH of the host
//! window: 206x208 px, "~69 modules across", therefore ~3 px/module. Both this
//! side and the Windows box repeated that figure, and it was written into a
//! renderer test as the realistic case.
//!
//! It is wrong. A 522-byte payload cannot fit in a 69-module symbol at error
//! correction M -- the capacity is not there, and anyone could have checked
//! that arithmetic before quoting the number. The encoder actually produces
//! **97 modules including the 4-wide quiet zone** (89 data modules, version
//! 18). So the real figure at the old fixed 220 px render was **2.27
//! px/module**, materially worse than the 3.19 that was being quoted, and the
//! renderer's own test was calibrated against a number that could not occur.
//!
//! Counting modules in a photo of a scaled, filtered image is not a
//! measurement. The encoder knows the answer exactly. This test asks it.
//!
//! It is a RATCHET, not a description: the assertion is an upper bound, so any
//! payload change that inflates the symbol fails here and names the cost in
//! px/module rather than being discovered by a camera that stops pairing.

/// The realistic invite payload, taken from the digest-pinned cross-language
/// contract vector rather than invented here, so this measures what actually
/// ships.
fn realistic_payload() -> String {
    payload_from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contract/signed_invite_v4.json"
    ))
}

/// The v5 payload, from its own digest-pinned vector.
fn relay_payload() -> String {
    payload_from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contract/signed_invite_v5.json"
    ))
}

fn payload_from(path: &str) -> String {
    let raw = std::fs::read_to_string(path).expect("contract fixture");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    let mut inv = v["rust_generated"].clone();
    let o = inv.as_object_mut().expect("object");
    // `_seed_note` and `canonical_utf8` are fixture bookkeeping, not wire fields.
    o.retain(|k, _| !k.starts_with('_') && k != "canonical_utf8");
    serde_json::to_string(&inv).expect("serializable")
}

#[test]
fn the_pairing_qr_is_no_denser_than_it_is_today() {
    // Current: 522 bytes -> 97 modules with the quiet zone (version 18).
    const MODULE_BUDGET: usize = 97;

    let payload = realistic_payload();
    let qr = pairing::qr::encode(&payload).expect("encodes");

    assert!(
        qr.size <= MODULE_BUDGET,
        "the pairing QR grew to {} modules ({} byte payload). Every extra module \
         costs the camera: at a 440px render that is {:.2} px/module against \
         {:.2} today, and the measured failure was at ~2-3 px/module BEFORE \
         optics. If this growth is intended, move the budget deliberately and \
         say what it buys.",
        qr.size,
        payload.len(),
        440.0 / qr.size as f32,
        440.0 / MODULE_BUDGET as f32,
    );
}

#[test]
fn the_module_count_is_taken_from_the_encoder_and_not_from_a_photograph() {
    // The specific defect this pins: "~69 modules" was quoted for two rounds
    // and is arithmetically impossible for this payload at EC level M. A
    // 69-module symbol is version 13; its capacity cannot hold 522 bytes.
    let qr = pairing::qr::encode(&realistic_payload()).expect("encodes");
    let width = qr.size - 8; // the 4-module quiet zone, both sides
    let version = (width as i32 - 17) / 4;

    assert_eq!((width - 17) % 4, 0, "a QR width is always 17 + 4 x version");
    assert!(
        version >= 14,
        "measured version {version} ({width} data modules). The figure quoted \
         from a photograph was ~13, which cannot encode this payload at EC M — \
         if the real version has dropped below 14 the payload shrank and this \
         test should be re-baselined on purpose."
    );
}

/// The v5 QR is BIGGER, and this is the measurement rather than a guess.
///
/// v5 replaces `addr`/`port` with `relay_addr`/`relay_port`/`session`, so the
/// payload grows: **522 bytes and 97 modules for v4, 568 bytes and 101 modules
/// for v5**, measured from the encoder on 2026-09-12. At a 440 px render that
/// is 4.36 px/module against v4's 4.54 — about 4% coarser.
///
/// That still clears the measured failure region of ~2-3 px/module before
/// optics, so it is a cost worth knowing rather than a problem. It is recorded
/// as a RATCHET for the same reason the v4 budget is: the next field somebody
/// adds to a relay invite should have to justify the modules it costs, instead
/// of being found by a camera that stops pairing.
#[test]
fn the_relay_qr_is_no_denser_than_it_is_today() {
    const MODULE_BUDGET: usize = 101;

    let payload = relay_payload();
    let qr = pairing::qr::encode(&payload).expect("encodes");

    assert!(
        qr.size <= MODULE_BUDGET,
        "the relay pairing QR grew to {} modules ({} byte payload). At a 440px \
         render that is {:.2} px/module against {:.2} today, and the measured \
         failure was at ~2-3 px/module BEFORE optics. If this growth is \
         intended, move the budget deliberately and say what it buys.",
        qr.size,
        payload.len(),
        440.0 / qr.size as f32,
        440.0 / MODULE_BUDGET as f32,
    );
}

/// The relay invite really is the larger of the two. If this ever stops being
/// true, one of the fixtures is not what it claims to be.
#[test]
fn the_relay_qr_costs_more_than_the_direct_one() {
    let direct = pairing::qr::encode(&realistic_payload()).expect("encodes");
    let relay = pairing::qr::encode(&relay_payload()).expect("encodes");
    assert!(
        relay.size >= direct.size,
        "the relay invite encoded smaller than the direct one ({} vs {} modules) — check the fixtures",
        relay.size,
        direct.size
    );
}
