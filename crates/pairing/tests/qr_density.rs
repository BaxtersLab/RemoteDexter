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

/// The v6 payload, from its own digest-pinned vector.
fn dual_payload() -> String {
    payload_from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contract/signed_invite_v6.json"
    ))
}

/// The largest QR the REAL service draws for a dual invite over `mints` mints.
///
/// Many mints, not one: the token and signature differ every time, and before
/// `qr::encode` took the smaller of two encodings the size depended on their
/// characters — the same routes gave 101 or 105 modules from one mint to the
/// next. One lucky mint proved nothing.
fn largest_minted_dual_qr(lan: &str, relay: &str, mints: u8) -> usize {
    (0..mints)
        .map(|i| {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[i; 32]);
            let pubkey_hex: String = signing
                .verifying_key()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let mut service = pairing::PairingService::new(signing, pubkey_hex);
            let caps = [
                pairing::CAP_VIEW.to_string(),
                pairing::CAP_CONTROL.to_string(),
            ];
            service
                .create_dual_invite(
                    lan.parse().expect("lan address"),
                    relay.parse().expect("relay address"),
                    // 16 bytes, base64url without padding: the relay's session id size.
                    "AAAAAAAAAAAAAAAAAAAAAA",
                    1_787_000_000,
                    &caps,
                )
                .unwrap_or_else(|e| panic!("minting a dual invite for {lan} / {relay}: {e:?}"))
                .qr
                .size
        })
        .max()
        .expect("at least one mint")
}

/// **v6 carries both routes and costs no more modules than v5**, measured from
/// the encoder on 2026-09-17: 602 bytes against v5's 568, and both are 101
/// modules (version 19; one byte-mode segment of 561-624 bytes fits it at EC
/// level M). The design expected a small density cost; at IPv4 sizes there is
/// none — once `qr::encode` stopped trusting the library's segment optimizer,
/// which had put 23-36% of real dual invites at 105.
///
/// The headroom is only 22 bytes on the fixture, which is why the next test
/// mints the LONGEST IPv4 invite rather than trusting the fixture's short
/// addresses: that is the size a real host's code will actually be.
#[test]
fn the_dual_route_qr_is_no_denser_than_it_is_today() {
    const MODULE_BUDGET: usize = 101;

    let payload = dual_payload();
    let qr = pairing::qr::encode(&payload).expect("encodes");

    assert!(
        qr.size <= MODULE_BUDGET,
        "the dual-route pairing QR grew to {} modules ({} byte payload). At a \
         440px render that is {:.2} px/module against {:.2} today, and the \
         measured failure was at ~2-3 px/module BEFORE optics. If this growth \
         is intended, move the budget deliberately and say what it buys.",
        qr.size,
        payload.len(),
        440.0 / qr.size as f32,
        440.0 / MODULE_BUDGET as f32,
    );
}

/// The longest IPv4 addresses and ports a host can put in a v6 still fit the
/// v5 symbol size — so turning on "Pairing codes carry both routes" never makes
/// the operator's code coarser than the relay code they already scan.
#[test]
fn the_longest_ipv4_dual_route_qr_is_no_bigger_than_the_relay_one() {
    let size = largest_minted_dual_qr("255.255.255.255:65535", "255.255.255.254:65535", 64);
    assert!(
        size <= 101,
        "a v6 invite with the longest IPv4 routes encodes at {size} modules, above \
         v5's 101 — every real host with long addresses would show a coarser code"
    );
}

/// IPv6 is the worst case: two 39-character addresses make a 659-byte payload,
/// one version up. Pinned so the cost is known — 105 modules is 4.19 px/module
/// at 440 px (before the encoder fix most such mints drew 109), still
/// clear of the ~2-3 px/module failure region — and so a field added later
/// cannot quietly push the worst case further.
#[test]
fn the_longest_ipv6_dual_route_qr_stays_within_one_version_of_the_relay_one() {
    let size = largest_minted_dual_qr(
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535",
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
        64,
    );
    assert!(
        size <= 105,
        "a v6 invite with the longest IPv6 routes encodes at {size} modules \
         ({:.2} px/module at 440 px); the pinned worst case is 105",
        440.0 / size as f32
    );
}

/// The dual invite is never the SMALLER code — it carries everything v5 does
/// plus the LAN route. If this ever fails, a fixture is not what it claims.
#[test]
fn the_dual_route_qr_costs_at_least_the_relay_one() {
    let relay = pairing::qr::encode(&relay_payload()).expect("encodes");
    let dual = pairing::qr::encode(&dual_payload()).expect("encodes");
    assert!(
        dual.size >= relay.size,
        "the dual-route invite encoded smaller than the relay one ({} vs {} modules) — check the fixtures",
        dual.size,
        relay.size
    );
}
