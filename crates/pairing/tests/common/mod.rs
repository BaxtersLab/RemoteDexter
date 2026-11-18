//! The QR module-grid cases, shared by `tests/qr_vectors.rs` and
//! `examples/generate_qr_vector.rs` so the fixture and its check cannot
//! disagree about what the cases are.

/// The v6 contract invite exactly as it would be put in a QR.
fn v6_contract_payload() -> String {
    let raw = include_str!("../../../../contract/signed_invite_v6.json");
    let v: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    let mut inv = v["rust_generated"].clone();
    inv.as_object_mut()
        .expect("object")
        .retain(|k, _| !k.starts_with('_') && k != "canonical_utf8");
    serde_json::to_string(&inv).expect("serializable")
}

/// `(name, encoding path encode() must take, text)`.
///
/// * `digit runs` — the library's mixed-mode optimizer puts this at 113
///   modules; one byte-mode segment needs 97. `encode` must take byte mode.
/// * `hex heavy` — here mixed mode genuinely wins (97 against byte mode's 101),
///   and `encode` must keep it.
/// * `v6 contract invite` — a tie at 101; `encode` keeps the mixed encoding.
pub fn cases() -> Vec<(&'static str, &'static str, String)> {
    vec![
        (
            "digit runs",
            "byte",
            "ab1234".repeat(110)[..560].to_string(),
        ),
        (
            "hex heavy",
            "mixed",
            "0123456789abcdef".repeat(40)[..600].to_string(),
        ),
        ("v6 contract invite", "mixed", v6_contract_payload()),
    ]
}

/// The symbol `pairing::qr::encode` draws, WITHOUT the 4-module quiet zone,
/// one string per row, '1' = dark.
pub fn symbol_rows(text: &str) -> Vec<String> {
    const QUIET: usize = 4;
    let qr = pairing::qr::encode(text).expect("encodes");
    let n = qr.size - 2 * QUIET;
    (0..n)
        .map(|y| {
            (0..n)
                .map(|x| {
                    if qr.is_dark(x + QUIET, y + QUIET) {
                        '1'
                    } else {
                        '0'
                    }
                })
                .collect()
        })
        .collect()
}
