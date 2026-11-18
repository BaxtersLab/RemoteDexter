//! Cross-language QR vectors: the host draws, the phone's decoder reads.
//!
//! `pairing::qr::encode` does not always use the library's own encoding — it
//! takes a single byte-mode segment when that is smaller. A code built that way
//! is only worth anything if the phone can scan it, and the phone scans with
//! ZXing, not with anything in this crate. So `contract/qr_modules_v1.json`
//! carries the exact module grids `encode` draws; this file proves the fixture
//! is exactly that, and `QrModulesTest.kt` decodes every grid with ZXing.

mod common;

use common::{cases, symbol_rows};

const FIXTURE: &str = include_str!("../../../contract/qr_modules_v1.json");
const REGENERATE: &str = "regenerate with: cargo run -q -p pairing --example \
                          generate_qr_vector > contract/qr_modules_v1.json";

fn fixture_cases() -> Vec<serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("contract/qr_modules_v1.json is valid JSON");
    v["cases"].as_array().expect("cases array").clone()
}

fn rows_of(v: &serde_json::Value) -> Vec<String> {
    v["rows"]
        .as_array()
        .expect("rows array")
        .iter()
        .map(|r| r.as_str().expect("row string").to_string())
        .collect()
}

/// The library's own mixed-mode symbol, same shape as `symbol_rows`.
fn library_rows(text: &str) -> Vec<String> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M)
        .expect("library encodes");
    let n = code.width();
    let colors = code.to_colors();
    (0..n)
        .map(|y| {
            (0..n)
                .map(|x| {
                    if colors[y * n + x] == qrcode::Color::Dark {
                        '1'
                    } else {
                        '0'
                    }
                })
                .collect()
        })
        .collect()
}

#[test]
fn the_fixture_is_exactly_what_the_encoder_draws() {
    let fixture = fixture_cases();
    let expected = cases();
    assert_eq!(
        fixture.len(),
        expected.len(),
        "case count differs; {REGENERATE}"
    );
    for ((name, path, text), got) in expected.iter().zip(&fixture) {
        assert_eq!(
            got["name"].as_str(),
            Some(*name),
            "case order; {REGENERATE}"
        );
        assert_eq!(
            got["path"].as_str(),
            Some(*path),
            "{name}: path; {REGENERATE}"
        );
        assert_eq!(
            got["text"].as_str(),
            Some(text.as_str()),
            "{name}: text; {REGENERATE}"
        );
        let rows = rows_of(got);
        assert_eq!(
            got["symbol_size"].as_u64(),
            Some(rows.len() as u64),
            "{name}: symbol_size disagrees with its own rows"
        );
        assert!(
            rows == symbol_rows(text),
            "{name}: the fixture is not what pairing::qr::encode draws today; {REGENERATE}"
        );
    }
}

/// The fixture must exercise BOTH encodings, or the Android decode proves
/// nothing about one of them.
#[test]
fn each_case_takes_the_encoding_path_it_claims() {
    for (name, path, text) in cases() {
        let ours = symbol_rows(&text);
        let library = library_rows(&text);
        match path {
            "byte" => assert!(
                ours.len() < library.len(),
                "{name}: expected encode() to beat the library's {} modules with byte \
                 mode, got {} — the case no longer exercises the byte-mode path",
                library.len(),
                ours.len()
            ),
            "mixed" => assert!(
                ours == library,
                "{name}: expected encode() to keep the library's own encoding"
            ),
            other => panic!("{name}: unknown path {other:?}"),
        }
    }
}
