//! The Android client's wire format, asserted against the host's own serde
//! derives.
//!
//! This closes a seam nothing else in the build covers. The Kotlin client hand-
//! builds `input_event` JSON; the host parses it with
//! `serde_json::from_value::<InputControlMessage>`. Both sides compile fine
//! when they disagree — the failure only ever appears on a device, as "control
//! does nothing", with no error anywhere.
//!
//! The fixture at `contract/android_input_wire_v1.json` is shared with
//! `InputJsonContractTest.kt`. Neither side imports the other.

use module10::message::InputControlMessage;
use serde_json::Value;

fn fixture() -> Value {
    // CARGO_MANIFEST_DIR is modules/module10; the contract lives at the repo root.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contract/android_input_wire_v1.json"
    );
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read the shared contract at {path}: {e}"));
    serde_json::from_str(&text).expect("contract fixture is not valid JSON")
}

/// Every command the Android client builds must deserialize into the exact
/// message the host will act on — and survive a round trip unchanged, which is
/// what catches a renamed or dropped field rather than merely a malformed one.
#[test]
fn every_client_command_parses_and_round_trips() {
    let f = fixture();
    let cases = f["valid"].as_array().expect("valid[] missing");
    assert!(!cases.is_empty(), "fixture has no valid cases — a vacuous pass");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let command = &case["command"];

        assert_eq!(
            command["type"].as_str(),
            Some("input_event"),
            "{name}: every input command must be typed input_event"
        );
        assert!(
            command.get("window").is_some(),
            "{name}: the host requires a window id and denies without one"
        );

        let event = command["event"].clone();
        let msg: InputControlMessage = serde_json::from_value(event.clone())
            .unwrap_or_else(|e| panic!("{name}: host cannot parse what the client sends: {e}"));

        let back = serde_json::to_value(&msg)
            .unwrap_or_else(|e| panic!("{name}: re-serialization failed: {e}"));
        assert_eq!(
            back, event,
            "{name}: round trip changed the message — a field is renamed, dropped or defaulted"
        );
    }
    eprintln!("verified {} client commands against the host's own derives", cases.len());
}

/// The negative control. Without this, the test above would pass just as
/// happily against a parser that accepted anything — including the shapes a
/// client is most likely to drift into.
#[test]
fn shapes_the_client_must_never_send_are_rejected() {
    let f = fixture();
    let cases = f["must_not_parse"].as_array().expect("must_not_parse[] missing");
    assert!(!cases.is_empty(), "no negative controls — the positive test proves nothing");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let why = case["why"].as_str().unwrap_or("");
        let event = case["event"].clone();
        let parsed: Result<InputControlMessage, _> = serde_json::from_value(event);
        assert!(
            parsed.is_err(),
            "{name}: this shape parsed but must not — {why}"
        );
    }
    eprintln!("verified {} shapes are rejected", cases.len());
}

/// The desktop surface id is `i64::MAX`, and it has already caused one real
/// defect: Android's `optLong` is signed, so a `u64::MAX` sentinel round-tripped
/// to -1 and streaming never started. The fixture carries the real value.
#[test]
fn the_desktop_surface_id_survives_as_a_signed_64_bit_value() {
    let f = fixture();
    let case = f["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "move_relative_desktop_surface_id")
        .expect("the desktop-surface-id case is missing from the fixture");

    let window = case["command"]["window"].as_i64().expect("window is not an i64");
    assert_eq!(window, i64::MAX, "the desktop sentinel must be exactly i64::MAX");
}
