use module10::message::{InputControlMessage, MouseMoveMode};
use serde_json::Value;
use session_core::SurfaceGeometry;

const NORMALIZED_MAX: u32 = 65535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputCoordinates {
    DesktopPixels,
    NormalizedV1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn absolute(x: u32, y: u32) -> InputControlMessage {
        InputControlMessage::MouseMove {
            mode: MouseMoveMode::Absolute,
            dx: 0,
            dy: 0,
            abs_x: x,
            abs_y: y,
        }
    }

    fn axes(message: InputControlMessage) -> (u32, u32) {
        match message {
            InputControlMessage::MouseMove { abs_x, abs_y, .. } => (abs_x, abs_y),
            other => panic!("expected pointer move, got {other:?}"),
        }
    }

    #[test]
    fn normalized_wire_contract_matches_the_phone() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../contract/android_pointer_normalized_v1.json"
        ))
        .unwrap();
        let coordinates =
            InputCoordinates::from_field(&fixture["stream_start"], "input_coordinates").unwrap();
        assert_eq!(coordinates, InputCoordinates::NormalizedV1);
        assert_eq!(
            serde_json::from_str::<Value>(&coordinates.stream_ack()).unwrap(),
            fixture["stream_ack"]
        );
        let bounds: [i32; 4] = serde_json::from_value(fixture["geometry"].clone()).unwrap();
        let geometry = Some(SurfaceGeometry::new(
            bounds[0], bounds[1], bounds[2], bounds[3],
        ));
        for case in fixture["moves"].as_array().unwrap() {
            let mode = InputCoordinates::from_field(&case["command"], "coordinate_space").unwrap();
            let mut message = serde_json::from_value(case["command"]["event"].clone()).unwrap();
            mode.convert(&mut message, geometry).unwrap();
            let expected: (u32, u32) = serde_json::from_value(case["native"].clone()).unwrap();
            assert_eq!(axes(message), expected);
        }
    }

    #[test]
    fn legacy_clients_keep_native_video_at_every_ladder_rung() {
        let coordinates = InputCoordinates::from_field(&json!({}), "input_coordinates").unwrap();
        assert_eq!(coordinates, InputCoordinates::DesktopPixels);
        assert_eq!(
            serde_json::from_str::<Value>(&coordinates.stream_ack()).unwrap(),
            json!({"type": "ack", "for": "stream_start"})
        );
        for rung in crate::stream_ladder::RUNGS {
            assert_eq!(coordinates.scale_pct(rung.scale_pct), 100);
        }
        let mut message = absolute(1439, 809);
        coordinates.convert(&mut message, None).unwrap();
        assert_eq!(axes(message), (1439, 809));
    }

    /// RD-RES-1 (3.1.0.2). The updated phone app speaks normalized coordinates,
    /// and that is what let 3.1.0's reduced-resolution rungs reach it: over the
    /// relay the operator's picture sank to the 33% floor within seconds and
    /// stayed there until a reconnect. Every phone now gets full-size frames at
    /// every rung — what the phone had before it was updated.
    #[test]
    fn every_phone_gets_full_size_frames_at_every_rung() {
        for rung in crate::stream_ladder::RUNGS {
            for coordinates in [
                InputCoordinates::DesktopPixels,
                InputCoordinates::NormalizedV1,
            ] {
                assert_eq!(
                    coordinates.scale_pct(rung.scale_pct),
                    100,
                    "{coordinates:?} at a {}% rung would be sent shrunk",
                    rung.scale_pct
                );
            }
        }
    }

    #[test]
    fn absent_modes_are_legacy_but_unknown_or_malformed_modes_are_not() {
        for field in ["input_coordinates", "coordinate_space"] {
            assert_eq!(
                InputCoordinates::from_field(&json!({}), field).unwrap(),
                InputCoordinates::DesktopPixels
            );
            for value in [
                Value::Null,
                json!(true),
                json!(1),
                json!([]),
                json!({}),
                json!("unknown"),
            ] {
                let command = json!({field: value});
                assert!(
                    InputCoordinates::from_field(&command, field).is_err(),
                    "{command}"
                );
            }
        }
    }

    #[test]
    fn normalized_input_needs_valid_geometry_and_bounded_axes() {
        let mode = InputCoordinates::NormalizedV1;
        for geometry in [
            None,
            Some(SurfaceGeometry::new(0, 0, 0, 1080)),
            Some(SurfaceGeometry::new(0, 100, 1920, 0)),
        ] {
            assert!(mode.convert(&mut absolute(32768, 32768), geometry).is_err());
        }
        for (x, y) in [(65536, 0), (0, 65536), (u32::MAX, u32::MAX)] {
            assert!(mode
                .convert(
                    &mut absolute(x, y),
                    Some(SurfaceGeometry::new(0, 0, 1920, 1080))
                )
                .is_err());
        }
    }

    #[test]
    fn normalization_uses_current_native_geometry_not_a_video_rung() {
        for (width, height) in [(1920, 1080), (3840, 2160), (1080, 1920)] {
            let mut message = absolute(65535, 65535);
            InputCoordinates::NormalizedV1
                .convert(
                    &mut message,
                    Some(SurfaceGeometry::new(0, 0, width, height)),
                )
                .unwrap();
            assert_eq!(axes(message), ((width - 1) as u32, (height - 1) as u32));
        }
    }

    #[test]
    fn signed_geometry_never_wraps_and_wide_geometry_never_overflows() {
        let mode = InputCoordinates::NormalizedV1;
        assert!(mode
            .convert(
                &mut absolute(0, 0),
                Some(SurfaceGeometry::new(-100, 0, 100, 1080))
            )
            .is_err());
        let mut message = absolute(65535, 65535);
        mode.convert(
            &mut message,
            Some(SurfaceGeometry::new(0, 0, i32::MAX, i32::MAX)),
        )
        .unwrap();
        assert_eq!(axes(message), (i32::MAX as u32 - 1, i32::MAX as u32 - 1));
        mode.convert(
            &mut absolute(65535, 65535),
            Some(SurfaceGeometry::new(i32::MIN, 0, i32::MAX, 1)),
        )
        .unwrap();
    }

    #[test]
    fn normalized_markers_on_relative_or_button_events_are_refused() {
        for event in [
            json!({"MouseMove": {"mode": "Relative", "dx": 1, "dy": 1, "abs_x": 0, "abs_y": 0}}),
            json!({"MouseButton": {"button": 0, "action": "Down"}}),
        ] {
            let mut message = serde_json::from_value(event).unwrap();
            assert!(InputCoordinates::NormalizedV1
                .convert(&mut message, Some(SurfaceGeometry::new(0, 0, 1920, 1080)))
                .is_err());
        }
    }
}

impl InputCoordinates {
    pub(crate) fn from_field(command: &Value, field: &str) -> Result<Self, &'static str> {
        match command.get(field) {
            None => Ok(Self::DesktopPixels),
            Some(Value::String(value)) if value == "normalized_v1" => Ok(Self::NormalizedV1),
            Some(_) => Err("unsupported input coordinate space"),
        }
    }

    pub(crate) fn stream_ack(self) -> String {
        let mut ack = serde_json::json!({"type": "ack", "for": "stream_start"});
        if self == Self::NormalizedV1 {
            ack["input_coordinates"] = Value::String("normalized_v1".into());
        }
        ack.to_string()
    }

    /// The size, in percent, to send a frame at for a client in this space.
    ///
    /// Older clients map touches in desktop pixels, so they always get native
    /// size. Normalized clients could take a smaller frame, but the reduced
    /// rungs are switched off (`stream_ladder::REDUCED_RESOLUTION`, RD-RES-1),
    /// so today every client gets full size.
    pub(crate) fn scale_pct(self, requested: u16) -> u16 {
        match self {
            Self::NormalizedV1 if crate::stream_ladder::REDUCED_RESOLUTION => requested,
            Self::DesktopPixels | Self::NormalizedV1 => 100,
        }
    }

    pub(crate) fn convert(
        self,
        message: &mut InputControlMessage,
        geometry: Option<SurfaceGeometry>,
    ) -> Result<(), &'static str> {
        if self == Self::DesktopPixels {
            return Ok(());
        }
        let InputControlMessage::MouseMove {
            mode: MouseMoveMode::Absolute,
            abs_x,
            abs_y,
            ..
        } = message
        else {
            return Err("coordinate space is only valid for absolute pointer moves");
        };
        if *abs_x > NORMALIZED_MAX || *abs_y > NORMALIZED_MAX {
            return Err("normalized pointer coordinates out of range");
        }
        let rect = geometry.ok_or("normalized pointer requires surface geometry")?;
        if rect.right <= rect.left || rect.bottom <= rect.top {
            return Err("normalized pointer requires nonempty surface geometry");
        }
        let axis = |value: u32, start: i32, end: i32| {
            let span = i64::from(end) - i64::from(start) - 1;
            let pixel = i64::from(start)
                + (i64::from(value) * span + i64::from(NORMALIZED_MAX / 2))
                    / i64::from(NORMALIZED_MAX);
            u32::try_from(pixel).map_err(|_| "surface coordinate cannot be represented")
        };
        let x = axis(*abs_x, rect.left, rect.right)?;
        let y = axis(*abs_y, rect.top, rect.bottom)?;
        *abs_x = x;
        *abs_y = y;
        Ok(())
    }
}
