#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed the parser; ensure no panics
    let _ = connection_package_generator::deserialize::parse_connection_package(data);
});
