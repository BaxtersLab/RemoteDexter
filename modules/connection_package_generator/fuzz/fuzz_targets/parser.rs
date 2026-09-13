#![no_main]
use libfuzzer_sys::fuzz_target;

use connection_package_generator::deserialize::parse_connection_package;

fuzz_target!(|data: &[u8]| {
    // Feed raw bytes to the parser; we only assert it doesn't unwind.
    let _ = parse_connection_package(data);
});
