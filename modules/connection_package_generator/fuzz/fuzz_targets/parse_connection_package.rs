#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The target is the Module 2 parser; ensure it never panics.
    let _ = connection_package_generator::parse_connection_package(data);
});
