use rand::{rngs::StdRng, RngCore, SeedableRng};

fn main() {
    // lightweight, deterministic harness for random-input stress testing
    let mut rng = StdRng::from_entropy();
    for i in 0..1000u32 {
        let len = (rng.next_u32() % 8192) as usize;
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        // call parser; ensure it doesn't panic
        let _ = connection_package_generator::deserialize::parse_connection_package(&data);
        if i % 100 == 0 {
            eprintln!("fuzz iteration {} (len={})", i, len);
        }
    }
    println!("fuzz_runner completed");
}
