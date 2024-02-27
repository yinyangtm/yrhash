use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("version.rs");
    let mut f = File::create(&dest_path).unwrap();

    f.write_all(b"
        pub const VERSION: &str = env!(\"CARGO_PKG_VERSION\");
        pub const AUTHORS: &str = env!(\"CARGO_PKG_AUTHORS\");
        pub const DESCRIPTION: &str = env!(\"CARGO_PKG_DESCRIPTION\");
    ").unwrap();
}