extern crate syntex;
extern crate pnet_macros;

use std::env;
use std::path::Path;

const FILES: &'static [&'static str] = &[
    "netlink.rs",
    "route.rs"
];

pub fn expand() {
    let out_dir = env::var_os("OUT_DIR").unwrap();

    for file in FILES {
        let src_file = format!("src/packet/{}.in", file);
        let src = Path::new(&src_file);
        let dst = Path::new(&out_dir).join(file);

        let mut registry = syntex::Registry::new();
        pnet_macros::register(&mut registry);

        registry.expand("", &src, &dst).unwrap();
    }
}

fn main() {
    expand();
}
