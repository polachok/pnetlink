extern crate syntex;
extern crate pnet_macros;

use std::env;
use std::path::Path;
use std::fs;

const FILES: &'static [&'static str] = &[
    "netlink.rs",
    "route/route.rs",
    "audit/audit.rs"
];

pub fn expand() {
    let out_dir = env::var_os("OUT_DIR").unwrap();

    for file in FILES {
        let src_file = format!("src/packet/{}.in", file);
        let src = Path::new(&src_file);
        let dst_name = Path::new(file);
        if let Some(parent) = dst_name.parent() {
            fs::create_dir(Path::new(&out_dir).join(parent));
        }
        let dst = Path::new(&out_dir).join(dst_name);

        let mut registry = syntex::Registry::new();
        pnet_macros::register(&mut registry);

        registry.expand("", &src, &dst).unwrap();
    }
}

fn main() {
    expand();
}
