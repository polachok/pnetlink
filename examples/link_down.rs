extern crate pnetlink;

use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::route::link::Links;

use std::env;

fn main() {
    let mut conn = NetlinkConnection::new();

    let linkname = match env::args().nth(1) {
        Some(n) => n,
        None => {
            println!("usage: <prog> linkname");
            return;
        }
    };
    println!("Setting link {} down...", linkname);

    let link = conn.get_link_by_name(linkname.as_str()).unwrap().unwrap();
    conn.link_set_down(link.get_index()).unwrap();
    println!("success!");
}
