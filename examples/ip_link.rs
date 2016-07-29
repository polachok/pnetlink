extern crate pnetlink;

use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::route::link::Link;

fn main() {
    let mut conn = NetlinkConnection::new();
    for link in Link::iter_links(&mut conn) {
        println!("{:?}", link);
    }
}
