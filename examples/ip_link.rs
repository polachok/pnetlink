extern crate pnetlink;

use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::route::link::LinkFactory;

fn main() {
    let mut conn = NetlinkConnection::new();
    let mut links = LinkFactory::new(conn);
    for link in links.iter_links() {
        println!("{:?}", link);
    }
}
