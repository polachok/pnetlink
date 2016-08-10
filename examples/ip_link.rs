extern crate pnetlink;

use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::route::link::LinkManager;

fn main() {
    let mut conn = NetlinkConnection::new();
    let mut links = LinkManager::new(conn);
    for link in links.iter_links() {
        println!("{:?}", link);
    }
}
