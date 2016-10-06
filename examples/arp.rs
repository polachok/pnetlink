extern crate pnetlink;

use std::collections::HashMap;

use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::route::link::{Links, Link};
use pnetlink::packet::route::neighbour::{Neighbour, Neighbours, NOARP};

fn main() {
    let mut conn = NetlinkConnection::new();
    let links =
        conn.iter_links().unwrap().map(|link| (link.get_index(), link)).collect::<HashMap<_, _>>();
    let neighbours = conn.iter_neighbours(None).unwrap().collect::<Vec<_>>();
    for neighbour in neighbours {
        if neighbour.get_state() == NOARP {
            continue;
        }
        let ifindex = neighbour.get_ifindex();
        let link = links.get(&ifindex).unwrap();
        println!("{:?} dev {} lladdr {:?} {:?}",
                 neighbour.get_destination().unwrap(),
                 link.get_name().unwrap(),
                 neighbour.get_ll_addr().unwrap(),
                 neighbour.get_state());
    }
}
