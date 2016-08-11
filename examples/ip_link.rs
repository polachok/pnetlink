extern crate pnetlink;

use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::route::link::{LinkManager,Link};
use pnetlink::packet::route::addr::{AddrManager,Addr};

fn print_link(link: &Link) {
    println!("{}: {}: <{:?}> mtu {:?} qdisc {} state {:?}", link.get_index(), link.get_name().unwrap(),
                link.get_flags(), link.get_mtu().unwrap(), link.get_qdisc().unwrap(), link.get_state());
    println!("   Link/{:?} {:?} brd {:?}", link.get_type(), link.get_hw_addr().unwrap(), link.get_broadcast().unwrap());
}

fn print_addr(addr: &Addr) {
    let family = match addr.get_family() {
        2 => "inet",
        10 => "inet6",
        _ => "unknown",
    };
    fn debug_or_empty<T: ::std::fmt::Debug>(prefix: &str, val: Option<T>) -> String {
        match val {
            Some(val) => format!("{}{:?} ", prefix, val),
            None => " ".to_owned(),
        }
    }
    fn display_or_empty<T: ::std::fmt::Display>(prefix: &str, val: Option<T>) -> String {
        match val {
            Some(val) => format!("{}{} ", prefix, val),
            None => " ".to_owned(),
        }
    }
    let broadcast = debug_or_empty("brd ", addr.get_broadcast_ip());
    let label = display_or_empty("", addr.get_label());
    println!("   {} {:?}/{}{}scope {:?} {}", family, addr.get_ip().unwrap(), addr.get_prefix_len(), broadcast, addr.get_scope(), label);
}

fn main() {
    let mut conn = NetlinkConnection::new();
    let links = LinkManager::new(&mut conn).iter_links().collect::<Vec<_>>();
    for link in links {
        print_link(&link);
        let mut addr_man = AddrManager::new(&mut conn);
        for addr in addr_man.get_link_addrs(&link) {
            //println!("{:?}", addr.get_ip());
            print_addr(&addr);
        }
    }
}
