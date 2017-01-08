use packet::route::{FibRulePacket,MutableRtMsgPacket,MutableIfInfoPacket,RtAttrIterator,RtAttrPacket,MutableRtAttrPacket};
use packet::route::link::Link;
use packet::netlink::{MutableNetlinkPacket,NetlinkPacket,NetlinkErrorPacket};
use packet::netlink::{NLM_F_ACK,NLM_F_REQUEST,NLM_F_DUMP,NLM_F_MATCH,NLM_F_EXCL,NLM_F_CREATE};
use packet::netlink::{NLMSG_NOOP,NLMSG_ERROR,NLMSG_DONE,NLMSG_OVERRUN};
use packet::netlink::{NetlinkBufIterator,NetlinkReader,NetlinkRequestBuilder};
use socket::{NetlinkSocket,NetlinkProtocol};
use packet::netlink::NetlinkConnection;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;
use libc;

use std::net::Ipv4Addr;
use std::io::{Read,Cursor,self};
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;

pub const FRA_UNSPEC: u16 = 0;
pub const FRA_DST: u16 = 1;        /* destination address */
pub const FRA_SRC: u16 = 2;        /* source address */
pub const FRA_IFNAME: u16 = 3;    /* interface name */
pub const FRA_GOTO: u16 = 4;       /* target to jump to (FR_ACT_GOTO) */
pub const FRA_UNUSED2: u16 = 5;
pub const FRA_PRIORITY: u16 = 6;   /* priority/preference */
pub const FRA_UNUSED3: u16 = 7;
pub const FRA_UNUSED4: u16 = 8;
pub const FRA_UNUSED5: u16 = 9;
pub const FRA_FWMARK: u16 = 10;     /* mark */
pub const FRA_FLOW: u16 = 11;       /* flow/class id */
pub const FRA_TUN_ID: u16 = 12;
pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_TABLE: u16 = 15;      /* Extended table id */
pub const FRA_FWMASK: u16 = 16;     /* mask for netfilter mark */
pub const FRA_OIFNAME: u16 = 17;

#[derive(Debug)]
pub struct Route {
    packet: NetlinkPacket<'static>,
}

impl Route {
    pub fn iter_rules(conn: &mut NetlinkConnection) -> RulesIterator<&mut NetlinkConnection> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETRULE, NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo
            }).build();
        let mut reply = conn.send(req);
        RulesIterator { iter: reply.into_iter() }
    }

    fn dump_rule(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWRULE {
            return;
        }
        //println!("NetLink pkt {:?}", msg);
        if let Some(rtm) = FibRulePacket::new(&msg.payload()[0..]) {
            println!("├ rtm: {:?}", rtm);
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match rta.get_rta_type() {
                    FRA_PRIORITY => {
                        let mut cur = Cursor::new(rta.payload());
                        let prio = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ PRIORITY: {:?}", prio);
                    },
                    FRA_SUPPRESS_PREFIXLEN => {
                        println!(" ├ SUPPRESS PREFIXLEN: {:?}", rta.payload());
                    },
                    FRA_TABLE => {
                        let mut cur = Cursor::new(rta.payload());
                        let table = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ TABLE: {:?}", table);
                    },
                    _ => println!(" ├ {:?}", rta),
                }
            }
        }
    }
}

pub struct RulesIterator<R: Read> {
    iter: NetlinkBufIterator<R>,
}

impl<R: Read> Iterator for RulesIterator<R> {
    type Item = Route;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(pkt) => {
                let kind = pkt.get_kind();
                if kind != RTM_NEWRULE {
                    return None;
                }
                return Some(Route { packet: pkt });
            },
            None => None,
        }
    }
}

#[test]
fn dump_rules() {
    let mut conn = NetlinkConnection::new();
    for rule in Route::iter_rules(&mut conn) {
        Route::dump_rule(rule.packet.get_packet());
    }
}