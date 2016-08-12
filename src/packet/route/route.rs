use packet::route::{RtMsgPacket,MutableRtMsgPacket,MutableIfInfoPacket,RtAttrIterator,RtAttrPacket,MutableRtAttrPacket};
use packet::route::link::Link;
use packet::netlink::{MutableNetlinkPacket,NetlinkPacket,NetlinkErrorPacket};
use packet::netlink::{NLM_F_ACK,NLM_F_REQUEST,NLM_F_DUMP,NLM_F_MATCH,NLM_F_EXCL,NLM_F_CREATE};
use packet::netlink::{NLMSG_NOOP,NLMSG_ERROR,NLMSG_DONE,NLMSG_OVERRUN};
use packet::netlink::{NetlinkBuf,NetlinkBufIterator,NetlinkReader,NetlinkRequestBuilder};
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

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

/* Reserved table identifiers */
pub const RT_TABLE_UNSPEC: u32 = 0;
/* User defined values */
pub const RT_TABLE_COMPAT: u32 = 252;
pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;

#[repr(u8)]
enum RtmType {
    UNICAST,            /* Gateway or direct route      */
    LOCAL,              /* Accept locally               */
    BROADCAST,          /* Accept locally as broadcast,
                                   send as broadcast */
    ANYCAST,            /* Accept locally as broadcast,
                                   but send as unicast */
    MULTICAST,          /* Multicast route              */
    BLACKHOLE,          /* Drop                         */
    UNREACHABLE,        /* Destination is unreachable   */
    PROHIBIT,           /* Administratively prohibited  */
    THROW,              /* Not in this table            */
    NAT,                /* Translate this address       */
    XRESOLVE,           /* Use external resolver        */
}

bitflags! {
    pub flags RtmFlags: u8 {
        const NOTIFY = 0x100,
        const CLONED = 0x200,
        const EQUALIZE = 0x400,
        const PREFIX = 0x800,
    }
}

impl RtmFlags {
    pub fn new(val: u8) -> Self {
        RtmFlags::from_bits_truncate(val)
    }
}

pub const RTA_UNSPEC: u16 = 0;
pub const RTA_DST: u16 = 1;
pub const RTA_SRC: u16 = 2;
pub const RTA_IIF: u16 = 3;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_METRICS: u16 = 8;
pub const RTA_MULTIPATH: u16 = 9;
pub const RTA_PROTOINFO: u16 = 10; /* no longer used */
pub const RTA_FLOW: u16 =  11;
pub const RTA_CACHEINFO: u16 = 12;
pub const RTA_SESSION: u16 = 13; /* no longer used */
pub const RTA_MP_ALGO: u16 = 14; /* no longer used */
pub const RTA_TABLE: u16 = 15;
pub const RTA_MARK: u16 = 16;

#[derive(Clone,Debug)]
pub struct Route {
    packet: NetlinkBuf,
}

impl Route {
    pub fn iter_routes(conn: &mut NetlinkConnection) -> RoutesIterator<&mut NetlinkConnection> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETROUTE, NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo
            }).build();
        let mut reply = conn.send(req.get_packet());
        RoutesIterator { iter: reply.into_iter() }
    }

    fn dump_route(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWROUTE {
            return;
        }
        //println!("NetLink pkt {:?}", msg);
        if let Some(rtm) = RtMsgPacket::new(&msg.payload()[0..]) {
            println!("├ rtm: {:?}", rtm);
            let payload = &rtm.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match rta.get_rta_type() {
                    RTA_TABLE => {
                        let mut cur = Cursor::new(rta.payload());
                        let table = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ TABLE {:?}", table);
                    },
                    RTA_OIF => {
                        let mut cur = Cursor::new(rta.payload());
                        let idx = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ OUT.IF {:?}", idx);
                    },
                    RTA_PRIORITY => {
                        let mut cur = Cursor::new(rta.payload());
                        let prio = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ PRIO {:?}", prio);
                    },
                    RTA_GATEWAY => {
                        let mut cur = Cursor::new(rta.payload());
                        let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap());
                        println!(" ├ GATEWAY {:?}", ip);
                    },
                    RTA_CACHEINFO => {
                        println!(" ├ CACHE INFO {:?}", rta.payload())
                    },
                    RTA_SRC => {
                        println!(" ├ SRC {:?}", rta.payload())
                    },
                    RTA_PREFSRC => {
                        let mut cur = Cursor::new(rta.payload());
                        let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap());
                        println!(" ├ PREFSRC {:?}", ip);
                    },
                    RTA_DST => {
                        let mut cur = Cursor::new(rta.payload());
                        let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap());
                        println!(" ├ DST {:?}", ip);
                    },
                    _ => println!(" ├ {:?}", rta),
                }
            }
        }
    }
}

pub struct RoutesIterator<R: Read> {
    iter: NetlinkBufIterator<R>,
}

impl<R: Read> Iterator for RoutesIterator<R> {
    type Item = Route;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(pkt) => {
                let kind = pkt.get_packet().get_kind();
                if kind != RTM_NEWROUTE {
                    return None;
                }
                return Some(Route { packet: pkt });
            },
            None => None,
        }
    }
}

#[test]
fn dump_routes() {
    let mut conn = NetlinkConnection::new();
    for route in Route::iter_routes(&mut conn) {
        Route::dump_route(route.packet.get_packet());
    }
}
