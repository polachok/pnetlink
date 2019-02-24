//! Route operations
use packet::route::{RouteCacheInfoPacket, RtMsgPacket, MutableIfInfoPacket, IfInfoPacket,
                    RtAttrIterator, RtAttrPacket, MutableRtAttrPacket};
use packet::netlink::NetlinkPacket;
use packet::netlink::NetlinkMsgFlags;
use packet::netlink::{NetlinkBufIterator, NetlinkReader, NetlinkRequestBuilder};
use packet::netlink::NetlinkConnection;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use util;

use std::net::{Ipv4Addr, IpAddr};
use std::io::{Read, Cursor};
use byteorder::{LittleEndian, BigEndian, ReadBytesExt, NativeEndian, ByteOrder};

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

// Reserved table identifiers
pub const RT_TABLE_UNSPEC: u32 = 0;
// User defined values
pub const RT_TABLE_COMPAT: u32 = 252;
pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;

#[repr(u8)]
enum RtmType {
    UNICAST, // Gateway or direct route
    LOCAL, // Accept locally
    BROADCAST, /* Accept locally as broadcast,
                * send as broadcast */
    ANYCAST, /* Accept locally as broadcast,
              * but send as unicast */
    MULTICAST, // Multicast route
    BLACKHOLE, // Drop
    UNREACHABLE, // Destination is unreachable
    PROHIBIT, // Administratively prohibited
    THROW, // Not in this table
    NAT, // Translate this address
    XRESOLVE, // Use external resolver
}

bitflags! {
    pub struct RtmFlags: u32 {
        const NOTIFY = 0x100;
        const CLONED = 0x200;
        const EQUALIZE = 0x400;
        const PREFIX = 0x800;
    }
}

impl RtmFlags {
    pub fn new(val: u32) -> Self {
          RtmFlags::from_bits_truncate(val)
    }
}

/// Each netlink family has a set of 32 multicast groups. The ROUTE family defines the
/// following values, which can be passed to `NetlinkSocket::bind`, eventually
/// ending up in the `sockaddr_nl` struct's `nl_groups` field. From `linux/rtnetlink.h`.
bitflags! {
    pub struct MulticastGroup: u32 {
        const RTMGRP_NONE = 0x0;

        const RTMGRP_LINK = 0x1;
        const RTMGRP_NOTIFY = 0x2;
        const RTMGRP_NEIGH = 0x4;
        const RTMGRP_TC = 0x8;

        const RTMGRP_IPV4_IFADDR = 0x10;
        const RTMGRP_IPV4_MROUTE = 0x20;
        const RTMGRP_IPV4_ROUTE = 0x40;
        const RTMGRP_IPV4_RULE = 0x80;

        const RTMGRP_IPV6_IFADDR = 0x100;
        const RTMGRP_IPV6_MROUTE = 0x200;
        const RTMGRP_IPV6_ROUTE = 0x400;
        const RTMGRP_IPV6_IFINFO = 0x800;

        const RTMGRP_DECnet_IFADDR = 0x1000;
        const RTMGRP_DECnet_ROUTE = 0x4000;

        const RTMGRP_IPV6_PREFIX = 0x20000;
    }
}

impl MulticastGroup {
    pub fn new(groups: u32) -> Self {
        MulticastGroup::from_bits_truncate(groups)
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
pub const RTA_FLOW: u16 = 11;
pub const RTA_CACHEINFO: u16 = 12;
pub const RTA_SESSION: u16 = 13; /* no longer used */
pub const RTA_MP_ALGO: u16 = 14; /* no longer used */
pub const RTA_TABLE: u16 = 15;
pub const RTA_MARK: u16 = 16;

#[derive(Debug)]
pub struct Route {
    packet: NetlinkPacket<'static>,
}

impl Route {
    /// Iterate over routes
    pub fn iter_routes(conn: &mut NetlinkConnection) -> RoutesIterator<&mut NetlinkConnection> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETROUTE, NetlinkMsgFlags::NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo
            })
            .build();
        let mut reply = conn.send(req);
        RoutesIterator { iter: reply.into_iter() }
    }

    fn dump_route(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWROUTE {
            return;
        }
        // println!("NetLink pkt {:?}", msg);
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
                    }
                    RTA_OIF => {
                        let mut cur = Cursor::new(rta.payload());
                        let idx = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ OUT.IF {:?}", idx);
                    }
                    RTA_PRIORITY => {
                        let mut cur = Cursor::new(rta.payload());
                        let prio = cur.read_u32::<LittleEndian>().unwrap();
                        println!(" ├ PRIO {:?}", prio);
                    }
                    RTA_GATEWAY => {
                        let mut cur = Cursor::new(rta.payload());
                        let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap());
                        println!(" ├ GATEWAY {:?}", ip);
                    }
                    RTA_CACHEINFO => {
                        let pkt = RouteCacheInfoPacket::new(rta.payload());
                        println!(" ├ CACHE INFO {:?}", pkt);
                    }
                    RTA_SRC => println!(" ├ SRC {:?}", rta.payload()),
                    RTA_PREFSRC => {
                        let mut cur = Cursor::new(rta.payload());
                        let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap());
                        println!(" ├ PREFSRC {:?}", ip);
                    }
                    RTA_DST => {
                        let mut cur = Cursor::new(rta.payload());
                        let ip = Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap());
                        println!(" ├ DST {:?}", ip);
                    }
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
                let kind = pkt.get_kind();
                if kind != RTM_NEWROUTE {
                    return None;
                }
                return Some(Route { packet: pkt });
            }
            None => None,
        }
    }
}

#[test]
fn dump_routes() {
    let mut conn = NetlinkConnection::new();
    for route in Route::iter_routes(&mut conn) {
        Route::dump_route(route.packet);
    }
}

/// A trait for converting data into Payload for a `RtAttrPacket`.
pub trait ToPayload {
    /// Add this data to the given u8 data slice.
    /// The `payload` expects that the data begins from index 0.
    /// The length of `payload` is at least `payload_size()` long.
    fn payload_add(&self, payload: &mut [u8]);
    /// The number of bytes required to encode this data.
    fn payload_size(&self) -> usize;
}

impl ToPayload for IpAddr {
    fn payload_add(&self, payload: &mut [u8]) {
        match self {
            &IpAddr::V4(ip) => {
                payload.copy_from_slice(&ip.octets());
            }
            &IpAddr::V6(ip) => {
                payload.copy_from_slice(&ip.octets());
            }
        }
    }

    fn payload_size(&self) -> usize {
        match self {
            &IpAddr::V4(_) => 4,
            &IpAddr::V6(_) => 16,
        }
    }
}

impl<'a> ToPayload for &'a str {
    fn payload_add(&self, payload: &mut [u8]) {
        payload[..self.as_bytes().len()].copy_from_slice(self.as_bytes())
    }

    fn payload_size(&self) -> usize {
        self.as_bytes().len() + 1
    }
}

impl<'a> ToPayload for &'a [&'a ToPayload] {
    fn payload_add(&self, payload: &mut [u8]) {
        self.iter().fold(0, |pos, pkg| {
            pkg.payload_add(&mut payload[pos..]);
            pos + pkg.payload_size()
        });
    }

    fn payload_size(&self) -> usize {
        self.iter().map(|p| p.payload_size()).sum()
    }
}

impl<P: ToPayload> ToPayload for Option<P> {
    fn payload_add(&self, payload: &mut [u8]) {
        self.as_ref().map(|d| d.payload_add(payload));
    }

    fn payload_size(&self) -> usize {
        self.as_ref().map(|d| d.payload_size()).unwrap_or(0)
    }
}

impl ToPayload for u16 {
    fn payload_add(&self, payload: &mut [u8]) {
        NativeEndian::write_u16(payload, *self)
    }

    fn payload_size(&self) -> usize {
        2
    }
}

impl ToPayload for u32 {
    fn payload_add(&self, payload: &mut [u8]) {
        NativeEndian::write_u32(payload, *self)
    }

    fn payload_size(&self) -> usize {
        4
    }
}

impl ToPayload for u8 {
    fn payload_add(&self, payload: &mut [u8]) {
        payload[0] = *self
    }

    fn payload_size(&self) -> usize {
        1
    }
}

impl<'a> ToPayload for RtAttrPacket<'a> {
    fn payload_add(&self, payload: &mut [u8]) {
        payload[..self.packet_size()].copy_from_slice(&self.packet())
    }

    fn payload_size(&self) -> usize {
        util::align(self.packet_size())
    }
}

impl<'a> ToPayload for IfInfoPacket<'a> {
    fn payload_add(&self, payload: &mut [u8]) {
        payload[..self.packet_size()].copy_from_slice(&self.packet())
    }

    fn payload_size(&self) -> usize {
        util::align(self.packet_size())
    }
}

/// A trait that provides a function to create a new `RtAttrPacket` with a payload.
pub trait WithPayload {
    /// Create a new `RtAttrPacket` with the given kind and payload.
    fn create_with_payload<P: ToPayload>(kind: u16, payload: P) -> RtAttrPacket<'static>;
}

impl<'a> WithPayload for RtAttrPacket<'a> {
    fn create_with_payload<P: ToPayload>(kind: u16, payload: P) -> RtAttrPacket<'static> {
        let total_len = RtAttrPacket::minimum_packet_size() + payload.payload_size();
        let mut buf = vec![0; total_len];
        let result = {
            let mut packet = MutableRtAttrPacket::new(&mut buf).unwrap();
            packet.set_rta_type(kind);
            packet.set_rta_len(total_len as u16);

            payload.payload_add(&mut packet.payload_mut());

            packet.consume_to_immutable()
        };

        RtAttrPacket::owned(result.packet().to_vec()).unwrap()
    }
}
