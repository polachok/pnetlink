use libc;
use std::io::{self, Read, Write};
use std::mem;

use byteorder::{ByteOrder, NativeEndian};

use packet::route::addr::Addr;
use packet::route::{NeighbourDiscoveryPacket, MutableNeighbourDiscoveryPacket, RtAttrIterator,
                    RtAttrPacket, MutableRtAttrPacket, RtAttrMtuPacket};
use packet::route::link::Link;
use packet::netlink::{MutableNetlinkPacket, NetlinkPacket, NetlinkErrorPacket};
use packet::netlink::{NLM_F_ACK, NLM_F_REQUEST, NLM_F_DUMP, NLM_F_MATCH, NLM_F_EXCL, NLM_F_CREATE};
use packet::netlink::{NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN};
use packet::netlink::{NetlinkBufIterator, NetlinkReader, NetlinkRequestBuilder};
use ::socket::{NetlinkSocket, NetlinkProtocol};
use packet::netlink::NetlinkConnection;
use packet::route::addr::IpAddr;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;

// rt message types
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;

// See linux/neighbour.h for the source for the cosntants and structs herein


#[derive(Debug,Copy,Clone)]
#[repr(u16)]
pub enum NeighbourAttributes {
    UNSPEC = 0,
    DST = 1,
    LLADDR = 2,
    CACHEINFO = 3,
    PROBES = 4,
    VLAN = 5,
    PORT = 6,
    VNI = 7,
    IFINDEX = 8,
    MASTER = 9,
    LINK_NETNSID = 10,
}

impl From<u16> for NeighbourAttributes {
    fn from(val: u16) -> Self {
        unsafe { mem::transmute(val) }
    }
}

// impl NeighbourAttributes {
// pub fn new(val: u16) -> Self {
// use std::mem;
// XXX
// unsafe { mem::transmute(val) }
// }
// }
//

#[derive(Debug,Copy,Clone)]
#[repr(u8)]
pub enum NeighbourType {
    UNSPEC = 0,
    DST = 1,
    LLADDR = 2,
    CACHEINFO = 3,
}


#[derive(Copy,Clone,Debug)]
pub enum LinkType {
    Vlan,
    Veth,
    Vcan,
    Dummy,
    Ifb,
    MacVlan,
    Can,
    Bridge,
}

// neighbour states
bitflags! {
    pub flags NeighbourState: u16 {
        const INCOMPLETE =  0x1,    /* Still attempting to resolve. */
        const REACHABLE  =  0x2,    /* A confirmed working cache entry. */
        const STALE      =  0x4,    /* an expired cache entry. */
        const DELAY      =  0x8,    /* Neighbor no longer reachable.
                                       Traffic sent, waiting for confirmation. */
        const PROBE      = 0x10,    /* A cache entry that is currently
                                       being re-solicited.*/
        const FAILED     = 0x20,    /* An invalid cache entry. */
        /* Dummy states */
        const NOARP      = 0x40,    /* A device that does not do neighbour discovery */
        const PERMANENT  = 0x80,    /* Permanently set entries */
    }
}

impl NeighbourState {
    pub fn new(val: u16) -> Self {
        NeighbourState::from_bits_truncate(val)
    }
}

// neighbour flags
bitflags! {
    pub flags NeighbourFlags: u8 {
        const USE         =  0x1,
        const SELF        =  0x2,
        const MASTER      =  0x4,
        const PROXY       =  0x8,
        const EXT_LEARNED = 0x10,
        const ROUTER      = 0x80,
    }
}

impl NeighbourFlags {
    pub fn new(val: u8) -> Self {
        NeighbourFlags::from_bits_truncate(val)
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum OperState {
    Unknown = 0,
    NotPresent = 1,
    Down = 2,
    LowerLayerDown = 3,
    Testing = 4,
    Dormant = 5,
    Up = 6,
}

pub struct Neighbour {
    packet: NetlinkPacket<'static>,
}

pub struct NeighboursIterator<R: Read> {
    iter: NetlinkBufIterator<R>,
}

impl<R: Read> Iterator for NeighboursIterator<R> {
    type Item = Neighbour;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(pkt) => {
                let kind = pkt.get_kind();
                if kind != RTM_NEWNEIGH {
                    return None;
                }
                return Some(Neighbour { packet: pkt });
            }
            None => None,
        }
    }
}

impl ::std::fmt::Debug for Neighbour {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        let family = self.get_family();
        write!(f,
               "{:?}: {:?}, {:?}, {:?}, {:?}",
               family,
               self.get_ifindex(),
               self.get_state(),
               self.get_flags(),
               self.get_type());
        self.with_rta_iter(|mut iter| {
            for rta in iter {
                match NeighbourAttributes::from(rta.get_rta_type()) {
                    NeighbourAttributes::LLADDR => {
                        let payload = rta.payload();
                        let mac_addr = MacAddr::new(payload[0],
                                                    payload[1],
                                                    payload[2],
                                                    payload[3],
                                                    payload[4],
                                                    payload[5]);
                        write!(f, " lladdr: {:?}", mac_addr);
                    }
                    NeighbourAttributes::VLAN => {
                        write!(f, " vlan id: {:?}", rta.payload());
                    }
                    NeighbourAttributes::DST => {
                        match rta.get_rta_len() {
                            // 4 for the rta header, then 4 or 16.
                            8 | 20 => {
                                let addr = Addr::ip_from_family_and_bytes(family, rta.payload());
                                write!(f, " {:?}", addr);
                            }
                            l => {
                                write!(f, "unknown address length {:?}", l);
                            }
                        }
                    }
                    _ => {
                        write!(f, " unknown attribute {:?}", rta);
                    }
                }
            }
        });
        Ok(())
    }
}

pub trait Neighbours
    where Self: Read + Write
{
    /// iterate over neighbours
    fn iter_neighbours(&mut self,
                       link: Option<&Link>)
                       -> io::Result<Box<NeighboursIterator<&mut Self>>>;
    // Not implemented yet.
    // delete neighbour
    // fn delete_neighbour(&mut self, neighbour: Neighbour) -> io::Result<()>;
    // create neighbour
    // fn create_neighbour(&mut self, name: &str) -> io::Result<()>;
    //
}

impl Neighbours for NetlinkConnection {
    fn iter_neighbours(&mut self,
                       link: Option<&Link>)
                       -> io::Result<Box<NeighboursIterator<&mut Self>>> {
        // NB: This should be a IfInfoPacket because - well see rtnetlink.c in Linux - but they pun
        // successfully.
        //
        let req = NetlinkRequestBuilder::new(RTM_GETNEIGH, NLM_F_DUMP)
            .append(match link {
                    Some(link) => {
                        NeighbourDiscoveryPacketBuilder::new().set_ifindex(link.get_index())
                    }
                    _ => NeighbourDiscoveryPacketBuilder::new(),
                }
                .build())
            .build();
        try!(self.write(req.packet()));
        let reader = NetlinkReader::new(self);
        Ok(Box::new(NeighboursIterator { iter: reader.into_iter() }))
    }
    // fn get_neighbour_by_index(&mut self, index: u32) -> io::Result<Option<Neighbour>> {
    // let mut req = {
    // let mut buf = vec![0; MutableNeighbourDiscoveryPacket::minimum_packet_size()];
    // NetlinkRequestBuilder::new(RTM_GETNEIGH, NLM_F_ACK)
    // .append(NeighbourDiscoveryPacketBuilder::new()
    // .set_ifindex(index)
    // .build()
    // .get_packet())
    // .build()
    // };
    // try!(self.write(req.get_packet().packet()));
    // let reader = NetlinkReader::new(self);
    // let li = NeighboursIterator { iter: reader.into_iter() };
    // Ok(li.last())
    // }
    //
    // #[cfg(test)]
    // fn new_dummy_neighbour(&mut self, name: &str) -> io::Result<()> {
    // let mut neigh = {
    // let mut buf = vec![0; 32];
    // let name_len = name.as_bytes().len();
    // let mut buf_name = vec![0; RtAttrPacket::minimum_packet_size() + name_len + 1];
    // NeighbourDiscoveryPacketBuilder::new()
    // .build()
    // };
    // let req = NetlinkRequestBuilder::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
    // .append(neigh.get_packet())
    // .build();
    // try!(self.write(req.get_packet().packet()));
    // let reader = NetlinkReader::new(self);
    // reader.read_to_end()
    // }
    //
    // fn delete_neighbour(&mut self, neighbour: Neighbour) -> io::Result<()> {
    // let index = neighbour.get_ifindex();
    // let mut req = {
    // let mut buf = vec![0; MutableNeighbourDiscoveryPacket::minimum_packet_size()];
    // NetlinkRequestBuilder::new(RTM_DELNEIGH, NLM_F_ACK)
    // .append({
    // let mut neighbour = MutableNeighbourDiscoveryPacket::new(&mut buf).unwrap();
    // neighbour.set_family(0 /* AF_UNSPEC */);
    // neighbour.set_ifindex(index);
    // neighbour
    // })
    // .build()
    // };
    // try!(self.write(req.get_packet().packet()));
    // let reader = NetlinkReader::new(self);
    // reader.read_to_end()
    // }
    //
}

impl Neighbour {
    pub fn get_family(&self) -> u8 {
        self.with_neighbour(|neigh| neigh.get_family())
    }

    pub fn get_ifindex(&self) -> u32 {
        self.with_neighbour(|neigh| neigh.get_ifindex())
    }

    pub fn get_state(&self) -> NeighbourState {
        self.with_neighbour(|neigh| neigh.get_state())
    }

    pub fn get_flags(&self) -> NeighbourFlags {
        self.with_neighbour(|neigh| neigh.get_flags())
    }

    pub fn get_type(&self) -> u8 {
        self.with_neighbour(|neigh| neigh.get_type_())
    }

    pub fn get_destination(&self) -> Option<IpAddr> {
        let family = self.get_family();
        let rta_lookup = self.with_rta(NeighbourAttributes::DST, |rta| {
                match rta.get_rta_len() {
                    // 4 for the rta header, then 4 or 16.
                    8 | 20 => {
                        let addr = Addr::ip_from_family_and_bytes(family, rta.payload());
                        Some(addr)
                    },
                    l => {
                        // Perhaps this should return Result<> ?
                        println!("unknown address length {:?}", l);
                        None
                    }
                }
            });
        match rta_lookup {
            Some(result) => result,
            None => None
        }
    }

    pub fn get_ll_addr(&self) -> Option<MacAddr> {
        self.with_rta(NeighbourAttributes::LLADDR, |rta| {
            let payload = rta.payload();
            MacAddr::new(payload[0],
                         payload[1],
                         payload[2],
                         payload[3],
                         payload[4],
                         payload[5])
        })
    }

    pub fn get_vlan_id(&self) -> Option<u16> {
        self.with_rta(NeighbourAttributes::VLAN,
                      |rta| NativeEndian::read_u16(rta.payload()))
    }

    // helper methods
    fn with_packet<T, F>(&self, mut cb: F) -> T
        where F: FnMut(&NetlinkPacket) -> T
    {
        cb(&self.packet)
    }

    fn with_neighbour<T, F>(&self, mut cb: F) -> T
        where F: FnMut(NeighbourDiscoveryPacket) -> T
    {
        self.with_packet(|pkt| cb(NeighbourDiscoveryPacket::new(pkt.payload()).unwrap()))
    }

    fn with_rta_iter<T, F>(&self, mut cb: F) -> T
        where F: FnMut(RtAttrIterator) -> T
    {
        self.with_neighbour(|neigh| cb(RtAttrIterator::new(neigh.payload())))
    }

    fn with_rta<T, F>(&self, rta_type: NeighbourAttributes, cb: F) -> Option<T>
        where F: Fn(RtAttrPacket) -> T
    {
        self.with_rta_iter(|mut rti| {
            rti.find(|rta| rta.get_rta_type() == rta_type as u16).map(|rta| cb(rta))
        })
    }

    // static methods
    fn get_neighbours_iter<R: Read>(r: NetlinkBufIterator<R>) -> NeighboursIterator<R> {
        NeighboursIterator { iter: r }
    }

    fn dump_neighbour(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWNEIGH {
            return;
        }
        println!("NetLink pkt {:?}", msg);
        if let Some(neigh) = NeighbourDiscoveryPacket::new(&msg.payload()[0..]) {
            println!("├ neigh: {:?}", neigh);
            let payload = &neigh.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match NeighbourAttributes::from(rta.get_rta_type()) {
                    NeighbourAttributes::LLADDR => {
                        println!(" ├ lladdr: {:?}", rta.payload());
                    }
                    NeighbourAttributes::VLAN => {
                        println!(" ├ vlan id: {:?}", rta.payload());
                    }
                    _ => {
                        println!(" ├ {:?}", rta);
                    }
                }
            }
        }
    }
}

struct NeighbourDiscoveryPacketBuilder {
    data: Vec<u8>,
}

impl NeighbourDiscoveryPacketBuilder {
    pub fn new() -> Self {
        let len = MutableNeighbourDiscoveryPacket::minimum_packet_size();
        let mut data = vec![0; len];
        NeighbourDiscoveryPacketBuilder { data: data }
    }

    pub fn set_family(mut self, family: u8) -> Self {
        {
            let mut pkt = MutableNeighbourDiscoveryPacket::new(&mut self.data[..]).unwrap();
            pkt.set_family(family);
        }
        self
    }

    pub fn set_ifindex(mut self, index: u32) -> Self {
        {
            let mut pkt = MutableNeighbourDiscoveryPacket::new(&mut self.data[..]).unwrap();
            pkt.set_ifindex(index);
        }
        self
    }

    pub fn set_state(mut self, state: NeighbourState) -> Self {
        {
            let mut pkt = MutableNeighbourDiscoveryPacket::new(&mut self.data[..]).unwrap();
            pkt.set_state(state);
        }
        self
    }

    pub fn set_flags(mut self, flags: NeighbourFlags) -> Self {
        {
            let mut pkt = MutableNeighbourDiscoveryPacket::new(&mut self.data[..]).unwrap();
            pkt.set_flags(flags);
        }
        self
    }

    pub fn set_type(mut self, type_: u8) -> Self {
        {
            let mut pkt = MutableNeighbourDiscoveryPacket::new(&mut self.data[..]).unwrap();
            pkt.set_type_(type_);
        }
        self
    }

    pub fn build(self) -> NeighbourDiscoveryPacket<'static> {
        NeighbourDiscoveryPacket::owned(self.data).unwrap()
    }
}


mod tests {
    #[test]
    fn dump_neighbours() {
        use ::packet::netlink::NetlinkConnection;
        use ::packet::route::neighbour::{Neighbour, Neighbours};
        let mut conn = NetlinkConnection::new();
        for neighbour in conn.iter_neighbours(None).unwrap() {
            Neighbour::dump_neighbour(neighbour.packet.get_packet());
        }
    }

    #[test]
    fn dump_lo_neighbours() {
        use ::packet::netlink::NetlinkConnection;
        use ::packet::route::link::{Link, Links};
        use ::packet::route::neighbour::{Neighbour, Neighbours};

        let mut conn = NetlinkConnection::new();
        let lo0 = conn.get_link_by_name("lo").unwrap().unwrap();
        for neighbour in conn.iter_neighbours(Some(&lo0)).unwrap() {
            Neighbour::dump_neighbour(neighbour.packet.get_packet());
        }
    }

    //    Not implemented yet.
    //    #[test]
    //    // root permissions required
    //    fn create_and_delete_neighbour() {
    //        use ::packet::netlink::NetlinkConnection;
    //        use ::packet::route::neighbour::{Neighbour, Neighbours};
    //
    //        let mut conn = NetlinkConnection::new();
    //        conn.new_dummy_neighbour("test1488").unwrap();
    //        let neighbour = conn.get_neighbour_by_name("test1488").unwrap().unwrap();
    //        assert!(neighbour.get_name() == Some("test1488".to_owned()));
    //        conn.iter_neighbours()
    //            .unwrap()
    //            .find(|neighbour| neighbour.get_name() == Some("test1488".to_owned()))
    //            .is_some();
    //        conn.delete_neighbour(neighbour);
    //        conn.iter_neighbours()
    //            .unwrap()
    //            .find(|neighbour| neighbour.get_name() == Some("test1488".to_owned()))
    //            .is_none();
    //    }

}
