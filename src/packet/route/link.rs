use packet::route::{IfInfoPacket,MutableIfInfoPacket,RtAttrIterator,RtAttrPacket,RtAttrMtuPacket};
use packet::netlink::{MutableNetlinkPacket,NetlinkPacket,NetlinkErrorPacket};
use packet::netlink::{NLM_F_ACK,NLM_F_REQUEST,NLM_F_DUMP,NLM_F_MATCH,NLM_F_ROOT};
use packet::netlink::{NLMSG_NOOP,NLMSG_ERROR,NLMSG_DONE,NLMSG_OVERRUN};
use packet::netlink::{NetlinkBuf,NetlinkBufIterator,NetlinkReader,NetlinkRequestBuilder};
use ::socket::{NetlinkSocket,NetlinkProtocol};
use packet::netlink::NetlinkConnection;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;
use libc;
use std::io::Read;

/* rt message types */
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;

/* attributes (linux/if_link.h) */
pub const IFLA_UNSPEC: u16 = 0;
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_BROADCAST: u16 = 2;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_LINK: u16 = 5;
pub const IFLA_QDISC: u16 = 6;
pub const IFLA_STATS: u16 = 7;
pub const IFLA_COST: u16 = 8;
pub const IFLA_PRIORITY: u16 = 9;
pub const IFLA_MASTER: u16 = 10;
pub const IFLA_WIRELESS: u16 = 11;
pub const IFLA_PROTINFO: u16 = 12;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_MAP: u16 = 14;
pub const IFLA_WEIGHT: u16 = 15;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFLA_LINKMODE: u16 = 17;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_NET_NS_PID: u16 = 19;
pub const IFLA_IFALIAS: u16 = 20;
pub const IFLA_NUM_VF: u16 = 21;
pub const IFLA_VFINFO_LIST: u16 = 22;
pub const IFLA_STATS64: u16 = 23;
pub const IFLA_VF_PORTS: u16 = 24;
pub const IFLA_PORT_SELF: u16 = 25;
pub const IFLA_AF_SPEC: u16 = 26;
pub const IFLA_GROUP: u16 = 27;
pub const IFLA_NET_NS_FD: u16 = 28;
pub const IFLA_EXT_MASK: u16 = 29;
pub const IFLA_PROMISCUITY: u16 = 30;
pub const IFLA_NUM_TX_QUEUES: u16 = 31;
pub const IFLA_NUM_RX_QUEUES: u16 = 32;
pub const IFLA_CARRIER: u16 = 33;
pub const IFLA_PHYS_PORT_ID: u16 = 34;
pub const IFLA_CARRIER_CHANGES: u16 = 35;
pub const IFLA_PHYS_SWITCH_ID: u16 = 36;
pub const IFLA_LINK_NETNSID: u16 = 37;
pub const IFLA_PHYS_PORT_NAME: u16 = 38;
pub const IFLA_PROTO_DOWN: u16 = 39;
pub const IFLA_GSO_MAX_SEGS: u16 = 40;
pub const IFLA_GSO_MAX_SIZE: u16 = 41;
pub const IFLA_PAD: u16 = 42;

pub const IFLA_INFO_UNSPEC: u16 = 0;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;
pub const IFLA_INFO_XSTATS: u16 = 3;

#[derive(Debug,Copy,Clone)]
#[repr(u16)]
pub enum IfType {
    /* todo: more types, see if_link.h */
    Generic = 0,
    Ether = 1,
    Loopback = 772,
}

impl IfType {
    pub fn new(val: u16) -> Self {
        use std::mem;
        /* XXX */
        unsafe { mem::transmute(val) }
    }
}

/* link flags */
bitflags! {
    pub flags IfFlags: u32 {
        const UP      =    0x1,             /* interface is up              */
        const BROADCAST =  0x2,             /* broadcast address valid      */
        const DEBUG    =   0x4,             /* turn on debugging            */
        const LOOPBACK  =  0x8,             /* is a loopback net            */
        const POINTOPOINT = 0x10,            /* interface is has p-p link    */
        const NOTRAILERS = 0x20,            /* avoid use of trailers        */
        const RUNNING   =  0x40,            /* interface RFC2863 OPER_UP    */
        const NOARP     =  0x80,            /* no ARP protocol              */
        const PROMISC   =  0x100,           /* receive all packets          */
        const ALLMULTI  =  0x200,           /* receive all multicast packets*/

        const MASTER    =  0x400,           /* master of a load balancer    */
        const SLAVE     =  0x800,           /* slave of a load balancer     */

        const MULTICAST =  0x1000,          /* Supports multicast           */

        const PORTSEL   =  0x2000,          /* can set media type           */
        const AUTOMEDIA =  0x4000,          /* auto media select active     */
        const DYNAMIC   =  0x8000,          /* dialup device with changing addresses*/

        const LOWER_UP  =  0x10000,         /* driver signals L1 up         */
        const DORMANT   =  0x20000,         /* driver signals dormant       */

        const ECHO      =  0x40000,         /* echo sent packets            */
    }
}

impl IfFlags {
    pub fn new(val: u32) -> Self {
        IfFlags::from_bits_truncate(val)
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

pub struct Link {
    packet: NetlinkBuf
}

pub struct LinksIterator<R: Read> {
    iter: NetlinkBufIterator<R>,
}

impl<R: Read> Iterator for LinksIterator<R> {
    type Item = Link;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(pkt) => {
                let kind = pkt.get_packet().get_kind();
                if kind != RTM_NEWLINK {
                    return None;
                }
                return Some(Link { packet: pkt });
            },
            None => None,
        }
    }
}

impl ::std::fmt::Debug for Link {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        try!(write!(f, "{}: {}: <{:?}> mtu {} qdisc {} state {:?}\n", self.get_index(), self.get_name(),
                self.get_flags(), self.get_mtu(), self.get_qdisc(), self.get_state()));
        write!(f, "   Link/{:?} {:?} brd {:?}", self.get_link_type(), self.get_hw_addr(), self.get_broadcast())
    }
}

impl Link {
    pub fn get_link_type(&self) -> IfType {
        self.with_ifinfo(|ifi| ifi.get_type_())
    }

    pub fn get_hw_addr(&self) -> MacAddr {
        self.with_rta_iter(|mut rti| {
            let rta = rti.find(|rta| rta.get_rta_type() == IFLA_ADDRESS).unwrap();
            let payload = rta.payload();
            MacAddr::new(payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
        })
    }

    pub fn get_broadcast(&self) -> MacAddr {
        self.with_rta_iter(|mut rti| {
            let rta = rti.find(|rta| rta.get_rta_type() == IFLA_BROADCAST).unwrap();
            let payload = rta.payload();
            MacAddr::new(payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
        })
    }

    pub fn get_flags(&self) -> IfFlags {
        let msg = self.packet.get_packet();
        let ifi = IfInfoPacket::new(&msg.payload()[0..]).unwrap();
        return ifi.get_flags();
    }

    pub fn get_index(&self) -> u32 {
        let msg = self.packet.get_packet();
        let ifi = IfInfoPacket::new(&msg.payload()[0..]).unwrap();
        return ifi.get_index();
    }

    pub fn get_name(&self) -> String {
        use std::ffi::CStr;
        let msg = self.packet.get_packet();
        let ifi = IfInfoPacket::new(&msg.payload()[0..]).unwrap();

        let payload = &ifi.payload()[0..];
        let iter = RtAttrIterator::new(payload);
        for rta in iter {
            match rta.get_rta_type() {
                IFLA_IFNAME => {
                    let cstr = CStr::from_bytes_with_nul(rta.payload()).unwrap();
                    return cstr.to_owned().into_string().unwrap();
                },
                _ => {},
            }
        }
        unreachable!();
    }

    fn with_packet<T,F>(&self, cb: F) -> T
        where F: Fn(NetlinkPacket) -> T {
        cb(self.packet.get_packet())
    }

    fn with_ifinfo<T,F>(&self, cb: F) -> T
        where F: Fn(IfInfoPacket) -> T {
        self.with_packet(|pkt| 
            cb(IfInfoPacket::new(pkt.payload()).unwrap())
        )
    }

    fn with_rta_iter<T,F>(&self, cb: F) -> T
        where F: Fn(RtAttrIterator) -> T {
            self.with_ifinfo(|ifi| {
                cb(RtAttrIterator::new(ifi.payload()))
            })
    }

    fn get_mtu(&self) -> u32 {
        self.with_rta_iter(|mut rti| {
            let rta = rti.find(|rta| rta.get_rta_type() == IFLA_MTU).unwrap();
            let mtu = RtAttrMtuPacket::new(rta.packet()).unwrap();
            mtu.get_mtu()
        })
    }

    fn get_qdisc(&self) -> String {
        use std::ffi::CStr;
        self.with_rta_iter(|mut rti| {
            let rta = rti.find(|rta| rta.get_rta_type() == IFLA_QDISC).unwrap();
            let cstr = CStr::from_bytes_with_nul(rta.payload()).unwrap();
            cstr.to_owned().into_string().unwrap()
        })
    }

    fn get_state(&self) -> OperState {
        use std::mem;
        self.with_rta_iter(|mut rti| {
            let rta = rti.find(|rta| rta.get_rta_type() == IFLA_OPERSTATE).unwrap();
            unsafe { mem::transmute(rta.payload()[0]) }
        })
    }

    // static methods
    pub fn iter_links(conn: &mut NetlinkConnection) -> LinksIterator<&mut NetlinkConnection> {
        let mut reply = conn.send(Self::dump_links_request().get_packet());
        LinksIterator { iter: reply.into_iter() }
    }

    pub fn get_by_index(conn: &mut NetlinkConnection, index: u32) -> Option<Link> {
        let mut req = {
            let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
            NetlinkRequestBuilder::new(RTM_GETLINK, NLM_F_ACK)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo.set_index(index);
                ifinfo
            }).build()
        };
        let mut reply = conn.send(req.get_packet());
        let li = LinksIterator { iter: reply.into_iter() };
        li.last()
    }

    fn get_links_iter<R: Read>(r: NetlinkBufIterator<R>) -> LinksIterator<R> {
        //let mut conn = NetlinkConnection::new();
        //let mut buf = [0; 32];
        //let mut reply = conn.send(Self::dump_links_request(&mut buf));
        LinksIterator { iter: r }
    }

    fn dump_links_request() -> NetlinkBuf {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];

        NetlinkRequestBuilder::new(RTM_GETLINK, NLM_F_DUMP)
        .append({
            let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
            ifinfo.set_family(0 /* AF_UNSPEC */);
            ifinfo
       }).build()
    }

    fn dump_links() {
        let mut conn = NetlinkConnection::new();
        let mut reply = conn.send(Self::dump_links_request().get_packet());

        for slot in reply {
            println!("{:?}", slot.get_packet());
            Self::dump_link(slot.get_packet());
        }
    }

    fn dump_link(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWLINK {
            return;
        }

        if let Some(ifi) = IfInfoPacket::new(&msg.payload()[0..]) {
            println!("├ ifi: {:?}", ifi);
            let payload = &ifi.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match rta.get_rta_type() {
                    IFLA_IFNAME => {
                        println!(" ├ ifname: {:?}", CStr::from_bytes_with_nul(rta.payload()));
                    },
                    IFLA_ADDRESS => {
                        println!(" ├ hw addr: {:?}", rta.payload());
                    },
                    IFLA_LINKINFO => {
                        println!(" ├ LINKINFO {:?}", rta);
                    },
                    IFLA_MTU => {
                        let rta = RtAttrMtuPacket::new(rta.packet()).unwrap();
                        println!(" |- MTU {:?}", rta);
                    },
                    IFLA_QDISC => {
                        println!(" ├ QDISC {:?} {:?}", rta, CStr::from_bytes_with_nul(rta.payload()));
                    },
                    IFLA_OPERSTATE => {
                        println!(" ├ OPERSTATE {:?} {:?}", rta, rta.payload());
                    },
                    _ => {
                        println!(" ├ {:?}", rta);
                    },
                }
            }
        }
    }
}

#[test]
fn netlink_route_dump_links() {
    Link::dump_links();
}

#[test]
fn link_by_idx() {
    let mut conn = NetlinkConnection::new();
    println!("{:?}", Link::get_by_index(&mut conn, 3))
}
