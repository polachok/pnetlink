use packet::route::{IfInfoPacket,MutableIfInfoPacket,RtAttrIterator,RtAttrPacket,MutableRtAttrPacket,RtAttrMtuPacket};
use packet::netlink::{MutableNetlinkPacket,NetlinkPacket,NetlinkErrorPacket};
use packet::netlink::{NLM_F_ACK,NLM_F_REQUEST,NLM_F_DUMP,NLM_F_MATCH,NLM_F_EXCL,NLM_F_CREATE};
use packet::netlink::{NLMSG_NOOP,NLMSG_ERROR,NLMSG_DONE,NLMSG_OVERRUN};
use packet::netlink::{NetlinkBuf,NetlinkBufIterator,NetlinkReader,NetlinkRequestBuilder};
use ::socket::{NetlinkSocket,NetlinkProtocol};
use packet::netlink::NetlinkConnection;
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;
use libc;
use std::io::{Read,self};

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

#[derive(Copy,Clone,Debug)]
pub enum LinkType {
    Vlan,
    Veth,
    Vcan,
    Dummy,
    Ifb,
    MacVlan,
    Can,
    Bridge
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

    pub fn delete(self, conn: &mut NetlinkConnection) -> io::Result<()> {
        let index = self.get_index();
        let mut req = {
            let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
            NetlinkRequestBuilder::new(RTM_DELLINK, NLM_F_ACK)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo.set_index(index);
                ifinfo
            }).build()
        };
        let mut reply = conn.send(req.get_packet());
        for p in reply.into_iter() {
            let packet = p.get_packet();
            if packet.get_kind() == NLMSG_ERROR {
                let err = NetlinkErrorPacket::new(packet.payload()).unwrap();
                return Err(io::Error::from_raw_os_error(-(err.get_error() as i32)));
            }
        }
        Ok(())
    }
    /*
fn new(name: &str, kind: &str) -> io::Result<()> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(0 /* AF_UNSPEC */);
                ifinfo
            }).build();
        Ok(())
    }
    */

    // static methods
    pub fn new(name: &str, kind: LinkType, conn: &mut NetlinkConnection) -> io::Result<Link> {
        let mut ifi = {
            let mut buf = vec![0; 32];
            let name_len = name.as_bytes().len();
            let mut buf_name = vec![0; RtAttrPacket::minimum_packet_size() + name_len + 1];
            IfInfoPacketBuilder::new().
                append({
                    {
                        let mut ifname_rta = MutableRtAttrPacket::new(&mut buf_name).unwrap();
                        ifname_rta.set_rta_type(IFLA_IFNAME);
                        ifname_rta.set_rta_len(4 + name_len as u16 + 1);
                        let mut payload = ifname_rta.payload_mut();
                        payload[0..name_len].copy_from_slice(name.as_bytes());
                    }
                    RtAttrPacket::new(&buf_name).unwrap()
                }).
                append({
                    {
                        let mut link_info_rta = MutableRtAttrPacket::new(&mut buf).unwrap();
                        link_info_rta.set_rta_type(IFLA_LINKINFO);
                        link_info_rta.set_rta_len(6 + 4 + 4);
                        let mut info_kind_rta = MutableRtAttrPacket::new(link_info_rta.payload_mut()).unwrap();
                        info_kind_rta.set_rta_type(IFLA_INFO_KIND);
                        info_kind_rta.set_rta_len(6 + 4);
                        let mut payload = info_kind_rta.payload_mut();
                        payload[0..6].copy_from_slice(b"dummy\0");
                    }
                    RtAttrPacket::new(&buf).unwrap()
            }).build()
        };
        let req = NetlinkRequestBuilder::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
            .append(ifi.get_packet()).build();
        {
            let mut reply = conn.send(req.get_packet());
            for pkt in reply {
                let pkt = pkt.get_packet();
                if pkt.get_kind() == NLMSG_ERROR {
                    let err = NetlinkErrorPacket::new(pkt.payload()).unwrap();
                    if err.get_error() != 0 {
                        return Err(io::Error::from_raw_os_error(-(err.get_error() as i32)));
                    }
                    break;
                }
            }
        }
        Ok(Link::get_by_name(conn, name).unwrap())
    }

    pub fn iter_links(conn: &mut NetlinkConnection) -> LinksIterator<&mut NetlinkConnection> {
        let mut reply = conn.send(Self::dump_links_request().get_packet());
        LinksIterator { iter: reply.into_iter() }
    }

    pub fn get_by_name(conn: &mut NetlinkConnection, name: &str) -> Option<Link> {
        let req = {
            let name_len = name.as_bytes().len();
            let mut buf = vec![0; RtAttrPacket::minimum_packet_size() + name_len + 1];
            let ifi = IfInfoPacketBuilder::new().append({
                {
                    let mut ifname_rta = MutableRtAttrPacket::new(&mut buf).unwrap();
                    ifname_rta.set_rta_type(IFLA_IFNAME);
                    ifname_rta.set_rta_len((RtAttrPacket::minimum_packet_size() + name_len + 1) as u16);
                    let mut payload = ifname_rta.payload_mut();
                    payload[0..name_len].copy_from_slice(name.as_bytes());
                }
                RtAttrPacket::new(&buf[..]).unwrap()
            }).build();
            NetlinkRequestBuilder::new(RTM_GETLINK, NLM_F_ACK).append(ifi.get_packet()).build()
        };
        let mut reply = conn.send(req.get_packet());
        let li = LinksIterator { iter: reply.into_iter() };
        li.last()
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
        println!("NL pkt length: {:?}", msg.get_length());
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

struct IfInfoPacketBuf {
    data: Vec<u8>,
}

impl IfInfoPacketBuf {
    pub fn get_packet(&self) -> IfInfoPacket {
        IfInfoPacket::new(&self.data[..]).unwrap()
    }
}

struct IfInfoPacketBuilder {
    data: Vec<u8>,
}

impl IfInfoPacketBuilder {
    pub fn new() -> Self {
        let len = MutableIfInfoPacket::minimum_packet_size();
        let mut data = vec![0; len];
        IfInfoPacketBuilder { data: data }
    }

    pub fn set_family(mut self, family: u8) -> Self {
        {
            let mut pkt = MutableIfInfoPacket::new(&mut self.data[..]).unwrap();
            pkt.set_family(family);
        }
        self
    }

    pub fn set_type(mut self, type_: IfType) -> Self {
        {
            let mut pkt = MutableIfInfoPacket::new(&mut self.data[..]).unwrap();
            pkt.set_type_(type_);
        }
        self
    }

    pub fn set_flags(mut self, flags: IfFlags) -> Self {
        {
            let mut pkt = MutableIfInfoPacket::new(&mut self.data[..]).unwrap();
            pkt.set_flags(flags);
        }
        self
    }

    pub fn append(mut self, rta: RtAttrPacket) -> Self {
        let len = rta.get_rta_len() as usize;
        let aligned_len = ::util::align(len);
        self.data.extend_from_slice(&rta.packet()[0..len]);
        // add padding for alignment
        for _ in len..aligned_len {
            self.data.push(0);
        }
        self
    }

    pub fn build(self) -> IfInfoPacketBuf {
        IfInfoPacketBuf { data: self.data }
    }
}

#[test]
fn netlink_route_dump_links() {
    Link::dump_links();
}

#[test]
fn link_by_idx() {
    let mut conn = NetlinkConnection::new();
    println!("{:?}", Link::get_by_index(&mut conn, 1))
}

#[test]
fn del_link() {
    let mut conn = NetlinkConnection::new();
    let link = Link::get_by_index(&mut conn, 6);
    assert!(link.is_some());
    let link = link.unwrap();
    let result = link.delete(&mut conn);
    match result {
        Ok(_) => {
            let link = Link::get_by_index(&mut conn, 6);
            assert!(link.is_none());
        },
        Err(e) => println!("{:?}", e),
    }
}

#[test]
fn new_link() {
    let mut conn = NetlinkConnection::new();
    println!("{:?}", Link::new("lol0", LinkType::Dummy, &mut conn));
}

#[test]
fn link_by_name() {
    let mut conn = NetlinkConnection::new();
    println!("{:?}", Link::get_by_name(&mut conn, "lo"));
}
