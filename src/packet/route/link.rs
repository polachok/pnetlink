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
        try!(write!(f, "{}: {:?}: <{:?}> mtu {:?} qdisc {:?} state {:?}\n", self.get_index(), self.get_name(),
                self.get_flags(), self.get_mtu(), self.get_qdisc(), self.get_state()));
        write!(f, "   Link/{:?} {:?} brd {:?}", self.get_type(), self.get_hw_addr(), self.get_broadcast())
    }
}

pub struct LinkManager<'a> {
    conn: &'a mut NetlinkConnection,
}

impl<'a> LinkManager<'a> {
    pub fn new(conn: &'a mut NetlinkConnection) -> Self {
        LinkManager { conn: conn }
    }

    pub fn iter_links(&mut self) -> LinksIterator<&mut NetlinkConnection> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETLINK, NLM_F_DUMP)
        .append({
            let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
            ifinfo.set_family(0 /* AF_UNSPEC */);
            ifinfo
        }).build();
        let mut reply = self.conn.send(req.get_packet());
        LinksIterator { iter: reply.into_iter() }
    }

    pub fn get_link_by_index(&mut self, index: u32) -> Option<Link> {
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
        let mut reply = self.conn.send(req.get_packet());
        let li = LinksIterator { iter: reply.into_iter() };
        li.last()
    }

    pub fn get_link_by_name(&mut self, name: &str) -> Option<Link> {
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
        let mut reply = self.conn.send(req.get_packet());
        let li = LinksIterator { iter: reply.into_iter() };
        li.last()
    }

    pub fn new_dummy_link(&mut self, name: &str) -> io::Result<Link> {
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
            let mut reply = self.conn.send(req.get_packet());
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
        Ok(self.get_link_by_name(name).unwrap())
    }

    pub fn delete(&mut self, link: Link) -> io::Result<()> {
        let index = link.get_index();
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
        let mut reply = self.conn.send(req.get_packet());
        for p in reply.into_iter() {
            let packet = p.get_packet();
            if packet.get_kind() == NLMSG_ERROR {
                let err = NetlinkErrorPacket::new(packet.payload()).unwrap();
                return Err(io::Error::from_raw_os_error(-(err.get_error() as i32)));
            }
        }
        Ok(())
    }

}

impl Link {
    /// Get link's unique index
    pub fn get_index(&self) -> u32 {
        self.with_ifinfo(|ifi| ifi.get_index())
    }

    pub fn get_type(&self) -> IfType {
        self.with_ifinfo(|ifi| ifi.get_type_())
    }

    pub fn get_flags(&self) -> IfFlags {
        self.with_ifinfo(|ifi| ifi.get_flags())
    }

    pub fn get_hw_addr(&self) -> Option<MacAddr> {
        self.with_rta(IFLA_ADDRESS, |rta| {
            let payload = rta.payload();
            MacAddr::new(payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
        })
    }

    pub fn get_mtu(&self) -> Option<u32> {
        self.with_rta(IFLA_MTU, |rta| {
            let mtu = RtAttrMtuPacket::new(rta.packet()).unwrap();
            mtu.get_mtu()
        })
    }

    /// Queueing discipline
    pub fn get_qdisc(&self) -> Option<String> {
        use std::ffi::CStr;
        self.with_rta(IFLA_QDISC, |rta| {
            let cstr = CStr::from_bytes_with_nul(rta.payload()).unwrap();
            cstr.to_owned().into_string().unwrap()
        })
    }

    pub fn get_state(&self) -> OperState {
        use std::mem;
        self.with_rta_iter(|mut rti| {
            let rta = rti.find(|rta| rta.get_rta_type() == IFLA_OPERSTATE).unwrap();
            unsafe { mem::transmute(rta.payload()[0]) }
        })
    }

    pub fn get_broadcast(&self) -> Option<MacAddr> {
        self.with_rta(IFLA_BROADCAST, |rta| {
            let payload = rta.payload();
            MacAddr::new(payload[0], payload[1], payload[2], payload[3], payload[4], payload[5])
        })
    }

    pub fn get_name(&self) -> Option<String> {
        use std::ffi::CStr;
        self.with_rta(IFLA_IFNAME, |rta| {
            let payload = rta.payload();
            let cstr = CStr::from_bytes_with_nul(rta.payload()).unwrap();
            cstr.to_owned().into_string().unwrap()
        })
    }

    // helper methods
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

    fn with_rta<T,F>(&self, rta_type: u16, cb: F) -> Option<T>
        where F: Fn(RtAttrPacket) -> T {
        self.with_rta_iter(|mut rti| {
            rti.find(|rta| rta.get_rta_type() == rta_type).map(|rta| cb(rta))
        })
    }


    // static methods
    fn get_links_iter<R: Read>(r: NetlinkBufIterator<R>) -> LinksIterator<R> {
        //let mut conn = NetlinkConnection::new();
        //let mut buf = [0; 32];
        //let mut reply = conn.send(Self::dump_links_request(&mut buf));
        LinksIterator { iter: r }
    }

    fn dump_link(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWLINK {
            return;
        }
        println!("NetLink pkt {:?}", msg);
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
fn find_lo() {
    let mut conn = NetlinkConnection::new();
    let mut links = LinkManager::new(&mut conn);
    let lo0 = links.get_link_by_name("lo");
    assert!(lo0.is_some());
    let lo0 = lo0.unwrap();
    let idx = lo0.get_index();
    let lo1 = links.get_link_by_index(idx);
    assert!(lo1.is_some());
    let lo1 = lo1.unwrap();
    assert!(lo1.get_name() == lo0.get_name());
}

#[test]
// root permissions required
fn create_and_delete_link() {
    let mut conn = NetlinkConnection::new();
    let mut links = LinkManager::new(&mut conn);
    let link = links.new_dummy_link("test1488");
    let link = link.unwrap();
    assert!(link.get_name() == Some("test1488".to_owned()));
    links.iter_links().find(|link| link.get_name() == Some("test1488".to_owned())).is_some();
    links.delete(link);
    links.iter_links().find(|link| link.get_name() == Some("test1488".to_owned())).is_none();
}