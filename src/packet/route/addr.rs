use packet::route::{IfAddrCacheInfoPacket,MutableIfInfoPacket,IfAddrPacket,MutableIfAddrPacket,RtAttrIterator,RtAttrPacket,MutableRtAttrPacket,RtAttrMtuPacket};
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
use std::io::{Read,Write,Cursor,self};
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
use std::net::{Ipv4Addr,Ipv6Addr};

pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;

/* rtm_scope

   Really it is not scope, but sort of distance to the destination.
   NOWHERE are reserved for not existing destinations, HOST is our
   local addresses, LINK are destinations, located on directly attached
   link and UNIVERSE is everywhere in the Universe.

   Intermediate values are also possible f.e. interior routes
   could be assigned a value between UNIVERSE and LINK.
*/
#[derive(Debug,Copy,Clone)]
#[repr(u8)]
pub enum Scope {
    Global=0,
    /* User defined values  */
    Site=200,
    Link=253,
    Host=254,
    Nowhere=255
}

impl Scope {
    pub fn new(val: u8) -> Self {
        use std::mem;
        unsafe { mem::transmute(val) }
    }
}

/* link flags */
bitflags! {
    pub flags IfAddrFlags: u8 {
        const SECONDARY = 0x01,
        const TEMPORARY = SECONDARY.bits,
        const NODAD = 0x02,
        const OPTIMISTIC = 0x04,
        const DADFAILED = 0x08,
        const HOMEADDRESS = 0x10,
        const DEPRECATED = 0x20,
        const TENTATIVE = 0x40,
        const PERMANENT = 0x80,
    }
}

impl IfAddrFlags {
    pub fn new(val: u8) -> Self {
        IfAddrFlags::from_bits_truncate(val)
    }
}

/* Important comment:
 * IFA_ADDRESS is prefix address, rather than local interface address.
 * It makes no difference for normally configured broadcast interfaces,
 * but for point-to-point IFA_ADDRESS is DESTINATION address,
 * local address is supplied in IFA_LOCAL attribute.
 */

pub const IFA_UNSPEC: u16 = 0;
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_BROADCAST: u16 = 4;
pub const IFA_ANYCAST: u16 = 5;
pub const IFA_CACHEINFO: u16 = 6;
pub const IFA_MULTICAST: u16 = 7;

pub struct AddrsIterator<R: Read> {
    iter: NetlinkBufIterator<R>,
}

impl<R: Read> Iterator for AddrsIterator<R> {
    type Item = Addr;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(pkt) => {
                let kind = pkt.get_kind();
                if kind != RTM_NEWADDR {
                    return None;
                }
                return Some(Addr { packet: pkt });
            },
            None => None,
        }
    }
}

/// Abstract over IP versions
#[derive(Eq,PartialEq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddr {
    fn bytes(&self) -> Vec<u8> {
        match self {
            &IpAddr::V4(ip) => {
                let mut v = Vec::new();
                v.extend_from_slice(&ip.octets()[..]);
                v
            },
            &IpAddr::V6(ip) => {
                panic!("not implemented"); /* FIXME */
            }
        }
    }
}

impl From<Ipv6Addr> for IpAddr {
    fn from(addr: Ipv6Addr) -> Self {
        IpAddr::V6(addr)
    }
}

impl From<Ipv4Addr> for IpAddr {
    fn from(addr: Ipv4Addr) -> Self {
        IpAddr::V4(addr)
    }
}

impl ::std::fmt::Debug for IpAddr {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            &IpAddr::V4(ip) => ip.fmt(f),
            &IpAddr::V6(ip) => ip.fmt(f),
        }
    }
}

pub trait Addresses where Self: Read + Write {
    fn iter_addrs<'a>(&'a mut self, family: Option<u8>) -> io::Result<Box<Iterator<Item = Addr> + 'a>>;
    fn get_link_addrs<'a,'b>(&'a mut self, family: Option<u8>, link: &'b Link) -> io::Result<Box<Iterator<Item = Addr> + 'a>>;
    fn add_addr<'a,'b>(&'a mut self, link: &'b Link, addr: IpAddr, scope: Scope) -> io::Result<()>;
}

impl Addresses for NetlinkConnection {
    fn iter_addrs<'a>(&'a mut self, family: Option<u8>) -> io::Result<Box<Iterator<Item = Addr> + 'a>> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETADDR, NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(family.unwrap_or(0));
                ifinfo
            }).build();
        try!(self.write(req.packet()));
        let reader = NetlinkReader::new(self);
        let iter = AddrsIterator { iter: reader.into_iter() };
        Ok(Box::new(iter))
    }

    fn get_link_addrs<'a,'b>(&'a mut self, family: Option<u8>, link: &'b Link) -> io::Result<Box<Iterator<Item = Addr> + 'a>> {
        let idx = link.get_index();
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETADDR, NLM_F_DUMP)
            .append({
                let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
                ifinfo.set_family(family.unwrap_or(0));
                ifinfo
            }).build();
        try!(self.write(req.packet()));
        let reader = NetlinkReader::new(self);
        let iter = AddrsIterator { iter: reader.into_iter() };
        Ok(Box::new(iter.filter(move |addr| addr.with_ifaddr(|ifa| ifa.get_index() == idx))))
    }

    fn add_addr<'a,'b>(&'a mut self, link: &'b Link, addr: IpAddr, scope: Scope) -> io::Result<()> {
        let link_index = link.get_index();
        let family = match addr {
            IpAddr::V4(_) => 2,
            IpAddr::V6(_) => 10,
        };
        let prefix_len = 32; /* XXX: FIXME */
        let mut buf = vec![0; MutableIfAddrPacket::minimum_packet_size()];
        let mut rta_buf = vec![0; MutableRtAttrPacket::minimum_packet_size() + 4];
        let mut rta_buf1 = vec![0; MutableRtAttrPacket::minimum_packet_size() + 4];
        let req = IfAddrRequestBuilder::new().with_ifa(|mut ifaddr| {
                ifaddr.set_index(link_index);
                ifaddr.set_family(family);
                ifaddr.set_scope(scope);
                ifaddr.set_prefix_len(prefix_len);
        }).append({
            {
                let mut pkt = MutableRtAttrPacket::new(&mut rta_buf).unwrap();
                pkt.set_rta_len(4 + 4 /* FIXME: hardcoded ipv4 */);
                pkt.set_rta_type(IFA_ADDRESS);
                let mut pl = pkt.payload_mut();
                pl.copy_from_slice(&addr.bytes()[0..4]);
            }
            RtAttrPacket::new(&mut rta_buf).unwrap()
        }).append({
            {
                let mut pkt = MutableRtAttrPacket::new(&mut rta_buf1).unwrap();
                pkt.set_rta_len(4 + 4 /* FIXME: hardcoded ipv4 */);
                pkt.set_rta_type(IFA_LOCAL);
                let mut pl = pkt.payload_mut();
                pl.copy_from_slice(&addr.bytes()[0..4]);
            }
            RtAttrPacket::new(&mut rta_buf1).unwrap()
        }).build();
        let req = NetlinkRequestBuilder::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK)
            .append(req.get_packet()).build();
        self.write(req.packet());
        let reader = NetlinkReader::new(self);
        reader.read_to_end()
    }
}

#[derive(Debug)]
pub struct Addr {
    packet: NetlinkPacket<'static>,
}

impl Addr {
    pub fn get_family(&self) -> u8 {
        self.with_ifaddr(|ifa| ifa.get_family())
    }

    pub fn get_flags(&self) -> IfAddrFlags {
        self.with_ifaddr(|ifa| ifa.get_flags())
    }

    pub fn get_prefix_len(&self) -> u8 {
        self.with_ifaddr(|ifa| ifa.get_prefix_len())
    }

    pub fn get_scope(&self) -> Scope {
        self.with_ifaddr(|ifa| ifa.get_scope())
    }

    pub fn get_link_index(&self) -> u32 {
        self.with_ifaddr(|ifa| ifa.get_index())
    }

    /// Get address
    ///
    /// This is prefix address, rather than local interface address.
    /// It makes no difference for normally configured broadcast interfaces,
    /// but for point-to-point it is DESTINATION address,
    /// local address is supplied by get_local_ip().
    ///
    pub fn get_ip(&self) -> Option<IpAddr> {
        let family = self.with_ifaddr(|ifa| ifa.get_family());
        self.with_rta(IFA_ADDRESS, |rta| {
            Self::ip_from_family_and_bytes(family, rta.payload())
        })
    }

    /// See get_ip()
    pub fn get_local_ip(&self) -> Option<IpAddr> {
        let family = self.with_ifaddr(|ifa| ifa.get_family());
        self.with_rta(IFA_LOCAL, |rta| {
            Self::ip_from_family_and_bytes(family, rta.payload())
        })
    }

    pub fn get_broadcast_ip(&self) -> Option<IpAddr> {
        let family = self.with_ifaddr(|ifa| ifa.get_family());
        self.with_rta(IFA_BROADCAST, |rta| {
            Self::ip_from_family_and_bytes(family, rta.payload())
        })
    }

    pub fn get_label(&self) -> Option<String> {
        use std::ffi::CStr;
        self.with_rta(IFA_LABEL, |rta| {
            let cstr = CStr::from_bytes_with_nul(rta.payload()).unwrap();
            cstr.to_owned().into_string().unwrap()
        })
    }

    /* TODO: implement get_cache_info() */

    // helper methods
    fn with_packet<T,F>(&self, cb: F) -> T
        where F: Fn(&NetlinkPacket) -> T {
        cb(&self.packet)
    }

    fn with_ifaddr<T,F>(&self, cb: F) -> T
        where F: Fn(IfAddrPacket) -> T {
        self.with_packet(|pkt|
            cb(IfAddrPacket::new(pkt.payload()).unwrap())
        )
    }

    fn with_rta_iter<T,F>(&self, cb: F) -> T
        where F: Fn(RtAttrIterator) -> T {
            self.with_ifaddr(|ifa| {
                cb(RtAttrIterator::new(ifa.payload()))
            })
    }

    fn with_rta<T,F>(&self, rta_type: u16, cb: F) -> Option<T>
        where F: Fn(RtAttrPacket) -> T {
        self.with_rta_iter(|mut rti| {
            rti.find(|rta| rta.get_rta_type() == rta_type).map(|rta| cb(rta))
        })
    }

    /// Extract an IP address from a buffer.
    pub fn ip_from_family_and_bytes(family: u8, bytes: &[u8]) -> IpAddr {
        let mut cur = Cursor::new(bytes);
        match family {
            2 /* AF_INET */ => IpAddr::V4(Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap())),
            10 /* AF_INET6 */ => {
                let mut ip6addr: [u8;16] = [0;16];
                &mut ip6addr[..].copy_from_slice(bytes);
                IpAddr::V6(Ipv6Addr::from(ip6addr))
            },
            _ => {
                panic!("not implemented")
            }
        }
    }

    fn dump_addr(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWADDR {
            return;
        }
        //println!("NetLink pkt {:?}", msg);
        if let Some(ifa) = IfAddrPacket::new(&msg.payload()[0..]) {
            println!("├ ifa: {:?}", ifa);
            let payload = &ifa.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match rta.get_rta_type() {
                    IFA_ADDRESS | IFA_LOCAL | IFA_BROADCAST => {
                        let mut cur = Cursor::new(rta.payload());
                        match rta.get_rta_type() {
                            IFA_ADDRESS => print!(" ├ ADDR: "),
                            IFA_LOCAL => print!(" ├ LOCAL: "),
                            IFA_BROADCAST => print!(" ├ BROADCAST: "),
                            _ => unreachable!(),
                        }
                        match ifa.get_family() {
                            2 => {
                                println!("{}", Ipv4Addr::from(cur.read_u32::<BigEndian>().unwrap()));
                            },
                            10 => {
                                let mut ip6addr: [u8;16] = [0;16];
                                &mut ip6addr[..].copy_from_slice(rta.payload());
                                println!("{}", Ipv6Addr::from(ip6addr));
                            },
                            _ => {
                                println!("{:?}", rta.payload());
                            }
                        }
                    },
                    /*
                    IFA_LOCAL => {
                        println!(" ├ LOCAL: {:?}", rta.payload());
                    },
                    IFA_BROADCAST => {
                        println!(" ├ BROADCAST: {:?}", rta.payload());
                    },
                    */
                    IFA_LABEL => {
                        println!(" ├ LABEL: {:?}", CStr::from_bytes_with_nul(rta.payload()));
                    },
                    IFA_CACHEINFO => {
                        println!(" ├ CACHEINFO: {:?}", IfAddrCacheInfoPacket::new(rta.payload()).unwrap());
                    },
                    _ => println!(" ├ {:?}", rta),
                }
            }
        }
    }

    pub fn iter_addrs(conn: &mut NetlinkConnection) -> AddrsIterator<&mut NetlinkConnection> {
        let mut buf = vec![0; MutableIfInfoPacket::minimum_packet_size()];
        let req = NetlinkRequestBuilder::new(RTM_GETADDR, NLM_F_DUMP)
        .append({
            let mut ifinfo = MutableIfInfoPacket::new(&mut buf).unwrap();
            ifinfo.set_family(0 /* AF_UNSPEC */);
            ifinfo
        }).build();
        let mut reply = conn.send(req);
        AddrsIterator { iter: reply.into_iter() }
    }
}

struct IfAddrPacketBuf {
    data: Vec<u8>,
}

impl IfAddrPacketBuf {
    pub fn get_packet(&self) -> IfAddrPacket {
        IfAddrPacket::new(&self.data[..]).unwrap()
    }
}

struct IfAddrRequestBuilder {
    data: Vec<u8>,
}

impl IfAddrRequestBuilder {
    pub fn new() -> Self {
        let data = vec![0; MutableIfAddrPacket::minimum_packet_size()];
        IfAddrRequestBuilder { data: data }
    }

    pub fn with_ifa<F>(mut self, f: F) -> Self
        where F: Fn(MutableIfAddrPacket) -> () {
        {
            let pkt = MutableIfAddrPacket::new(&mut self.data[..]).unwrap();
            f(pkt);
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

    pub fn build(self) -> IfAddrPacketBuf {
        IfAddrPacketBuf { data: self.data }
    }
}

#[test]
fn dump_addrs() {
    use packet::netlink::NetlinkConnection;
    use packet::route::addr::Addresses;

    let mut conn = NetlinkConnection::new();
    for addr in conn.iter_addrs(None).unwrap() {
        Addr::dump_addr(addr.packet.get_packet());
    }
}

/*
#[test]
fn check_lo_addr() {
    use packet::route::link::LinkManager;
    let mut conn = NetlinkConnection::new();
    let lo = LinkManager::new(&mut conn).get_link_by_name("lo").unwrap();
    let mut addrs = AddrManager::new(&mut conn);
    let mut addrs = addrs.get_link_addrs(&lo);
    assert!(addrs.find(|addr| addr.get_ip() == Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))).is_some());
}

#[test]
fn add_lo_addr() {
     use packet::route::link::LinkManager;
    let mut conn = NetlinkConnection::new();
    let lo = LinkManager::new(&mut conn).get_link_by_name("lo").unwrap();
    let mut addrman = AddrManager::new(&mut conn);
    /*
    {
        let mut addrs = addrman.get_link_addrs(&lo);
        assert!(addrs.find(|addr| addr.get_ip() == Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))).is_some());
    }
    */
    addrman.add_addr(&lo, IpAddr::from(Ipv4Addr::new(127, 0, 0, 5)), Scope::Host);
    /*
    {
        let mut addrs = addrman.get_link_addrs(&lo);
        assert!(addrs.find(|addr| addr.get_ip() == Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)))).is_some());
    }
    */
}
*/
