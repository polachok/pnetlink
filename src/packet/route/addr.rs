use packet::route::{MutableIfInfoPacket,IfAddrPacket,MutableIfAddrPacket,RtAttrIterator,RtAttrPacket,MutableRtAttrPacket,RtAttrMtuPacket};
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
use std::io::{Read,self};

pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;


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
                let kind = pkt.get_packet().get_kind();
                if kind != RTM_NEWADDR {
                    return None;
                }
                return Some(Addr { packet: pkt });
            },
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct Addr {
    packet: NetlinkBuf,
}

impl Addr {
    fn dump_addr(msg: NetlinkPacket) {
        use std::ffi::CStr;
        if msg.get_kind() != RTM_NEWADDR {
            return;
        }
        println!("NetLink pkt {:?}", msg);
        if let Some(ifa) = IfAddrPacket::new(&msg.payload()[0..]) {
            println!("├ ifa: {:?}", ifa);
            let payload = &ifa.payload()[0..];
            let iter = RtAttrIterator::new(payload);
            for rta in iter {
                match rta.get_rta_type() {
                    IFA_ADDRESS => {
                        println!(" ├ ADDR: {:?}", rta.payload());
                    },
                    IFA_LOCAL => {
                        println!(" ├ LOCAL: {:?}", rta.payload());
                    },
                    IFA_BROADCAST => {
                        println!(" ├ BROADCAST: {:?}", rta.payload());
                    },
                    IFA_LABEL => {
                        println!(" ├ LABEL: {:?}", CStr::from_bytes_with_nul(rta.payload()));
                    },
                    IFA_CACHEINFO => {
                        println!(" ├ CACHEINFO: {:?}", rta.payload());
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
        let mut reply = conn.send(req.get_packet());
        AddrsIterator { iter: reply.into_iter() }
    }
}

#[test]
fn dump_addrs() {
    let mut conn = NetlinkConnection::new();
    for addr in Addr::iter_addrs(&mut conn) {
        Addr::dump_addr(addr.packet.get_packet());
    }
}