extern crate pnet;
extern crate pnet_macros_support;
extern crate libc;

mod socket;
mod route;
mod packet;

#[test]
fn netlink_route() {
    use packet::netlink::{MutableNetlinkPacket,NetlinkPacket};
    use packet::route::{MutableIfInfoPacket,IfInfoPacket};
    use packet::route::RtAttrPacket;
    use packet::netlink::{NLM_F_REQUEST, NLM_F_DUMP};
    use packet::netlink::{NLMSG_NOOP,NLMSG_ERROR,NLMSG_DONE,NLMSG_OVERRUN};
    use packet::route::{RTM_GETLINK,RTM_NEWLINK,IFLA_IFNAME,IFLA_ADDRESS,IFLA_LINKINFO};
    use socket::{NetlinkSocket,NetlinkProtocol};
    use pnet::packet::MutablePacket;
    use pnet::packet::Packet;
    use pnet::packet::PacketSize;
    use std::ffi::CStr;

    let mut sock = NetlinkSocket::bind(NetlinkProtocol::Route, 0 as u32).unwrap();
    let mut buf = [0; 1024];
    {
        let mut pkt = MutableNetlinkPacket::new(&mut buf).unwrap();
        pkt.set_length(MutableNetlinkPacket::minimum_packet_size() as u32 + 
                MutableIfInfoPacket::minimum_packet_size() as u32);
        pkt.set_flags(NLM_F_REQUEST | NLM_F_DUMP/*| flags */);
        pkt.set_kind(RTM_GETLINK);
        let mut ifinfo_buf = pkt.payload_mut();
        let mut ifinfo = MutableIfInfoPacket::new(&mut ifinfo_buf).unwrap();
        ifinfo.set_family(0 /* AF_UNSPEC */);
    }
    fn align(len: usize) -> usize {
        const RTA_ALIGNTO: usize = 4;
        ((len)+RTA_ALIGNTO-1) & !(RTA_ALIGNTO-1)
    }
    sock.send(&buf[0..32]);
    'done: loop {
    let mut rcvbuf = [0; 4096];
    let mut big_buff = vec![0; 4096];
    if let Ok(len) = sock.recv(&mut rcvbuf) {
        if len == 0 {
            break;
        }
        let mut nl_payload = &rcvbuf[0..len];
        //println!("{:?}", nl_payload);
        big_buff.extend_from_slice(&nl_payload[..]);
        let mut pkt_idx = 0;
        loop {
            //println!("PKT IDX: {}", pkt_idx);
            if let Some(msg) = NetlinkPacket::new(nl_payload) {
                let pid = unsafe { libc::getpid() } as u32;
                let kind = msg.get_kind();
                match kind {
                    NLMSG_NOOP => { println!("noop") },
                    NLMSG_ERROR => { println!("err") },
                    NLMSG_DONE => { println!("done"); break 'done; },
                    NLMSG_OVERRUN => { println!("overrun") },
                    _ => {},
                }
                pkt_idx = align(msg.get_length() as usize);
                if pkt_idx == 0 {
                    break;
                }
                nl_payload = &nl_payload[pkt_idx..];

                println!("{:?} {}", msg, pid);

                if msg.get_pid() != pid {
                    println!("wrong pid!");
                    continue;
                }
                if msg.get_kind() != RTM_NEWLINK {
                    println!("bad type!");
                    continue;
                }
            
                if let Some(ifi) = IfInfoPacket::new(&msg.payload()[0..]) {
                    println!("├ ifi: {:?}", ifi);
                    let mut payload = &ifi.payload()[0..];
                    let total_len = payload.len();
                    let mut idx = 0;
                    loop {
                        if let Some(rta) = RtAttrPacket::new(payload) {
                            let len = rta.get_rta_len() as usize;
                            //println!("RTA LEN: {}, TOTAL: {}", len, total_len - idx);
                            if len > total_len - idx || len < 4 {
                                break;
                            }
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
                                _ => {
                                    println!(" ├ {:?}", rta);
                                },
                            }
                            let mut align = align(len);
                            idx += align;
                            payload = &payload[align..];
                        } else {
                            //println!("CANT PARSE RTATTR");
                            break;
                        }
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
    }
}
