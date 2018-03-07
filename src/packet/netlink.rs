//! Netlink packet handling
use ::socket::{NetlinkSocket,NetlinkProtocol};
use libc;
use std::io;
use std::io::{Read,BufRead,BufReader,Write};
use std::marker::PhantomData;
use pnet::packet::{Packet,PacketSize,FromPacket};

include!(concat!(env!("OUT_DIR"), "/netlink.rs"));

bitflags! {
    pub struct NetlinkMsgFlags: u16 {
        /* It is request message. 	*/
        const NLM_F_REQUEST = 1;
        /* Multipart message, terminated by NLMSG_DONE */
        const NLM_F_MULTI = 2;
        /* Reply with ack, with zero or error code */
        const NLM_F_ACK = 4;
        /* Echo this request 		*/
        const NLM_F_ECHO = 8;
        /* Dump was inconsistent due to sequence change */
        const NLM_F_DUMP_INTR = 16;

        /* Modifiers to GET request */
        const NLM_F_ROOT =	0x100;	/* specify tree	root	*/
        const NLM_F_MATCH = 0x200;	/* return all matching	*/
        const NLM_F_ATOMIC = 0x400;	/* atomic GET		*/
        const NLM_F_DUMP =	(Self::NLM_F_ROOT.bits | Self::NLM_F_MATCH.bits);

        /* Modifiers to NEW request */
        const NLM_F_REPLACE = 0x100;   /* Override existing            */
        const NLM_F_EXCL =    0x200;   /* Do not touch, if it exists   */
        const NLM_F_CREATE =  0x400;   /* Create, if it does not exist */
        const NLM_F_APPEND =  0x800;   /* Add to end of list           */
    }
}

impl NetlinkMsgFlags {
    pub fn new(val: u16) -> Self {
        NetlinkMsgFlags::from_bits_truncate(val)
    }
}

/* message types */
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;


impl<'a> NetlinkIterable<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        NetlinkIterable { buf: buf }
    }
}

#[test]
fn read_ip_link_dump() {
    use std::fs::File;
    use std::io::prelude;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::io::Read;

    let f = File::open("dumps/ip_link.bin").unwrap();
    let mut r = BufReader::new(f);
    let mut data = vec![];
    r.read_to_end(&mut data).unwrap();

    let it = NetlinkIterable::new(&data);
    for pkt in it {
        println!("{:?}", pkt);
    }
}

#[test]
fn read_ip_link_dump_2() {
    use std::fs::File;
    use std::io::prelude;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::io::Read;

    let f = File::open("dumps/ip_link.bin").unwrap();
    let mut r = BufReader::new(f);
    let mut reader = NetlinkReader::new(&mut r);
    while let Ok(Some(pkt)) = reader.read_netlink() {
        println!("{:?}", pkt);
        if pkt.get_kind() == NLMSG_DONE {
            break;
        }
    }
}

#[test]
fn read_ip_link_sock() {
    use std::fs::File;
    use std::io::prelude;
    use std::io::BufReader;
    use std::io::BufRead;
    use std::io::Read;

    let mut r = NetlinkSocket::bind(NetlinkProtocol::Route, 0 as u32).unwrap();
    let mut reader = NetlinkReader::new(&mut r);
    while let Ok(Some(pkt)) = reader.read_netlink() {
        println!("{:?}", pkt);
    }
}

/// Netlink packet parser
pub struct NetlinkReader<R: Read> {
    reader: R,
    buf: Vec<u8>,
    read_at: usize,
    state: NetlinkReaderState,
}

enum NetlinkReaderState {
    Done,
    NeedMore,
    Error,
    Parsing,
}

impl<R: Read> NetlinkReader<R> {
    pub fn new(reader: R) -> Self {
        NetlinkReader {
            reader: reader,
            buf: vec![],
            read_at: 0,
            state: NetlinkReaderState::NeedMore,
        }
    }

    /// Read to end ignoring everything but errors
    pub fn read_to_end(self) -> io::Result<()> {
        for pkt in self.into_iter() {
            if let Some(err) = pkt.to_io_error() {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl<R: Read> ::std::iter::IntoIterator for NetlinkReader<R> {
    type Item = NetlinkPacket<'static>;
    type IntoIter = NetlinkBufIterator<R>;

    fn into_iter(self) -> Self::IntoIter {
        NetlinkBufIterator { reader: self }
    }
}

impl<R: Read> NetlinkReader<R> {
    pub fn read_netlink(&mut self) -> io::Result<Option<NetlinkPacket<'static>>> {
        loop {
            match self.state {
                NetlinkReaderState::NeedMore => {
                    let mut buf = [0; 4096];
                    match self.reader.read(&mut buf) {
                        Ok(0) => {
                            self.state = NetlinkReaderState::Done;
                            return Ok(None);
                        },
                        Ok(len) =>{
                            self.buf.extend_from_slice(&buf[0..len]);
                        },
                        Err(e) => {
                            self.state = NetlinkReaderState::Error;
                            return Err(e);
                        }
                    }
                },
                NetlinkReaderState::Done => return Ok(None),
                NetlinkReaderState::Error => return Ok(None),
                NetlinkReaderState::Parsing => { },
            }
            loop {
                if let Some(pkt) = NetlinkPacket::new(&self.buf[self.read_at..]) {
                    let len = ::util::align(pkt.get_length() as usize);
                    if len == 0 {
                        return Ok(None);
                    }
                    match pkt.get_kind() {
                        NLMSG_ERROR => {
                            self.state = NetlinkReaderState::Error;
                        },
                        NLMSG_OVERRUN => {
                            panic!("overrun!");
                        },
                        NLMSG_DONE => {
                            self.state = NetlinkReaderState::Done;
                        },
                        NLMSG_NOOP => {
                            println!("noop")
                        },
                        _ => {
                            self.state = NetlinkReaderState::Parsing;
                        },
                    }
                    let slot = NetlinkPacket::owned(self.buf[self.read_at..self.read_at + pkt.get_length() as usize].to_owned()).unwrap();
                    self.read_at += len;
                    return Ok(Some(slot));
                } else {
                    self.state = NetlinkReaderState::NeedMore;
                    break;
                }
            }
        }
    }
}

pub struct NetlinkBufIterator<R: Read> {
    reader: NetlinkReader<R>,
}

impl<R: Read> Iterator for NetlinkBufIterator<R> {
    type Item = NetlinkPacket<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_netlink() {
            Ok(Some(slot)) => Some(slot),
            _ => None,
        }
    }
}

/// NetlinkConnection represents active netlink connection
pub struct NetlinkConnection {
    sock: NetlinkSocket,
}

impl From<NetlinkSocket> for NetlinkConnection {
    fn from(sock: NetlinkSocket) -> Self {
        NetlinkConnection { sock: sock }
    }
}

impl NetlinkConnection {
    pub fn new() -> Self {
        NetlinkConnection {
            sock: NetlinkSocket::bind(NetlinkProtocol::Route, 0 as u32).unwrap(),
        }
    }

    pub fn send<'a,'b>(&'a mut self, msg: NetlinkPacket<'b>) -> NetlinkReader<&'a mut NetlinkConnection> {
        self.sock.send(msg.packet()).unwrap();
        NetlinkReader::new(self)
    }
}

impl ::std::io::Read for NetlinkConnection {
    fn read(&mut self, buf: &mut [u8]) -> ::std::io::Result<usize> {
        self.sock.read(buf)
    }
}

impl ::std::io::Write for NetlinkConnection {
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        self.sock.send(buf)
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        Ok(())
    }
}

/// NetlinkRequestBuilder provides functions
/// for building Netlink requests
pub struct NetlinkRequestBuilder {
    data: Vec<u8>,
}

impl NetlinkRequestBuilder {
    /// Creates an empty request with flags `flags`
    /// `NLM_F_REQUEST` is set automatically
    pub fn new(kind: u16, flags: NetlinkMsgFlags) -> Self {
        let len = MutableNetlinkPacket::minimum_packet_size();
        let mut data = vec![0; len];
        {
            let mut pkt = MutableNetlinkPacket::new(&mut data).unwrap();
            pkt.set_length(len as u32);
            pkt.set_kind(kind);
            pkt.set_flags(flags | NetlinkMsgFlags::NLM_F_REQUEST);
        }
        NetlinkRequestBuilder {
            data: data,
        }
    }

    /// Appends `data` to Netlink header. Alignment is handled 
    /// automatically.
    pub fn append<P: PacketSize + Packet>(mut self, data: P) -> Self {
        let data = data.packet();
        let len = data.len();
        let aligned_len = ::util::align(len as usize);
        {
            let mut pkt = MutableNetlinkPacket::new(&mut self.data).unwrap();
            let new_len = pkt.get_length() + aligned_len as u32;
            pkt.set_length(new_len as u32);
        }
        self.data.extend_from_slice(data);
        // add padding for alignment
        for _ in len..aligned_len {
            self.data.push(0);
        }
        self
    }

    /// Returns final packet
    pub fn build(self) -> NetlinkPacket<'static> {
        NetlinkPacket::owned(self.data).unwrap()
    }
}

pub trait ToIoError {
    fn to_io_error(&self) -> Option<io::Error>;
}

impl<'a> ToIoError for NetlinkPacket<'a> {
    fn to_io_error(&self) -> Option<io::Error> {
        if self.get_kind() == NLMSG_ERROR {
            let err = NetlinkErrorPacket::new(self.payload()).unwrap();
            if err.get_error() != 0 {
                return Some(io::Error::from_raw_os_error(-(err.get_error() as i32)));
            }
        }

        None
    }
}
