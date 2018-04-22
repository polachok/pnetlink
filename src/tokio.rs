use bytes::BytesMut;
use futures::{Future, Poll, Async};
use std::io;
use tokio_core::reactor::{Handle, PollEvented};
use tokio_io;
use ::socket;
use ::packet::netlink::{NetlinkPacket,MutableNetlinkPacket,NetlinkMsgFlags,self};
use ::packet::route::{IfInfoPacket,MutableIfInfoPacket};
use pnet::packet::{Packet,PacketSize,FromPacket};

pub struct NetlinkSocket {
    io: PollEvented<::socket::NetlinkSocket>,
}

impl NetlinkSocket {
    pub fn bind(proto: socket::NetlinkProtocol, groups: u32, handle: &Handle) -> io::Result<NetlinkSocket> {
        let sock = try!(socket::NetlinkSocket::bind(proto, groups));
        NetlinkSocket::new(sock, handle)
    }

    fn new(socket: ::socket::NetlinkSocket, handle: &Handle) -> io::Result<NetlinkSocket> {
        let io = try!(PollEvented::new(socket, handle));
        Ok(NetlinkSocket { io: io })
    }

    /// Test whether this socket is ready to be read or not.
    pub fn poll_read(&self) -> Async<()> {
        self.io.poll_read()
    }

    /// Test whether this socket is writey to be written to or not.
    pub fn poll_write(&self) -> Async<()> {
        self.io.poll_write()
    }
}

impl io::Read for NetlinkSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.read(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        buf.resize(4096, 0);
        let mut write_at = 0;
        loop {
            match self.read(&mut buf[write_at..]) {
                Ok(n) => {
                    write_at += n;
                },
                Err(e) => {
                    buf.truncate(write_at);
                    return Err(e);
                }
            }
        }
        buf.truncate(write_at);
        return Ok(write_at);
    }
}

impl io::Write for NetlinkSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

pub struct NetlinkCodec {}

impl tokio_io::AsyncRead for NetlinkSocket {
}

impl tokio_io::AsyncWrite for NetlinkSocket {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        Ok(().into())
    }
}


impl tokio_io::codec::Decoder for NetlinkCodec {
    type Item = NetlinkPacket<'static>;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Self::Item>> {
        let (owned_pkt, len) = {
            if buf.len() == 0 {
                return Ok(None);
            }
            if let Some(pkt) = NetlinkPacket::new(buf) {
                let aligned_len = ::util::align(pkt.get_length() as usize);
                if aligned_len > buf.len() {
                    // need more bytes
                    return Ok(None);
                }
                (NetlinkPacket::owned(buf[..pkt.get_length() as usize].to_owned()), aligned_len)
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed netlink packet"))
            }
        };
        buf.drain_to(len as usize);
        return Ok(owned_pkt);
    }
}

impl tokio_io::codec::Encoder for NetlinkCodec {
    type Item = NetlinkPacket<'static>;
    type Error = io::Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> io::Result<()> {
        let data = msg.packet();
        buf.extend_from_slice(data);
        Ok(())
    }
}

pub struct NetlinkRequestBuilder {
    data: Vec<u8>,
}

impl NetlinkRequestBuilder {
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

    pub fn append<P: PacketSize + Packet>(mut self, data: P) -> Self {
        let data = data.packet();
        let len = data.len();
        let aligned_len = ::util::align(len as usize);
        {
            let mut pkt = MutableNetlinkPacket::new(&mut self.data).unwrap();
            let new_len = pkt.get_length() + len as u32;
            pkt.set_length(new_len as u32);
        }
        self.data.extend_from_slice(data);
        // add padding for alignment
        for _ in len..aligned_len {
            self.data.push(0);
        }
        self
    }

    pub fn build(self) -> NetlinkPacket<'static> {
        NetlinkPacket::owned(self.data).unwrap()
    }
}


#[test]
fn try_tokio_conn() {
    use tokio_core::reactor::Core;
    use futures::{Sink,Stream,Future};
    use ::packet::route::link::Link;

    let mut l = Core::new().unwrap();
    let handle = l.handle();
    let sock = NetlinkSocket::bind(socket::NetlinkProtocol::Route, 0, &handle).unwrap();
    println!("Netlink socket bound");
    let framed = tokio_io::AsyncRead::framed(sock, NetlinkCodec {});

    let pkt = NetlinkRequestBuilder::new(18 /* RTM GETLINK */, NetlinkMsgFlags::NLM_F_DUMP).append(
        {
            let len = MutableIfInfoPacket::minimum_packet_size();
            let mut data = vec![0; len];
            MutableIfInfoPacket::owned(data).unwrap()
        }
    ).build();
    /*
    let f = framed.send(pkt).and_then(|s|
        s.into_future().map_err(|(e, _)| {
        println!("E: {:?}", e);
        e
    } ))
    .and_then(|(frame, stream)| {
         println!("RECEIVED FRAME: {:?}", frame); Ok(stream)
    });
    */
    let f = framed.send(pkt).and_then(|stream|
        stream.for_each(|frame| {
            println!("RECEIVED FRAME: {:?}", frame);
            if frame.get_kind() == 16 /* NEW LINK */ {
                Link::dump_link(frame);
            }
            Ok(())
        })
    );
    let s = l.run(f);
}

#[test]
fn try_mio_conn() {
    use mio::*;

    let poll = Poll::new().unwrap();
    let mut sock = socket::NetlinkSocket::bind(socket::NetlinkProtocol::Route, 0).unwrap();
    poll.register(&sock, Token(0), Ready::writable() | Ready::readable(),
              PollOpt::edge()).unwrap();

    let pkt = NetlinkRequestBuilder::new(18 /* RTM GETLINK */, NetlinkMsgFlags::NLM_F_DUMP).append(
        {
            let len = MutableIfInfoPacket::minimum_packet_size();
            let mut data = vec![0; len];
            MutableIfInfoPacket::owned(data).unwrap()
        }
    ).build();

    let mut buf = vec![0;4096];
    let mut pos: usize = 0;
    let mut events = Events::with_capacity(1024);
    let mut written = false;
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                Token(0) => {
                    println!("EVENT: {:?}", event);
                    if event.kind() == Ready::writable() {
                        use std::io::Write;
                        if !written {
                            println!("WRITABLE");
                            sock.write(pkt.packet()).unwrap();
                            written = true;
                        }
                    }
                    if event.kind() & Ready::readable() == Ready::readable() {
                        use std::io::Read;
                        println!("Reading");
                        'read: loop {
                            match sock.read(&mut buf[pos..]) {
                                Ok(n) => {
                                    if n == 0 {
                                        break 'read;
                                    }
                                    pos += n;
                                    println!("read {}", n);
                                    if pos >= buf.len() - 1 {
                                        println!("Growing buf: len: {} pos: {}", buf.len(), pos);
                                        for _ in 0..buf.len() {
                                            buf.push(0);
                                        }
                                        println!("Growing buf: new len: {} pos: {}", buf.len(), pos);
                                    }
                                },
                                Err(e) => {
                                     println!("err: {:?}", e);
                                     break 'read;
                                },
                            }
                        }
                        if let Some(pkt) = NetlinkPacket::new(&buf) {
                            println!("PKT: {:?}", pkt);
                            let mut cursor = 0;
                            let total_len = buf.len();

                            let mut aligned_len = ::util::align(pkt.get_length() as usize);
                            loop {
                                cursor += aligned_len;
                                if cursor >= total_len {
                                    break;
                                }
                                println!("NEXT PKT @ {:?}", cursor);
                                if let Some(next_pkt) = NetlinkPacket::new(&buf[cursor..]) {
                                    println!("PKT: {:?}", next_pkt);
                                    aligned_len = ::util::align(next_pkt.get_length() as usize);
                                    if aligned_len == 0 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                },
                _ => {},
            }
        }
    }
}