use tokio_core::reactor::{Handle, PollEvented};
use tokio_core::io::{Codec,EasyBuf};
use tokio_core::io::Io;
use futures::{Future, Poll, Async};
use std::io;
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
}

impl io::Write for NetlinkSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl Io for NetlinkSocket {
    fn poll_read(&mut self) -> Async<()> {
        <NetlinkSocket>::poll_read(self)
    }

    fn poll_write(&mut self) -> Async<()> {
        <NetlinkSocket>::poll_write(self)
    }
}

struct NetlinkCodec {

}

impl Codec for NetlinkCodec {
    type In = NetlinkPacket<'static>;
    type Out = NetlinkPacket<'static>;

    fn decode_eof(&mut self, buf: &mut EasyBuf) -> io::Result<Self::In> {
        println!("DECODE EOF CALLED");

        Ok(NetlinkPacket::owned(buf.as_slice().to_owned()).unwrap())
    }

    fn decode(&mut self, buf: &mut EasyBuf) -> io::Result<Option<Self::In>> {
        let (owned_pkt, len) = {
            let slice = buf.as_slice();
            println!("SLICE: {:?}", slice);
            if let Some(pkt) = NetlinkPacket::new(slice) {
                println!("{:?} slice: {}", pkt, slice.len());
                if pkt.get_length() as usize > slice.len() {
                    println!("NEED MORE BYTES");
                    return Ok(None);
                }
                (NetlinkPacket::owned(slice.to_owned()), pkt.get_length())
            } else {
                unimplemented!();
            }
        };
        buf.drain_to(len as usize);
        return Ok(owned_pkt);
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> io::Result<()> {
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
    use tokio_core::io::Io;
    use futures::{Sink,Stream,Future};

    let mut l = Core::new().unwrap();
    let handle = l.handle();
    let sock = NetlinkSocket::bind(socket::NetlinkProtocol::Route, 0, &handle).unwrap();
    println!("Netlink socket bound");
    let framed = Io::framed(sock, NetlinkCodec {});

    let pkt = NetlinkRequestBuilder::new(18 /* RTM GETLINK */, NetlinkMsgFlags::NLM_F_DUMP).append(
        {
            let len = MutableIfInfoPacket::minimum_packet_size();
            let mut data = vec![0; len];
            MutableIfInfoPacket::owned(data).unwrap()
        }
    ).build();
    let f = framed.send(pkt).and_then(|f| f.into_future().map_err(|(e, _)| e))
    .and_then(|(x, y)| {
         println!("RECEIVED FRAME: {:?}", x); Ok(())
    });
    l.run(f);
}