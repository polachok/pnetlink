//! RTNETLINK aka Netlink Route Family is used for network device configuration.
//!
//! Different layer operations are implemented as traits 
//! on NetlinkConnection
pub mod addr;
pub mod link;
pub mod neighbour;
pub mod route;
pub mod rule;

include!(concat!(env!("OUT_DIR"), "/route/route.rs"));

const RTA_ALIGNTO: usize = 4;

fn align(len: usize) -> usize {
    ((len)+RTA_ALIGNTO-1) & !(RTA_ALIGNTO-1)
}

/// RTNETLINK attribute iterator
pub struct RtAttrIterator<'a> {
    buf: &'a [u8],
}

impl<'a> RtAttrIterator<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        RtAttrIterator {
            buf: buf,
        }
    }
}

impl<'a> Iterator for RtAttrIterator<'a> {
    type Item = RtAttrPacket<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(rta) = RtAttrPacket::new(&self.buf[..]) {
            let len = rta.get_rta_len() as usize;
            if len < 4 {
                return None;
            }
            self.buf = &self.buf[align(len as usize)..];
            return Some(rta);
        }
        None
    }
}


