//! Netlink socket related functions
extern crate libc;
extern crate mio;

use libc::c_int;
use libc::{socket,bind,send,recvfrom,setsockopt,getsockopt};
use std::os::unix::io::{AsRawFd,RawFd};
use std::io::{self,Error,Result,Read,Write};
use std::mem;

use self::mio::unix::EventedFd;
use self::mio::{Evented, Poll, Token, Ready, PollOpt};

#[repr(C)]
#[derive(Debug)]
pub enum SockOpt {
	AddMembership = 1,
	DropMembership = 2,
	PktInfo = 3,
	BroadcastError = 4,
	NoEnobufs = 5,
}


/// supported protocols
pub enum NetlinkProtocol {
	Route = 0,
	//Unused = 1,
	Usersock = 2,
	Firewall = 3,
	Inet_diag = 4,
	NFlog = 5,
	Xfrm = 6,
	SELinux = 7,
	ISCSI = 8,
	Audit = 9,
	FibLookup = 10,
	Connector = 11,
	Netfilter = 12,
	IP6_fw = 13,
	Dnrtmsg = 14,
	KObjectUevent = 15,
	Generic = 16,
	SCSItransport = 18,
	Ecryptfs = 19,
	Rdma = 20,
	Crypto = 21,
}

/// Bound Netlink socket.
#[derive(Debug)]
pub struct NetlinkSocket {
	fd: RawFd,
}

impl AsRawFd for NetlinkSocket {
	fn as_raw_fd(&self) -> RawFd {
		self.fd
	}
}

impl Drop for NetlinkSocket {
	fn drop(&mut self) {
		unsafe { libc::close(self.fd) };
	}
}

impl NetlinkSocket {
	pub fn bind(proto: NetlinkProtocol, groups: u32) -> Result<NetlinkSocket> {
		let nonblocking = true;
		NetlinkSocket::bind_with_args(proto, groups, nonblocking)
	}

	pub fn bind_with_args(proto: NetlinkProtocol, groups: u32, nonblocking: bool) -> Result<NetlinkSocket> {
		use std::mem::size_of;
		use std::mem::transmute;
		use libc::getpid;

		let mut res = unsafe {
			socket(libc::PF_NETLINK, libc::SOCK_DGRAM, proto as i32)
		};
		if res < 0 {
			return Err(Error::last_os_error());
		}
		let sock = NetlinkSocket { fd: res };

		let mut nonblocking = if nonblocking { 1 } else { 0 } as libc::c_ulong;
		res = unsafe {
			libc::ioctl(sock.fd, libc::FIONBIO, &mut nonblocking)
		};
		if res < 0 {
			return Err(Error::last_os_error());
		}

		let mut sockaddr: libc::sockaddr_nl = unsafe { mem::zeroed() };
		sockaddr.nl_family = libc::PF_NETLINK as libc::sa_family_t;
		sockaddr.nl_pid = unsafe { getpid() } as u32;
		sockaddr.nl_groups = groups;

		res = unsafe {
			bind(sock.fd, transmute(&mut sockaddr), size_of::<libc::sockaddr_nl>() as u32)
		};
		if res < 0 {
			return Err(Error::last_os_error());
		}
		Ok(sock)
	}

	pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
		use libc::c_void;
		let len = buf.len();
		let res = unsafe {
			send(self.fd, buf.as_ptr() as *const c_void, len, 0)
		};
		if res == -1 {
			return Err(Error::last_os_error());
		}
		Ok(res as usize)
	}

	pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
		use libc::c_void;
		use std::ptr::null_mut;
		use libc::sockaddr;

		let len = buf.len();
		let res = unsafe {
			recvfrom(self.fd, buf.as_mut_ptr() as *mut c_void, len, 0, null_mut::<sockaddr>(), null_mut::<u32>())
		};
		if res < 0 {
			return Err(Error::last_os_error());
		}
		Ok(res as usize)
	}

	fn setsockopt_int(&mut self, level: c_int, option: c_int, val: c_int) -> Result<()> {
		use std::mem;
		let res = unsafe {
			setsockopt(self.fd, level, option as c_int,
					   mem::transmute(&val), mem::size_of::<c_int>() as u32)
		};

		if res == -1 {
			return Err(Error::last_os_error());
		}
		Ok(())

	}

	fn getsockopt_int(&mut self, level: c_int, option: c_int) -> Result<u32> {
		use std::mem;
		let mut ffi_val: c_int = 0;
		let mut opt_len: c_int = mem::size_of::<c_int>() as c_int;
		let res = unsafe {
			getsockopt(self.fd, level, option as c_int,
					   mem::transmute(&mut ffi_val), mem::transmute(&mut opt_len))
		};

		if res == -1 {
			return Err(Error::last_os_error());
		}
		Ok(ffi_val as u32)

	}

	pub fn setsockopt(&mut self, option: SockOpt, val: bool) -> Result<()> {
		let ffi_val: c_int = if val { 1 } else { 0 };
		self.setsockopt_int(libc::SOL_NETLINK, option as c_int, ffi_val)
	}

	pub fn setrcvbuf(&mut self, len: c_int) -> Result<()> {
		self.setsockopt_int(libc::SOL_SOCKET, libc::SO_RCVBUF, len)
	}

	pub fn getrcvbuf(&mut self) -> Result<u32> {
		self.getsockopt_int(libc::SOL_SOCKET, libc::SO_RCVBUF)
	}

	pub fn getsockopt(&mut self, option: SockOpt, val: bool) -> Result<u32> {
		self.getsockopt_int(libc::SOL_NETLINK, option as c_int)
	}
}

impl Read for NetlinkSocket {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
		self.recv(buf)
	}
}

impl Write for NetlinkSocket {
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        self.send(buf)
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        Ok(())
    }
}

impl Evented for NetlinkSocket {
    fn register(&self,
                poll: &Poll,
                token: Token,
                events: Ready,
                opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).register(poll, token, events, opts)
    }

    fn reregister(&self,
                  poll: &Poll,
                  token: Token,
                  events: Ready,
                  opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, events, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}
