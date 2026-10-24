//! System DNS configuration from libresolv.
//!
//! Used on the Apple platforms other than macOS (iOS, tvOS, watchOS,
//! visionOS): the SystemConfiguration dynamic store is `API_UNAVAILABLE`
//! there and the sandbox hides `/etc/resolv.conf`. `res_ninit` loads the
//! system resolver configuration and `res_getservers` returns its
//! nameservers; both are public API on these platforms.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::{Config, DnsProtocol, Hosts, Nameserver};

/// `struct __res_state` from `<resolv.h>`, kept opaque.
///
/// Sized and aligned for the largest layout (552 bytes, 8-aligned on 64-bit
/// targets; 512 bytes, 4-aligned on arm64_32 watchOS).
#[repr(C, align(8))]
struct ResState([u8; 552]);

/// `union res_sockaddr_union` from `<resolv.h>`: 128 bytes, 4-aligned.
#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct ResSockaddrUnion([u8; 128]);

/// `MAXNS` from `<resolv.h>`.
const MAXNS: usize = 3;

#[link(name = "resolv")]
unsafe extern "C" {
    fn res_9_ninit(state: *mut ResState) -> libc::c_int;
    fn res_9_getservers(
        state: *mut ResState,
        set: *mut ResSockaddrUnion,
        cnt: libc::c_int,
    ) -> libc::c_int;
    fn res_9_ndestroy(state: *mut ResState);
}

/// Reads the system nameservers through libresolv.
///
/// Search domains are not read. Also reads the hosts file.
pub(super) fn read_system_dns() -> Result<Config, std::io::Error> {
    let mut state = ResState([0; 552]);
    let mut servers = [ResSockaddrUnion([0; 128]); MAXNS];
    // SAFETY: `state` is zeroed and at least as large and aligned as
    // `struct __res_state`, as `res_ninit` requires, and destroyed only after a
    // successful init. `servers` holds `MAXNS` unions, the count passed.
    let count = unsafe {
        if res_9_ninit(&mut state) != 0 {
            return Err(std::io::Error::other("res_ninit failed"));
        }
        let count = res_9_getservers(&mut state, servers.as_mut_ptr(), MAXNS as libc::c_int);
        res_9_ndestroy(&mut state);
        count
    };
    let nameservers = servers
        .iter()
        .take(usize::try_from(count).unwrap_or(0))
        .filter_map(socket_addr)
        .map(|addr| Nameserver::new(addr, DnsProtocol::Udp))
        .collect();

    Ok(Config {
        nameservers,
        search_domains: Vec::new(),
        ndots: None,
        hosts: Hosts::from_system(),
    })
}

/// Converts a nameserver address to a [`SocketAddr`] on the DNS UDP port.
///
/// Keeps the scope of a link-local IPv6 nameserver (e.g. `fe80::1` on the
/// Wi-Fi interface), which cannot be reached without it.
fn socket_addr(addr: &ResSockaddrUnion) -> Option<SocketAddr> {
    let port = DnsProtocol::Udp.port();
    // BSD `sockaddr`: `sa_len`, then `sa_family`.
    match i32::from(addr.0[1]) {
        libc::AF_INET => {
            // SAFETY: for `AF_INET` the union holds a `sockaddr_in`, which is smaller.
            let sin: libc::sockaddr_in =
                unsafe { std::ptr::read_unaligned(addr.0.as_ptr().cast()) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddrV4::new(ip, port).into())
        }
        libc::AF_INET6 => {
            // SAFETY: for `AF_INET6` the union holds a `sockaddr_in6`, which is smaller.
            let sin6: libc::sockaddr_in6 =
                unsafe { std::ptr::read_unaligned(addr.0.as_ptr().cast()) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddrV6::new(ip, port, 0, sin6.sin6_scope_id).into())
        }
        _ => None,
    }
}
