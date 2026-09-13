//! Bind-address validation — refused before a socket is ever created.
//!
//! RemoteDexter binds one deliberately chosen interface. A wildcard bind is
//! rejected, not warned about, because the difference between `192.168.1.20:8082`
//! and `0.0.0.0:8082` is the difference between "my phone can reach this" and
//! "every network this machine is attached to can reach this, including the one
//! I joined at an airport". The user cannot see that difference in a UI; the
//! type system can.

use std::net::{IpAddr, SocketAddr};

/// Why a requested bind address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRejection {
    /// `0.0.0.0` — every IPv4 interface, present and future.
    WildcardIpv4,
    /// `::` — every IPv6 interface, and on most systems every IPv4 one too via
    /// v4-mapped addresses, which makes it strictly worse than `0.0.0.0`.
    WildcardIpv6,
    /// A multicast or broadcast address is not a thing a TCP server binds.
    NotUnicast,
}

impl BindRejection {
    /// A message safe to show a user and safe to log: it names the rule, not
    /// the address the caller supplied.
    pub fn reason(self) -> &'static str {
        match self {
            BindRejection::WildcardIpv4 => {
                "0.0.0.0 binds every IPv4 interface — choose one interface"
            }
            BindRejection::WildcardIpv6 => {
                "\u{3a}\u{3a} binds every IPv6 interface — choose one interface"
            }
            BindRejection::NotUnicast => "not a unicast address",
        }
    }
}

/// Accept a bind address, or say precisely why not.
///
/// Loopback is deliberately permitted: it is how the host is developed and
/// tested, and it is reachable by nothing outside the machine. Port 0 is also
/// permitted — the OS assigns one, which is what the tests use and what a
/// future "pick a free port" option would use. Neither widens exposure.
pub fn validate(addr: SocketAddr) -> Result<SocketAddr, BindRejection> {
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err(BindRejection::WildcardIpv4);
            }
            if v4.is_multicast() || v4.is_broadcast() {
                return Err(BindRejection::NotUnicast);
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err(BindRejection::WildcardIpv6);
            }
            if v6.is_multicast() {
                return Err(BindRejection::NotUnicast);
            }
            // A v4-mapped wildcard (`::ffff:0.0.0.0`) is `0.0.0.0` wearing a
            // hat. Catch it here rather than letting the kernel widen the bind.
            if let Some(v4) = v6.to_ipv4_mapped() {
                if v4.is_unspecified() {
                    return Err(BindRejection::WildcardIpv4);
                }
            }
        }
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_and_lan_addresses_are_accepted() {
        assert!(validate(sa("127.0.0.1:8082")).is_ok());
        assert!(validate(sa("127.0.0.1:0")).is_ok());
        assert!(validate(sa("192.168.1.20:8082")).is_ok());
        assert!(validate(sa("[::1]:8082")).is_ok());
    }

    /// The two the whole module exists for. These were missing on the first
    /// pass: deleting the wildcard checks turned the LIFECYCLE tests red but
    /// left this unit suite green, which means the unit suite was not testing
    /// the rule it is named after.
    #[test]
    fn plain_wildcards_are_refused() {
        assert_eq!(
            validate(sa("0.0.0.0:8082")),
            Err(BindRejection::WildcardIpv4)
        );
        assert_eq!(validate(sa("0.0.0.0:0")), Err(BindRejection::WildcardIpv4));
        assert_eq!(validate(sa("[::]:8082")), Err(BindRejection::WildcardIpv6));
        assert_eq!(validate(sa("[::]:0")), Err(BindRejection::WildcardIpv6));
    }

    #[test]
    fn every_rejection_has_a_reason_that_names_the_rule() {
        // A refusal a user cannot act on is a refusal they will work around.
        assert!(BindRejection::WildcardIpv4.reason().contains("0.0.0.0"));
        assert!(BindRejection::WildcardIpv6.reason().contains("::"));
        assert!(!BindRejection::NotUnicast.reason().is_empty());
    }

    #[test]
    fn multicast_and_broadcast_are_refused() {
        assert_eq!(
            validate(sa("224.0.0.1:8082")),
            Err(BindRejection::NotUnicast)
        );
        assert_eq!(
            validate(sa("255.255.255.255:8082")),
            Err(BindRejection::NotUnicast)
        );
        assert_eq!(
            validate(sa("[ff02::1]:8082")),
            Err(BindRejection::NotUnicast)
        );
    }

    /// `::ffff:0.0.0.0` is the IPv4 wildcard reached through IPv6. It must be
    /// refused as the wildcard it is, not accepted as an ordinary v6 address.
    #[test]
    fn v4_mapped_wildcard_is_still_a_wildcard() {
        assert_eq!(
            validate(sa("[::ffff:0.0.0.0]:8082")),
            Err(BindRejection::WildcardIpv4)
        );
    }
}
