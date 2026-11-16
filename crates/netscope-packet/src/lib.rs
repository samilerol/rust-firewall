//! Allocation-free IP/TCP/UDP parsing, with explicit optional checksum validation.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Packet {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub length: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Truncated,
    InvalidLength,
    Unsupported,
    Fragmented,
    InvalidHeader,
    InvalidIpv4Checksum,
    InvalidTransportChecksum,
    MissingTransportChecksum,
}
fn word(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Accepts exactly one IP datagram, without link-layer framing or trailing bytes.
/// Rejects fragments, IPv4 options and all IPv6 extension headers conservatively.
/// Does not validate IP/TCP/UDP checksums; metadata is not proof of authenticity.
pub fn parse(b: &[u8]) -> Result<Packet, ParseError> {
    let version = b.first().ok_or(ParseError::Truncated)? >> 4;
    let (source, destination, next, offset) = match version {
        4 => {
            if b.len() < 20 {
                return Err(ParseError::Truncated);
            }
            let ihl = usize::from(b[0] & 15) * 4;
            if ihl < 20 {
                return Err(ParseError::InvalidHeader);
            }
            if ihl != 20 {
                return Err(ParseError::Unsupported);
            }
            if usize::from(word(b, 2)) != b.len() {
                return Err(ParseError::InvalidLength);
            }
            let fragment = word(b, 6);
            if fragment & 0x8000 != 0 {
                return Err(ParseError::InvalidHeader);
            }
            if fragment & 0x3fff != 0 {
                return Err(ParseError::Fragmented);
            }
            (
                IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
                IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
                b[9],
                20,
            )
        }
        6 => {
            if b.len() < 40 {
                return Err(ParseError::Truncated);
            }
            if usize::from(word(b, 4)) + 40 != b.len() {
                return Err(ParseError::InvalidLength);
            }
            let mut src = [0; 16];
            src.copy_from_slice(&b[8..24]);
            let mut dst = [0; 16];
            dst.copy_from_slice(&b[24..40]);
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                b[6],
                40,
            )
        }
        _ => return Err(ParseError::Unsupported),
    };
    let t = &b[offset..];
    let protocol = match next {
        6 => {
            if t.len() < 20 {
                return Err(ParseError::Truncated);
            }
            let header = usize::from(t[12] >> 4) * 4;
            if header < 20 || header > t.len() {
                return Err(ParseError::InvalidLength);
            }
            Protocol::Tcp
        }
        17 => {
            if t.len() < 8 {
                return Err(ParseError::Truncated);
            }
            if usize::from(word(t, 4)) != t.len() {
                return Err(ParseError::InvalidLength);
            }
            Protocol::Udp
        }
        _ => return Err(ParseError::Unsupported),
    };
    Ok(Packet {
        source,
        destination,
        source_port: word(t, 0),
        destination_port: word(t, 2),
        protocol,
        length: b.len(),
    })
}

/// Whether an IPv4 UDP datagram may deliberately omit its optional checksum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumPolicy {
    Require,
    AllowIpv4UdpOmission,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportChecksum {
    Verified,
    OmittedIpv4Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckedPacket {
    pub packet: Packet,
    pub transport_checksum: TransportChecksum,
}

// Fold on every addition: bounded arithmetic even for long datagrams.
// Each call represents an even-aligned portion of the checksum stream;
// only the final transport slice may have odd length.
fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let Some(byte) = words.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    (sum & 0xffff) + (sum >> 16)
}

/// Parse one structurally supported datagram, then verify IPv4 header (when present)
/// and TCP/UDP pseudo-header+segment checksums. IPv6 UDP always requires a checksum;
/// IPv4 UDP omission is accepted only by explicit policy and reported in the result.
/// No checksum offload assumptions are made: partially checksummed buffers may fail.
/// Checksums detect accidental corruption, not malicious modification or authenticity.
pub fn parse_checked(b: &[u8], policy: ChecksumPolicy) -> Result<CheckedPacket, ParseError> {
    let packet = parse(b)?;
    let ipv4 = packet.source.is_ipv4();
    let offset = if ipv4 { 20 } else { 40 };
    if ipv4 && add_words(0, &b[..20]) != 0xffff {
        return Err(ParseError::InvalidIpv4Checksum);
    }
    let segment = &b[offset..];
    if packet.protocol == Protocol::Udp && word(segment, 6) == 0 {
        if ipv4 && policy == ChecksumPolicy::AllowIpv4UdpOmission {
            return Ok(CheckedPacket {
                packet,
                transport_checksum: TransportChecksum::OmittedIpv4Udp,
            });
        }
        return Err(ParseError::MissingTransportChecksum);
    }
    let protocol = match packet.protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    };
    // parse already restricted transport length to the IP datagram's 16-bit length field.
    let length = segment.len() as u32;
    let mut sum = if ipv4 {
        add_words(0, &b[12..20])
    } else {
        add_words(0, &b[8..40])
    };
    if ipv4 {
        sum = add_words(sum, &[0, protocol]);
        sum = add_words(sum, &(length as u16).to_be_bytes());
    } else {
        sum = add_words(sum, &length.to_be_bytes());
        sum = add_words(sum, &[0, 0, 0, protocol]);
    }
    if add_words(sum, segment) != 0xffff {
        return Err(ParseError::InvalidTransportChecksum);
    }
    Ok(CheckedPacket {
        packet,
        transport_checksum: TransportChecksum::Verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(v6: bool, tcp: bool) -> Vec<u8> {
        let offset = if v6 { 40 } else { 20 };
        let transport = if tcp { 20 } else { 8 };
        let mut b = vec![0; offset + transport];
        let len = b.len() as u16;
        if v6 {
            b[0] = 0x60;
            b[4..6].copy_from_slice(&(transport as u16).to_be_bytes());
            b[6] = if tcp { 6 } else { 17 };
            b[23] = 1;
            b[39] = 2;
        } else {
            b[0] = 0x45;
            b[2..4].copy_from_slice(&len.to_be_bytes());
            b[9] = if tcp { 6 } else { 17 };
            b[12..16].copy_from_slice(&[10, 0, 0, 1]);
            b[16..20].copy_from_slice(&[10, 0, 0, 2]);
        }
        b[offset..offset + 2].copy_from_slice(&1234u16.to_be_bytes());
        b[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
        if tcp {
            b[offset + 12] = 0x50;
        } else {
            b[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
        }
        b
    }
    #[test]
    fn parses_all_combinations() {
        for v6 in [false, true] {
            for tcp in [false, true] {
                let b = fixture(v6, tcp);
                let p = parse(&b).unwrap();
                assert_eq!(p.source_port, 1234);
                assert_eq!(p.destination_port, 443);
                assert_eq!(p.protocol, if tcp { Protocol::Tcp } else { Protocol::Udp });
                assert_eq!(
                    p.source,
                    if v6 {
                        "::1".parse::<IpAddr>().unwrap()
                    } else {
                        "10.0.0.1".parse::<IpAddr>().unwrap()
                    }
                );
                assert_eq!(
                    p.destination,
                    if v6 {
                        "::2".parse::<IpAddr>().unwrap()
                    } else {
                        "10.0.0.2".parse::<IpAddr>().unwrap()
                    }
                );
                assert_eq!(p.length, b.len());
                for n in 0..b.len() {
                    assert!(parse(&b[..n]).is_err());
                }
            }
        }
    }
    #[test]
    fn rejects_malformed_and_unsupported() {
        let mut b = fixture(false, false);
        b[24] = 0;
        b[25] = 7;
        assert_eq!(parse(&b), Err(ParseError::InvalidLength));
        let mut b = fixture(false, true);
        b[32] = 0x40;
        assert_eq!(parse(&b), Err(ParseError::InvalidLength));
        b[32] = 0xf0;
        assert_eq!(parse(&b), Err(ParseError::InvalidLength));
        let mut b = fixture(false, false);
        b[6] = 0x20;
        assert_eq!(parse(&b), Err(ParseError::Fragmented));
        b[6] = 0;
        b[7] = 1;
        assert_eq!(parse(&b), Err(ParseError::Fragmented));
        b[7] = 0;
        b[0] = 0x46;
        assert_eq!(parse(&b), Err(ParseError::Unsupported));
        b[0] = 0x44;
        assert_eq!(parse(&b), Err(ParseError::InvalidHeader));
        let mut b = fixture(true, false);
        b[6] = 44;
        assert_eq!(parse(&b), Err(ParseError::Unsupported));
        let mut b = fixture(false, false);
        b.push(0);
        assert_eq!(parse(&b), Err(ParseError::InvalidLength));
    }
    #[test]
    fn arbitrary_bytes_do_not_panic() {
        let mut state = 7u64;
        for len in 0..512 {
            for _ in 0..32 {
                let b: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state as u8
                    })
                    .collect();
                let _ = parse(&b);
                let _ = parse_checked(&b, ChecksumPolicy::Require);
                let _ = parse_checked(&b, ChecksumPolicy::AllowIpv4UdpOmission);
            }
        }
    }
}
