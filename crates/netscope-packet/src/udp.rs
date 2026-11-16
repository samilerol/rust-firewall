//! Constructs complete unfragmented UDP/IP datagrams with checksums. No network I/O.
use std::net::{IpAddr, SocketAddr};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    AddressFamily,
    PayloadTooLarge,
}

pub fn encode(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let ipv4 = source.is_ipv4();
    if ipv4 != destination.is_ipv4() {
        return Err(EncodeError::AddressFamily);
    }
    let offset = if ipv4 { 20 } else { 40 };
    let max_payload = if ipv4 { 65507 } else { 65527 };
    if payload.len() > max_payload {
        return Err(EncodeError::PayloadTooLarge);
    }
    let length = payload.len() + 8;
    let mut bytes = vec![0; offset + length];
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            bytes[0] = 0x45;
            let total = bytes.len() as u16;
            bytes[2..4].copy_from_slice(&total.to_be_bytes());
            bytes[6] = 0x40;
            bytes[8] = 64;
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&src.octets());
            bytes[16..20].copy_from_slice(&dst.octets());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&(length as u16).to_be_bytes());
            bytes[6] = 17;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&src.octets());
            bytes[24..40].copy_from_slice(&dst.octets());
        }
        _ => return Err(EncodeError::AddressFamily),
    }
    bytes[offset..offset + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&destination.port().to_be_bytes());
    bytes[offset + 4..offset + 6].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[offset + 8..].copy_from_slice(payload);
    let checksum = !(super::transport_sum(&bytes, offset, 17) as u16);
    bytes[offset + 6..offset + 8]
        .copy_from_slice(&(if checksum == 0 { 0xffff } else { checksum }).to_be_bytes());
    if ipv4 {
        let header = !(super::add_words(0, &bytes[..20]) as u16);
        bytes[10..12].copy_from_slice(&header.to_be_bytes());
    }
    Ok(bytes)
}
