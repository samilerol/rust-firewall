//! Decoder for the fixed 96-byte active-flow records exported by the Android adapter
//! (`snapshotForwarding`, layout documented in crates/netscope-android/src/forwarding.rs).
//! Informational display data only; never an authorization input.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const RECORD_BYTES: usize = 96;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowRow {
    pub tcp: bool,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
    /// Owning uid, or None when unknown.
    pub uid: Option<u32>,
    pub out_packets: u64,
    pub out_bytes: u64,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub created_ms: u64,
    pub last_seen_ms: u64,
}

fn be64(bytes: &[u8]) -> u64 {
    bytes.try_into().map(u64::from_be_bytes).unwrap_or(0)
}

/// Returns None for an all-zero/unsupported record (protocol or family not recognised).
pub fn decode(record: &[u8]) -> Option<FlowRow> {
    if record.len() != RECORD_BYTES {
        return None;
    }
    let tcp = match record[0] {
        6 => true,
        17 => false,
        _ => return None,
    };
    let address = |range: std::ops::Range<usize>| -> Option<IpAddr> {
        match record[1] {
            4 => Some(
                Ipv4Addr::from(<[u8; 4]>::try_from(&record[range.start..range.start + 4]).ok()?)
                    .into(),
            ),
            16 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(&record[range]).ok()?).into()),
            _ => None,
        }
    };
    let uid = i32::from_be_bytes(record[38..42].try_into().ok()?);
    Some(FlowRow {
        tcp,
        source: address(6..22)?,
        source_port: u16::from_be_bytes([record[2], record[3]]),
        destination: address(22..38)?,
        destination_port: u16::from_be_bytes([record[4], record[5]]),
        uid: u32::try_from(uid).ok(),
        out_packets: be64(&record[44..52]),
        out_bytes: be64(&record[52..60]),
        in_packets: be64(&record[60..68]),
        in_bytes: be64(&record[68..76]),
        created_ms: be64(&record[76..84]),
        last_seen_ms: be64(&record[84..92]),
    })
}

/// Decodes `count` records from a snapshot block, skipping unsupported ones; never reads past
/// the block and never returns more than it holds.
pub fn decode_block(block: &[u8], count: usize) -> Vec<FlowRow> {
    block
        .chunks_exact(RECORD_BYTES)
        .take(count)
        .filter_map(decode)
        .collect()
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(v6: bool, uid: i32) -> [u8; RECORD_BYTES] {
        let mut r = [0u8; RECORD_BYTES];
        r[0] = 6;
        r[1] = if v6 { 16 } else { 4 };
        r[2..4].copy_from_slice(&40_000u16.to_be_bytes());
        r[4..6].copy_from_slice(&443u16.to_be_bytes());
        if v6 {
            r[6..22].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
            r[22..38].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        } else {
            r[6..10].copy_from_slice(&[10, 0, 0, 2]);
            r[22..26].copy_from_slice(&[93, 184, 216, 34]);
        }
        r[38..42].copy_from_slice(&uid.to_be_bytes());
        r[44..52].copy_from_slice(&2u64.to_be_bytes());
        r[52..60].copy_from_slice(&300u64.to_be_bytes());
        r[60..68].copy_from_slice(&1u64.to_be_bytes());
        r[68..76].copy_from_slice(&1_500u64.to_be_bytes());
        r[76..84].copy_from_slice(&5u64.to_be_bytes());
        r[84..92].copy_from_slice(&9u64.to_be_bytes());
        r
    }

    #[test]
    fn decodes_both_families_and_unknown_uid() {
        let v4 = decode(&record(false, 10_042)).unwrap();
        assert!(v4.tcp);
        assert_eq!(v4.source, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(v4.destination, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!((v4.source_port, v4.destination_port), (40_000, 443));
        assert_eq!(v4.uid, Some(10_042));
        assert_eq!((v4.out_packets, v4.out_bytes), (2, 300));
        assert_eq!((v4.in_packets, v4.in_bytes), (1, 1_500));
        assert_eq!((v4.created_ms, v4.last_seen_ms), (5, 9));
        let v6 = decode(&record(true, -1)).unwrap();
        assert_eq!(v6.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(v6.uid, None);
    }

    #[test]
    fn rejects_wrong_size_unknown_protocol_and_unknown_family() {
        assert_eq!(decode(&[0u8; RECORD_BYTES - 1]), None);
        assert_eq!(decode(&[0u8; RECORD_BYTES]), None, "all-zero record");
        let mut bad = record(false, 1);
        bad[1] = 7;
        assert_eq!(decode(&bad), None);
    }

    #[test]
    fn block_decoding_is_bounded_by_count_and_block_length() {
        let mut block = Vec::new();
        block.extend_from_slice(&record(false, 1));
        block.extend_from_slice(&record(true, 2));
        block.extend_from_slice(&[0u8; RECORD_BYTES]); // unsupported, skipped
        assert_eq!(decode_block(&block, 1).len(), 1);
        assert_eq!(decode_block(&block, 99).len(), 2);
        assert_eq!(decode_block(&block[..RECORD_BYTES + 10], 2).len(), 1);
        assert!(decode_block(&[], 5).is_empty());
    }

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert!(human_bytes(u64::MAX).ends_with("GiB"));
    }
}
