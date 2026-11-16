//! Bounded, dependency-free microbenchmarks. CSV timings are observations, not guarantees.
use netscope_conntrack::{FlowId, Tracker};
use netscope_dns::{DomainName, DomainPolicy, Match as DomainMatch, Rule as DomainRule};
use netscope_packet::{parse, Packet, Protocol};
use netscope_policy::{Action, Policy, Rule};
use std::{hint::black_box, time::Instant};

fn datagram(v6: bool, tcp: bool) -> Vec<u8> {
    let offset = if v6 { 40 } else { 20 };
    let transport = if tcp { 20 } else { 8 };
    let mut bytes = vec![0; offset + transport];
    if v6 {
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(transport as u16).to_be_bytes());
        bytes[6] = if tcp { 6 } else { 17 };
        bytes[23] = 1;
        bytes[39] = 2;
    } else {
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&((offset + transport) as u16).to_be_bytes());
        bytes[9] = if tcp { 6 } else { 17 };
        bytes[15] = 1;
        bytes[19] = 2;
    }
    bytes[offset..offset + 2].copy_from_slice(&1234u16.to_be_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&443u16.to_be_bytes());
    if tcp {
        bytes[offset + 12] = 0x50;
    } else {
        bytes[offset + 4..offset + 6].copy_from_slice(&8u16.to_be_bytes());
    }
    bytes
}

fn measure<T>(name: &str, sample: usize, iterations: usize, mut operation: impl FnMut() -> T) {
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }
    let ns = start.elapsed().as_nanos();
    println!(
        "{name},{sample},{iterations},{ns},{:.3}",
        ns as f64 / iterations as f64
    );
}

fn rule(priority: u32, port: u16) -> Rule {
    Rule {
        priority,
        action: Action::Allow,
        source: None,
        destination: None,
        protocol: Some(Protocol::Tcp),
        source_port: None,
        destination_port: Some(port..=port),
    }
}

fn flow(packet: &Packet, port: u16) -> FlowId {
    FlowId {
        source_port: port,
        ..FlowId::from(packet)
    }
}

fn filled(packet: &Packet, entries: usize) -> Tracker {
    let mut tracker = Tracker::new(entries, 10);
    for port in 0..entries {
        tracker.observe(flow(packet, port as u16), 0).unwrap();
    }
    assert_eq!(tracker.len(), entries);
    tracker
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("Benchmarks require --release to avoid misleading debug timings.");
        std::process::exit(2);
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let smoke = match args.as_slice() {
        [] => false,
        [arg] if arg == "--smoke" => true,
        _ => {
            eprintln!("Usage: netscope-bench [--smoke]");
            std::process::exit(2);
        }
    };
    let iterations = if smoke { 100 } else { 10_000 };
    let samples = if smoke { 3 } else { 7 };
    eprintln!("mode={} samples={samples} iterations={iterations}; sample 0 is warmup; release profile required", if smoke { "smoke" } else { "baseline" });
    println!("case,sample,operations,elapsed_ns,ns_per_operation");
    let bytes = datagram(false, true);
    let packet = parse(&bytes).unwrap();
    let dns_query = vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'C', b'O', b'M', 0, 0, 1, 0, 1,
    ];
    let mut dns_response = dns_query.clone();
    dns_response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    dns_response[7] = 1;
    dns_response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
    assert!(netscope_dns::parse_query(&dns_query).is_ok());
    assert!(netscope_dns::parse_response(&dns_response).is_ok());
    for sample in 0..=samples {
        for v6 in [false, true] {
            for tcp in [false, true] {
                let bytes = datagram(v6, tcp);
                assert!(parse(&bytes).is_ok());
                measure(
                    &format!(
                        "parse_ipv{}_{}",
                        if v6 { 6 } else { 4 },
                        if tcp { "tcp" } else { "udp" }
                    ),
                    sample,
                    iterations,
                    || parse(black_box(&bytes)),
                );
            }
        }
        let malformed = [0x45u8; 3];
        assert!(parse(&malformed).is_err());
        measure("parse_truncated", sample, iterations, || {
            parse(black_box(&malformed))
        });
        for count in [0, 64, 512, 4096] {
            for position in ["first", "last", "miss"] {
                if count == 0 && position != "miss" {
                    continue;
                }
                let mut rules = vec![rule(1, 80); count];
                let index = match position {
                    "first" => Some(0),
                    "last" => Some(count - 1),
                    _ => None,
                };
                if let Some(index) = index {
                    rules[index] = rule(0, 443);
                }
                let policy = Policy::new(rules, Action::Deny).unwrap();
                assert_eq!(policy.decide(&packet).rule_index, index);
                measure(
                    &format!("policy_{count}_{position}"),
                    sample,
                    iterations,
                    || policy.decide(black_box(&packet)),
                );
            }
        }
        measure("dns_parse_query", sample, iterations, || {
            netscope_dns::parse_query(black_box(&dns_query))
        });
        measure("dns_parse_compressed_response", sample, iterations, || {
            netscope_dns::parse_response(black_box(&dns_response))
        });
        for count in [64, 4096] {
            let mut rules: Vec<_> = (0..count)
                .map(|i| DomainRule {
                    name: DomainName::new(&format!("unused{i}.example")).unwrap(),
                    kind: DomainMatch::Exact,
                    priority: 1,
                    action: Action::Deny,
                })
                .collect();
            rules[count - 1] = DomainRule {
                name: DomainName::new("blocked.example").unwrap(),
                kind: DomainMatch::DomainAndSubdomains,
                priority: 0,
                action: Action::Deny,
            };
            let policy = DomainPolicy::new(rules, Action::Allow).unwrap();
            for (label, name, action) in [
                ("hit", "a.blocked.example", Action::Deny),
                ("miss", "safe.test", Action::Allow),
            ] {
                let name = DomainName::new(name).unwrap();
                assert_eq!(policy.decide(&name).action, action);
                measure(
                    &format!("dns_rules_{count}_{label}"),
                    sample,
                    iterations,
                    || policy.decide(black_box(&name)),
                );
            }
        }
        for entries in [1, 64, 512, 4096] {
            let mut inserting = Tracker::new(entries, 10);
            let mut port = 0u16;
            measure(
                &format!("flow_{entries}_insert_unique"),
                sample,
                entries,
                || {
                    let id = flow(black_box(&packet), port);
                    port += 1;
                    inserting.observe(id, black_box(0))
                },
            );
            assert_eq!(inserting.len(), entries);
            let mut tracker = filled(&packet, entries);
            let id = flow(&packet, 0);
            measure(
                &format!("flow_{entries}_refresh_with_sweep"),
                sample,
                iterations,
                || tracker.observe(black_box(id), black_box(1)),
            );
            assert_eq!(tracker.len(), entries);
            // Batch drain: setup outside timer; one operation expires the entire table.
            measure(&format!("flow_{entries}_expire_all"), sample, 1, || {
                tracker.expire(black_box(11)).unwrap()
            });
            assert!(tracker.is_empty());
            let mut tracker = filled(&packet, entries);
            let missing = flow(&packet, u16::MAX);
            assert!(tracker.observe(missing, 1).is_err());
            measure(
                &format!("flow_{entries}_full_reject_with_sweep"),
                sample,
                iterations,
                || tracker.observe(black_box(missing), black_box(1)),
            );
        }
    }
}
