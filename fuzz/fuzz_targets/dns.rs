#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope_dns::{decode_name, parse_query, parse_response, DomainName, DomainPolicy};
use netscope_policy::Action;
fuzz_target!(|bytes: &[u8]| {
    netscope_transport::exercise_dns_transactions(bytes);
    let deny = DomainPolicy::new(vec![], Action::Deny).unwrap();
    for parsed in [parse_query(bytes), parse_response(bytes)] {
        if let Ok(message) = parsed {
            assert_eq!(
                DomainName::new(message.question.name.as_str()).unwrap(),
                message.question.name
            );
            assert_eq!(deny.decide(&message.question.name).action, Action::Deny);
            assert_ne!(message.question.qtype, 0);
            assert_eq!(message.question.qclass, 1);
        }
    }
    for start in [0, 12, bytes.len() / 2, bytes.len()] {
        if let Ok((name, end)) = decode_name(bytes, start) {
            assert!(end > start && end <= bytes.len());
            assert_eq!(DomainName::new(name.as_str()).unwrap(), name);
        }
    }
});
