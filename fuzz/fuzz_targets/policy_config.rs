#![no_main]
use libfuzzer_sys::fuzz_target;
use netscope_policy::config::{parse_policy, ConfigErrorKind, MAX_CONFIG_BYTES};
fuzz_target!(|bytes: &[u8]| {
    match parse_policy(bytes) {
        Ok(_) => assert!(bytes.len() <= MAX_CONFIG_BYTES),
        Err(error) => {
            if bytes.len() > MAX_CONFIG_BYTES {
                assert_eq!(error.kind, ConfigErrorKind::TooLarge);
            }
        }
    }
});
