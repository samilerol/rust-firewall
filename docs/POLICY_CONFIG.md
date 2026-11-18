# Bounded policy configuration

`netscope_policy::config::{parse_policy, parse_policy_from}` turn a small text file into a `Policy`. It has no dependencies, never returns a partial policy and never panics on any input: a problem anywhere rejects the whole file with the 1-based line (0 when not tied to a line).

```text
# comment (anywhere on a line)
default deny
allow priority=10 proto=tcp dst=10.0.0.0/8 dport=443 uid=10001-10099 network=wifi
deny  dst=203.0.113.0/24
allow proto=udp dport=53 uid=unknown
```

- Exactly one `default allow|deny` line is required; it may appear anywhere.
- A rule is `allow|deny` plus unique `key=value` tokens: `priority` (u32, default 0), `proto` (`tcp`|`udp`), `src`/`dst` (CIDR; the address family must match the prefix range), `sport`/`dport` (`N` or `A-B`), `uid` (`N`, `A-B` or `unknown`) and `network` (`wifi`|`cellular`|`other`|`unknown`). All present constraints must match. Equal priorities keep file order, exactly like `Policy::new`.
- Rejected: unknown directive or key, a token without `=`, a repeated key, a malformed or out-of-range value, a second `default`, no `default`, inverted port/uid ranges (reported by the policy as `Policy(InvalidPortRange | InvalidUidRange { rule_index })`).
- Limits: 512 KiB of input (`MAX_CONFIG_BYTES`), 512 bytes per line (`MAX_LINE_BYTES`) and 4096 rules (`MAX_RULES`). `parse_policy_from` reads at most the byte limit plus one, so an endless reader cannot exhaust memory; `parse_policy` rejects over-limit slices before looking at them. Input must be UTF-8; CRLF is accepted.

Not provided: a writer/serializer, includes, hostnames/domain rules (those belong to the DNS policy), per-rule comments metadata or a schema version. A file is configuration, not authentication: the loader says nothing about where the file came from or whether the user approved it. Evidence: unit tests for every rejection, the limits and equivalence with a hand-built policy, and a deterministic 20,000-case mutation test; a libFuzzer target exists (`fuzz/`) but was not run locally.
