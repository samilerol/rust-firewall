# Classic DNS parsing and question policy

## Implemented scope

`netscope-dns` is a std-only/internal-workspace library: bounded DNS wire parsing, canonical ASCII question names and deterministic exact/subdomain policy. `UdpRelay::set_dns_filter(Some(policy), ports)` explicitly enables it on up to 32 distinct nonzero destination ports. No DNS filter is active in a plain relay constructor. An allow from the domain policy never overrides the packet/IP/current inbound policy.

This is **question-based classic UDP DNS filtering**, not a DNS resolver, cache, DNSSEC/TSIG validator or comprehensive domain-access control. No upstream resolver is selected or forced. Original DNS payloads are forwarded without modification when permitted. Blocked/invalid queries return errors and are not sent; no synthetic NXDOMAIN/REFUSED is generated.

## Wire/input limits

- Message length <=4096 bytes; exactly one IN-class question, nonzero QTYPE. All QTYPEs in that supported question profile are filtered by the same name rules, including AAAA/ANY.
- Standard opcode only, reserved Z bit rejected. Queries allow RD/AD/CD flags and no answer/authority section. Their only supported additional record is one EDNS0 OPT. Unsupported query shapes are rejected, not passed through on selected ports.
- Expanded name wire length <=255; label length <=63. Names accept ASCII letters/digits/hyphen/underscore (service labels supported), normalize case, and expose a single canonical representation. Root is `.`. Binary/escaped labels and raw Unicode are outside this profile and rejected. Configuration can use one trailing dot; no IDNA conversion occurs. Already-encoded ASCII A-labels such as xn--... are matched literally; this is not punycode/confusable validation.
- Compressed resource-owner/selected RDATA names use backward non-header pointers, <=16 pointer hops and no recursion. Self/forward pointers, cycles, unsupported label types and expanded-length overflow are rejected. The first sole question cannot compress against a prior name and must be uncompressed. Decoder does not maintain a registry of all earlier label boundaries; it validates the target encoding, direction and budgets, not full RFC semantic provenance of every pointer.
- Total resource records <=128. Record envelopes/RDLENGTH are bounded; A/AAAA size and common NS/CNAME/PTR/DNAME/MX/SRV/SOA name/length shapes are checked. Other RDATA is length-bounded and opaque. This is not a full semantic validator for every RR/class/EDNS option or newer DNS extension.
- EDNS0 OPT must have literal root owner, version zero, only DO in its flags and <=32 length-checked options. Unknown option payloads are opaque. Query extended RCODE must be zero; response extended codes are not used as security signals.
- Response QR/opcode/question profile and all declared record envelopes must fit. A complete TC-marked response may be returned to the client, but TCP fallback is not implemented by this UDP relay. A partially missing declared record is rejected even with TC set.

## Rule contract

`DomainPolicy` accepts at most 4096 typed rules and an explicit default action. Each rule has a validated DomainName, Exact/DomainAndSubdomains match mode, priority and allow/deny action. Lower numeric priority wins; equal priorities retain input order. Decisions report the original input index. Compilation sorts precedence once; evaluation remains O(R) worst-case. Original Vec/string allocation is caller-owned before validation; an external configuration loader still needs byte limits.

Subdomain matching requires a dot boundary: example.com matches a.example.com, not notexample.com or example.com.evil. Exact rules do not match descendants. A root rule matches the root question only, not all names; use default action for catch-all. No wildcards, regular expressions, public-suffix interpretation or implicit longest-suffix precedence. Use explicit priority for allow exceptions. Domain rules must be constructed successfully before activation.

## UDP transaction/ownership contract

A selected-port query is parsed and domain-checked before any upstream socket opens or any payload is sent. The existing engine still verifies packet checksums, IP policy and capacity. Up to `MAX_DNS_PENDING` (8) pending `(transaction ID, canonical question name, type, class)` entries are retained per active flow, so resolvers that send A and AAAA together from one socket work; the total cannot exceed 8 times the relay's <=1024 flow cap. An identical retransmission refreshes its entry's send time instead of adding one. A new distinct question when the flow already holds 8 returns Busy without replacing or refreshing any pending request; callers retry later or use a distinct source port.

The connected upstream socket's reply must be a supported response matching the exact pending ID/question. Both current domain and inbound packet policy must allow it. A successful response consumes only the entry it answers, in any order; the others stay pending. A reply with no outstanding question at all (a duplicate or late answer) is discarded and the flow is kept. A malformed reply, or one that matches none of the outstanding questions, is dropped and closes that mapping. Failed DNS queries do not open sockets or overwrite an existing legitimate pending question. Protection-before-connect still applies.

Expiry, network reset, valid IP-policy changes and valid DNS-filter changes clear associated pending state and sockets. Invalid filter port configuration leaves previous policy/state intact. Each question has its own lifetime equal to the engine idle timeout, measured from its last send (accepted identical retransmissions refresh it) and enforced lazily on the next send or receive for that flow, so an unanswered question frees its slot independently of the flow; there is no background timer. The caller must drive expiry. Disable explicitly with `set_dns_filter(None, vec![])`, which also revokes mappings.

## Boundaries and limitations

- No CNAME/HTTPS/SVCB alias-chain blocking, response address/CIDR pinning, DNS rebinding defense or IP cache derived from DNS. Valid answer target names may be parsed for structural safety but domain blocking is based on the question only.
- No encrypted DoH/DoT/DoQ inspection, TCP DNS parsing, resolver-authentication or certificate handling. DNS on unselected ports and direct IP access are outside this filter; ordinary packet policy remains in force. Do not claim this prevents all DNS bypass or DNS leaks.
- Connected peers, transaction matching and checksums are not cryptographic authentication. DNSSEC/AD bits, Cookies and signatures are not verified. Original payloads remain unchanged so a client's own DNS validation can still apply.
- Pending question names are local ephemeral state only; no DNS history, logging, telemetry, persistence or cloud service is added. The library does not claim a universal OS memory byte budget.
- APK/UI remains paused. Android diagnostic is not integrated with the relay/filter, and no device/leak/battery claim follows from host loopback tests.

## Evidence and reproduction

`cargo test --workspace` includes compression/length/flags/EDNS/RDATA fixtures, suffix/priority/case boundaries, query/reply correlation and real IPv4/IPv6 loopback tests. Existing normal fmt/Clippy/build/MSRV checks apply. A separate pure DNS fuzz target tries queries, responses and multiple name offsets under a 30-second sanitizer CI budget; it never opens sockets. Four synthetic DNS seeds include a query, compressed answer, EDNS query and compression cycle.

The benchmark harness now has 37 cases (six DNS cases added): query parsing, compressed response parsing and hit/miss domain policies with 64/4096 rules. Historical comparison applies only to the 31 cases shared with its reference commit; new DNS cases establish an initial baseline, not speed claims. See actual PR Actions runs for hosted results; creating a workflow is not passing evidence.

Generic TCP relay now exists independently (TCP_TRANSPORT.md), but this DNS guard is still UDP-only. Configurations requiring classic DNS-domain enforcement must explicitly deny TCP/53 until a TCP stream DNS guard is implemented. Do not infer encrypted-DNS or cross-protocol domain coverage from a UDP rule.
