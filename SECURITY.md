# Security policy

This is experimental security software, not an operational Android firewall. Supported development target: latest main and active milestone branch. No production security guarantee is offered.

Report suspected vulnerabilities privately using this repository's GitHub private vulnerability reporting feature if enabled. If unavailable, ask the maintainer to establish a private reporting channel without posting exploit details publicly. Never include browsing histories, credentials or private source in reports. Provide version/commit, affected boundary, reproducer, expected behavior and impact. No response-time SLA is promised.

Review untrusted packet lengths, arithmetic, parser rejection behavior, rule precedence, bounded state and clock handling. Future JNI, TUN, sockets, privileged adapters and rule updates require their own validation. See docs/SECURITY_MODEL.md for current scope and limits.
