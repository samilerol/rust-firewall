use netscope_dns::{DomainName, DomainPolicy, Match, Rule, MAX_RULES};
use netscope_policy::Action;
fn rule(name: &str, kind: Match, priority: u32, action: Action) -> Rule {
    Rule {
        name: DomainName::new(name).unwrap(),
        kind,
        priority,
        action,
    }
}
#[test]
fn exact_subdomain_boundaries_case_and_root_are_deterministic() {
    let p = DomainPolicy::new(
        vec![rule(
            "Example.COM.",
            Match::DomainAndSubdomains,
            10,
            Action::Deny,
        )],
        Action::Allow,
    )
    .unwrap();
    for name in ["example.com", "EXAMPLE.COM.", "a.b.example.com"] {
        assert_eq!(
            p.decide(&DomainName::new(name).unwrap()).action,
            Action::Deny
        );
    }
    for name in ["notexample.com", "example.com.evil", "com", "."] {
        assert_eq!(
            p.decide(&DomainName::new(name).unwrap()).action,
            Action::Allow
        );
    }
    let p = DomainPolicy::new(
        vec![rule("example.com", Match::Exact, 1, Action::Deny)],
        Action::Allow,
    )
    .unwrap();
    assert_eq!(
        p.decide(&DomainName::new("a.example.com").unwrap()).action,
        Action::Allow
    );
    let root = DomainPolicy::new(
        vec![rule(".", Match::DomainAndSubdomains, 0, Action::Deny)],
        Action::Allow,
    )
    .unwrap();
    assert_eq!(
        root.decide(&DomainName::new("com").unwrap()).action,
        Action::Allow
    );
}
#[test]
fn priorities_ties_defaults_and_original_indices_are_preserved() {
    let p = DomainPolicy::new(
        vec![
            rule("example.com", Match::DomainAndSubdomains, 10, Action::Deny),
            rule("safe.example.com", Match::Exact, 5, Action::Allow),
            rule("safe.example.com", Match::Exact, 5, Action::Deny),
        ],
        Action::Deny,
    )
    .unwrap();
    let d = p.decide(&DomainName::new("safe.example.com").unwrap());
    assert_eq!(d.action, Action::Allow);
    assert_eq!(d.rule_index, Some(1));
    assert_eq!(
        p.decide(&DomainName::new("other.example.com").unwrap())
            .action,
        Action::Deny
    );
    assert_eq!(
        p.decide(&DomainName::new("other.test").unwrap()).rule_index,
        None
    );
}
#[test]
fn rule_count_is_bounded() {
    let r = rule("example.com", Match::Exact, 0, Action::Deny);
    assert!(DomainPolicy::new(vec![r.clone(); MAX_RULES], Action::Deny).is_ok());
    assert!(DomainPolicy::new(vec![r; MAX_RULES + 1], Action::Allow).is_err());
}
