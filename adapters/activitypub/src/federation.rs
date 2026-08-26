//! The federation switch (D12).
//!
//! Federation ships **off**, and every federation code path still runs. Those
//! are not in tension: the switch gates delivery to *other hosts*, and local
//! delivery — one member on this instance to another — goes out regardless.
//! So signing, queueing, inbox verification and the processors are all
//! exercised on every local post, and turning federation on is a one-line
//! change to something already known to work.
//!
//! The predecessor shipped the flag too, and §0 of the learnings records that
//! this part worked: "shipped fully integrated with `federation_enabled =
//! false`, so every crypto and delivery path was exercised locally." Keeping
//! the flag is deliberate continuity, not caution.

use url::Url;

/// Whether this instance talks to other instances.
///
/// A constant, not configuration: Phase 8 flips it in a one-line commit once
/// relay registration, remote-actor caching and the moderation surface exist
/// (plan §3). Making it an environment variable would let it be turned on
/// before those land, which is exactly what the phase ordering is for.
pub const FEDERATION_ENABLED: bool = false;

/// Is this inbox served by us?
///
/// True for the apex and for any of our user subdomains. A nested subdomain is
/// **not** local: `evil.alice.brolly.id` is a host someone else can point at us,
/// and treating it as local would let it receive deliveries that bypass the
/// federation switch entirely.
pub fn is_local(inbox: &Url, base_domain: &str) -> bool {
    let Some(host) = inbox.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let base = base_domain.to_ascii_lowercase();

    if host == base {
        return true;
    }
    match host.strip_suffix(&format!(".{base}")) {
        Some(label) => !label.is_empty() && !label.contains('.'),
        None => false,
    }
}

/// Should this delivery leave the queue?
///
/// Local always; remote only once federation is on. A suppressed delivery is
/// dropped rather than deferred — Phase 8 is not a backlog to flush, and
/// holding weeks of undelivered activities would make the flip a thundering
/// herd aimed at instances that never asked for it.
pub fn should_deliver(inbox: &Url, base_domain: &str) -> bool {
    is_local(inbox, base_domain) || FEDERATION_ENABLED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test url")
    }

    #[test]
    fn federation_is_off_until_phase_8() {
        // `black_box` because the compiler would otherwise fold this to
        // `assert!(true)` and optimize the whole test away — which clippy
        // rightly flags. The tripwire is the point: flipping the constant has
        // to fail something, so that turning federation on is a deliberate act
        // with Phase 8's prerequisites in hand rather than a stray edit.
        assert!(
            !std::hint::black_box(FEDERATION_ENABLED),
            "D12: federation ships dormant. Phase 8 flips this, and it is the \
             commit that needs relay registration, remote-actor caching and the \
             moderation surface in place first."
        );
    }

    #[test]
    fn the_apex_and_user_subdomains_are_local() {
        assert!(is_local(&url("https://brolly.id/inbox"), "brolly.id"));
        assert!(is_local(&url("https://alice.brolly.id/inbox"), "brolly.id"));
        assert!(is_local(&url("https://ALICE.BROLLY.ID/inbox"), "brolly.id"));
    }

    #[test]
    fn other_hosts_are_not_local() {
        assert!(!is_local(
            &url("https://mastodon.social/inbox"),
            "brolly.id"
        ));
        assert!(!is_local(&url("https://notbrolly.id/inbox"), "brolly.id"));
        // Suffix matching without the dot would call this local.
        assert!(!is_local(&url("https://evilbrolly.id/inbox"), "brolly.id"));
    }

    #[test]
    fn a_nested_subdomain_is_not_local() {
        // Anyone can point `evil.alice.brolly.id` at us. Treating it as local
        // would hand it deliveries that skip the federation switch.
        assert!(!is_local(
            &url("https://evil.alice.brolly.id/inbox"),
            "brolly.id"
        ));
    }

    #[test]
    fn local_delivery_runs_with_federation_off() {
        // This is what keeps the dormant code exercised: every local post signs,
        // queues, delivers and is verified on arrival.
        assert!(should_deliver(
            &url("https://alice.brolly.id/inbox"),
            "brolly.id"
        ));
        assert!(should_deliver(&url("https://brolly.id/inbox"), "brolly.id"));
    }

    #[test]
    fn remote_delivery_is_suppressed_with_federation_off() {
        assert_eq!(
            should_deliver(&url("https://mastodon.social/inbox"), "brolly.id"),
            FEDERATION_ENABLED,
            "remote delivery must track the switch and nothing else"
        );
    }
}
