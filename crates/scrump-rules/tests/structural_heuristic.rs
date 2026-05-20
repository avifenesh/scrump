//! Validates the structural quarantine heuristic (issue #9 long-tail layer).
//!
//! The heuristic auto-quarantines auto-extracted TruffleHog rules whose
//! value pattern has no fixed ≥3-char literal anchor — the shape that
//! floods compiled binaries and JS bundles with false positives. This test
//! pins two guarantees:
//!
//!   1. It NEVER flags a rule that carries a distinctive literal (every
//!      marquee format + the deliberately-kept structural detectors).
//!   2. It DOES flag the bare-character-class provider rules.
//!
//! The companion `fn_marquee` test proves detection still works end to end;
//! this test guards the heuristic's precision so it can't quietly start
//! eating real detectors.

use scrump_rules::rule_is_active;

#[test]
fn keeps_rules_with_distinctive_literal_anchors() {
    // Auto-extracted rules deliberately kept active because their value
    // pattern carries a real literal (or they're on the dual-use
    // allowlist). If the heuristic regresses and flags one of these, real
    // detection breaks silently.
    // These carry a distinctive literal in the *value* and must never be
    // flagged by the structural heuristic. (Some bare-hostname domain
    // detectors that also have literals — okta__domainpat,
    // hashicorpvaultauth__vaulturlpat — are now *explicitly* quarantined
    // by policy, so they're not asserted here.)
    let must_stay_active = [
        "ldap__uripat",                  // `ldap://` — can embed bind creds
        "grafanaserviceaccount__keypat", // `glsa_`
        "privatekey__keypat",            // `BEGIN … PRIVATE KEY`
        "okta__tokenpat",                // allowlisted dual-use
        "azure_cosmosdb__dbkeypattern",  // allowlisted dual-use
    ];
    for id in must_stay_active {
        assert!(
            rule_is_active(id),
            "structural heuristic wrongly quarantined a real detector: {id}"
        );
    }
}

#[test]
fn flags_bare_charclass_provider_rules() {
    // A sample of rules whose value is a bare character class anchored on a
    // weak keyword — these MUST be inactive (explicit list or heuristic).
    let must_be_inactive = [
        "box__keypat",
        "lob__keypat",
        "roaring__secretpat",
        "polygon__keypat",
        "customerguru__keypat",
        "wit__keypat",
    ];
    for id in must_be_inactive {
        assert!(
            !rule_is_active(id),
            "expected {id} to be quarantined (bare-charclass value)"
        );
    }
}
