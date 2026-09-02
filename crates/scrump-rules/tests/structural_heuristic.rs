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
        // The Harvest bearer token (97 chars). `harvest__idpat` — the paired ACCOUNT id, a bare
        // 4-9 digit integer — is explicitly quarantined, which makes `harvest` a known-noisy
        // provider and puts every sibling rule of the same bare-charclass shape in reach of the
        // structural sweep. The token rule is the only thing that detects a real Harvest
        // credential, so it is allowlisted rather than swept. Without that allowlist entry this
        // assertion is what goes red.
        "harvest__keypat",
        // The Survey Anyplace API key (32 alnum). Its sibling `surveyanyplace__idpat` — the same
        // shape plus a hyphen in the class, so it matched any 36-char slug near the word
        // "survey" — is explicitly quarantined, which makes `surveyanyplace` a known-noisy
        // provider and puts this rule in reach of the structural sweep. It is the only rule that
        // detects a real key for this provider, and it measured zero hits on three real corpora,
        // so it is allowlisted rather than swept. Without the allowlist entry this goes red.
        "surveyanyplace__keypat",
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
        // Harvest ACCOUNT id: keyword `harvest` + `\b([0-9]{4,9})\b`. Not a credential at all —
        // see the TH_QUARANTINE entry for the measured hit distribution.
        "harvest__idpat",
        // Survey Anyplace "id": keyword `(?i:survey)` + `\b([a-z0-9A-Z-]{36})\b`. The hyphen in
        // the class means any 36-char hyphenated slug near the English word "survey" — see the
        // TH_QUARANTINE entry for the measured captures.
        "surveyanyplace__idpat",
    ];
    for id in must_be_inactive {
        assert!(
            !rule_is_active(id),
            "expected {id} to be quarantined (bare-charclass value)"
        );
    }
}
