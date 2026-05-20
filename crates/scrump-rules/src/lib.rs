//! Default rules + YAML loader.
//!
//! The default ruleset (`rules/default.yaml`) is compiled into the binary
//! via `include_str!`. Users override it via `--rules-path FILE.yaml`.

use std::path::Path;

use regex::bytes::Regex;
use scrump_core::{Detector, Result, ScrumpError};
use serde::Deserialize;

const DEFAULT_RULES_YAML: &str = include_str!("../rules/default.yaml");
const TRUFFLEHOG_RULES_YAML: &str = include_str!("../rules/trufflehog.yaml");

/// Auto-extracted TruffleHog rules whose patterns produce unusable noise on
/// real artifacts (issue #9). Each entry was added based on an empirical
/// audit (`tests/noise_audit.rs`) that runs the full ruleset against an
/// ~ 8 MB synthetic corpus mimicking SQLite log text, source code, config
/// files, `.env`-style assignments, alphanumeric blobs, and tar padding.
/// A rule is quarantined when it either fires more than ten times or
/// captures more than 1 KB on that corpus — both dimensions matter
/// because the unbounded-quantifier class (`{N,}` patterns) fires once
/// per blob but eats megabytes per fire, equally destructive for `scrub`.
///
/// These patterns are unsalvageable as scrubber rules: scrump
/// deliberately does not verify candidates against the upstream
/// provider's API (the way TruffleHog does), so per-rule false positives
/// translate one-for-one into destructive overwrites in `scrub`.
///
/// Users who need a quarantined rule can reintroduce it via `--rules-path`.
///
/// Kept in sorted order so the const itself is easy to review.
pub const TH_QUARANTINE: &[&str] = &[
    "adobeio__idpat", // keyword `adobe` + 12 alnums — matches Go strings like `metadatacbor`
    "agora__keypat",  // keyword `agora|key|token` + 32 alnums — matches Go string concatenations
    "agora__secretpat", // keyword `agora|secret` + 32 alnums — matches Go string concatenations
    "aha__keypat",    // keyword `aha` matches `Aha`/`Sahara` + 64 hex (SHA-256 shape)
    "aiven__keypat",  // keyword `aiven` matches `naive`/`having` + 372-char destructive capture
    "alibaba__keypat", // `\b([a-zA-Z0-9]{30})\b` no anchor
    "anypoint__keypat", // UUID, no keyword anchor
    "anypoint__orgpat", // keyword `org` is too generic
    "anypointoauth2__idpat", // keyword `id` + 32 hex — matches any MD5/UUID-like in logs
    "atlassian_v2__organizationidpat", // keyword `org|id` + UUID
    "auth0managementapitoken__managementapitokenpat", // `\b(ey[a-zA-Z0-9._-]+)\b` unbounded
    "auth0oauth__clientidpat", // keyword `auth0` + 32-60 chars — matches Go string concatenations
    "auth0oauth__clientsecretpat", // `\b([a-zA-Z0-9_-]{64,})\b` unbounded — eats megabytes
    "aws_session_keys__sessionpat", // `[a-zA-Z0-9+/]{100,}` unbounded — eats megabytes
    "azure_batch__secretpat", // raw `[A-Za-z0-9+/=]{88}` no anchor
    "azureapimanagement_repositorykey__regex", // `\d+\.\d+\.\d+` — fires on every semver in any log
    "azureapimanagementsubscriptionkey__keypat", // keyword `key` + 32 alnums — fires on every config
    "azure_storage__keypat", // keyword `key` + 86-88 base64 — matches Go string-table concatenations
    "azure_storage__namepat", // keyword `name|storage` + 3-24 lowercase — matches single words `schema`/`autorest`
    "azuredevopspersonalaccesstoken__orgpat", // keyword `azure` + 5-48 chars — fires on JFR/HPROF binary strings
    "azurefunctionkey__keypat", // keyword `azure` + 20-56 chars — matches Go fn names like `CreateOrUpdateSender`
    "azuresearchadminkey__keypat", // keyword `azure` + 52 alnums — matches Go string concatenations
    "azuresearchadminkey__servicepat", // keyword `azure` + 7-40 chars — fires on JFR/HPROF binary strings
    "azuresearchquerykey__keypat",     // keyword `azure` + 52 alnums — duplicate shape
    "box__keypat",                     // keyword `box` matches `box`/`boxer`/`inbox` + 32 alnums
    "boxoauth__clientidpat", // keyword `id` + 32 alnums — duplicate of spotify/shopify hits
    "boxoauth__clientsecretpat", // keyword `secret` + 32 alnums — matches Go function names
    "boxoauth__subjectidpat", // keyword `user|subject|id` + 6-20 digits — every numeric ID matches
    "browserstack__keypat",  // keyword `key` + 20 alnums — fires on every env var
    "browserstack__userpat", // keyword `user|username` + 9-29 alnums — fires on every env var
    "chatbot__keypat", // keyword `chatbot` + alnums — matches AWS SDK fn names like `DeleteMicrosoftTeamsUserIdentity`
    "circleci_v1__keypat", // keyword `circle` + 40 hex — matches every git SHA-1 near the word
    "clickhelp__emailpat", // RFC-shaped email pattern, no provider context
    "clickhelp__keypat", // keyword `key|token|api|secret` + 24 alnums — every config value
    "cloudflareapitoken__keypat", // keyword `cloudflare` + 40 alnums — matches package-name concatenations
    "cloudflareglobalapikey__apikeypat", // keyword `cloudflare` + 37 alnums — matches package-name concatenations
    "cloudflareglobalapikey__emailpat",  // RFC-shaped email pattern, no provider context
    "copper__idpat", // `\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b` email
    "currencycloud__emailpat", // RFC-shaped email pattern, no provider context
    "customerguru__idpat", // keyword `customer|guru` + alnums — matches Go middleware fn names
    "customerguru__keypat", // keyword `customer|guru` + alnums — matches Go type names
    "customerio__idpat", // keyword `customer` + 20 alnums — matches Go fn names like `SetChecksumAlgorithm`
    "customerio__keypat", // keyword `customer` + 20 alnums — same shape
    "datadogapikey__apikeypat", // keyword `dd` + 32 alnums — fires on Go fn names
    "datadogtoken__apipat", // keyword `dd` + 32 alnums — duplicate of datadogapikey
    "datadogtoken__apppat", // keyword `dd` fires on `dd-mm-yyyy` etc.
    "debounce__keypat", // keyword `debounce` + 13 alnums — matches JavaScript function names like `debounceTimer`
    "digitaloceantoken__keypat", // keyword `do` matches every English `do`
    "dockerhub_v1__usernamepat", // keyword `docker|id` + 4-40 alnums — matches `network`
    "dockerhub_v2__emailpat", // RFC-shaped email pattern, no provider context
    "dockerhub_v2__usernamepat", // keyword `id` matches every config field
    "docusign__idpat",  // keyword `integration|id` + UUID
    "docusign__secretpat", // keyword `secret` + UUID — `secret` is generic in any Go binary
    "dotdigital__passpat", // keyword `pw|pass` fires on every config password line
    "algoliaadminkey__keypat", // keyword `algolia` + alnums — matches Go middleware fn names
    "azuresastoken__urlpat", // keyword `sas` + url — matches words like `storageaccount`
    "easyinsight__idpat", // keyword `id` + 20 alnums — every random env value
    "easyinsight__keypat", // keyword `key` + 20 alnums — every random env value
    "elasticemail__keypat", // keyword `elastic` + 96 destructive chars — matches Go TLD data tables
    "eightxeight__idpat", // keyword `8x8` + 18-30 alnums — matches `8x8 grid`/`8x8 pixel` text
    "elevenlabs_v1__keypat", // keyword `el` matches `elephant`, `panel`, `level`, etc.
    "clicksendsms__idpat", // keyword `sms` + email pattern — matches Go module paths
    "clicksendsms__keypat", // `\b([0-9A-Z]{8}-...-{12})\b` UUID, no keyword
    "clientary__idpat", // keyword `ronin|clientary` + 4-25 chars — matches Go fn names like `StringifyMapKeysWithFmt`
    "clockworksms__tokenpat", // keyword `clockwork|textanywhere` + 24 alnums — fires on Go fn names
    "dockerhub_v1__emailpat", // keyword `docker` + email pattern — Go module paths `github.com/x/y@v1.2.3` trigger the `@`
    "flowflu__accountpat",    // keyword `account` is too generic
    "formbucket__keypat", // keyword `formbucket` + 3 unbounded dotted segments — matches `storage.Notification.Config`
    "front__keypat", // keyword `front` matches `frontend`/`confrontation` + 36+188 destructive chars
    "gcpapplicationdefaultcredentials__keypat", // `\{[^{]+client_secret[^}]+\}` greedy — captured 8KB JSON
    "gemini__secretpat",                        // unanchored 27-28 char alnum
    "github_oauth2__oauth2clientidpat", // keyword `github` + 20 alnums — matches GraphQL type names like `CheckConclusionState`
    "github_oauth2__oauth2clientsecretpat", // keyword `github` + 40 hex — matches every git SHA-1
    "githubapp__apppat",                // keyword `github` + 6 digits — matches any 6-digit run
    "gitlab_v1__keypat", // keyword `gitlab` + 20-22 chars — matches Jest matchers like `toHaveBeenCalledWith`
    "gitlaboauth2__clientidpat", // keyword `id` + 64 hex
    "grafanaserviceaccount__domainpat", // keyword `grafana` + domain — matches `drone.grafana.net`
    "groovehq__keypat",  // keyword `groove` + alnums — matches concatenated words
    "guru__unamepat",    // keyword `guru` + email pattern — matches `sass@replayio`
    "intercom__keypat",  // keyword `intercom` + capture — matches surrounding prose
    "jiratoken_v1__tokenpat", // keyword `jira` + alnums — matches Go type names like `FeaturedResultsSetStatus`
    "liveagent__keypat",      // keyword `live` matches `liveagent`/`alive` + alnums (Go fn names)
    "polygon__keypat", // keyword `polygon` matches geometry code like `TangentVisibilityGraphCalculator`
    "redis__keypat",   // keyword `redis` + capture — matches the word `password`
    "roaring__clientpat", // keyword `roaring` matches `orBitmap…` from the roaring bitmap library
    "roaring__secretpat", // keyword `roaring` — duplicate shape
    "zendeskapi__token", // keyword `zendesk` + alnums — matches Go SDK identifiers
    "graphcms__idpat", // keyword `graph` + 25 alnums — matches GraphQL identifiers
    "hashicorpvaultauth__roleidpat", // keyword `role` + UUID — `role` matches every k8s/IAM role string
    "hashicorpvaultauth__secretidpat", // keyword `secret` + UUID — duplicate of docusign__secretpat
    "hive__idpat", // keyword `hive` + 17 alnums — matches code identifiers like `archiveItemConfig`
    "host__keypat", // keyword `host` + 14 lowercase alnum — matches `addressunknown`, etc.
    "ibmclouduserkey__keypat", // keyword `ibm` matches `IBM-`/`ebcdic` text in encoding tables
    "jdbc__pattern", // `(?i)pass.*?=(.+?)\b` matches any config `password=...` line
    "jiratoken_v1__domainpat", // keyword `jira|atlassian` + dotted hostname — matches .NET namespaces like `Markdig.Extensions.NoRefLinks`
    "jiratoken_v2__domainpat", // `\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]{2,16})\b` matches every dotted hostname
    "jiratoken_v2__emailpat",  // RFC-shaped email pattern, no provider context
    "ldap__passwordpat",       // keyword `pass` + quoted 4-48 chars — every config `password='…'`
    "ldap__usernamepat",       // keyword `user` + any quoted string
    "lessannoyingcrm__keypat", // keyword `less` matches `lesson`, `endless`, etc.
    "lob__keypat", // keyword `lob` matches `blob`/`global`/`globe` — captures git SHA-1s in Cargo.lock
    "luno__idpat", // keyword `luno` matches words like `gluon`/`Lunos` + 13 alnums
    "luno__keypat", // keyword `luno` + 43 chars — same broken keyword
    "magicbell__emailpat", // RFC-shaped email pattern, no provider context
    "manifest__keypat", // keyword `manifest` + 32 alnums — matches arbitrary code identifiers
    "mapbox__idpat", // `([a-zA-Z-0-9]{4,32})` no boundary, no keyword
    "mite__keypat", // keyword `mite` matches `committed`/`permitted`/`submit`
    "mongodb__placeholderpasswordpat", // `^[xX]+|\*+$` matches any line starting with x/X or ending with * — broken
    "mux__secretpat", // keyword `mux` matches `demultiplexer`/`multiplex` + 75 base64 chars
    "myfreshworks__idpat", // keyword `freshworks` + 2-20 chars — captures generic words like `freshdesk`
    "mrticktock__emailpat", // RFC-shaped email pattern, no provider context
    "netsuite__accountidpat", // keyword `id|account|netsuite` too broad
    "netsuite__consumerkeypat", // keyword `consumer|key` + 64 alnums — matches SHA-256-shape
    "netsuite__consumersecretpat", // keyword `consumer|secret` + 64 alnums — matches placeholder zeros
    "netsuite__tokenkeypat",       // keyword `token|key` + 64 alnums — duplicate of consumerkey
    "netsuite__tokensecretpat",    // keyword `token|secret` + 64 alnums — matches placeholder zeros
    "ngc__keypat1", // unanchored 84-char alnum — matches Go string-table concatenations
    "oanda__keypat", // keyword `oanda` + 24 alnums — fires on Go binary identifiers
    "onedesk__emailpat", // RFC-shaped email pattern, no provider context
    "onelogin__oauthclientidpat", // keyword `id` + 64 lowercase hex
    "onelogin__oauthclientsecretpat", // keyword `secret` + 64 hex — Go string concatenations
    "linemessaging__keypat", // keyword `line` matches `inlayHint`/LSP method names + 171 chars
    "openvpn__clientidpat", // keyword `openvpn` + 2 dotted segments — matches `u-boot-exception` etc.
    "openvpn__clientsecretpat", // `\b([a-zA-Z0-9_-]{64,})\b` unbounded — eats megabytes
    "paypaloauth__idpat", // `\b([A-Za-z0-9_\.]{7}-[A-Za-z0-9_\.]{72}|...)\b` — matches Go string concatenations
    "paypaloauth__keypat", // `\b([A-Za-z0-9_\.\-]{44,80})\b` no anchor; needs hand-coded rule in default.yaml
    "planetscale__usernamepat", // `\b[a-z0-9]{12}\b` no keyword
    "planetscaledb__usernamepat", // `\b[a-z0-9]{20}\b` no keyword
    "postgres__connstrpartpattern", // `([[:alpha:]]+)='(.+?)' ?` matches every quoted assignment; default.yaml has the proper postgres__uripattern
    "pusherchannelkey__keypat",     // keyword `key` ALONE — fires on every key/value pair
    "razorpay__secretpat", // `\b[A-Za-z0-9]{24}\b` no anchor — the auto-extracted pattern is broken even though the curated version works
    "rev__clientkeypat", // keyword `rev` matches `Reverse`/`revoke`/`revision` followed by 27 chars
    "robinhoodcrypto__privkeybase64pat", // generic base64 with `=`/`==` tail
    "salesforceoauth2__consumersecretpat", // keyword `secret|consumer` + 19-64 alnums
    "salesforcerefreshtoken__consumersecretpat", // same shape as above
    "saucelabs__usernamepat", // keyword `username` + 2-70 alnums — too loose
    "shopifyoauth__clientidpat", // keyword `id` + 32 alnums — duplicate hits of spotify/box
    "signable__keywordpat", // `(?i)([a-z]{2})signable` matches `assignable`, captures only 2 chars
    "signable__tokenpat", // `.{0,2}signable` matches `assignable` followed by 32 alnums
    "snowflake__accountidentifierpat", // keyword `account` + 7-262 chars — matches arbitrary identifiers
    "sirv__keypat", // keyword `sirv` + 88 chars — matches binary garbage in model files
    "sourcegraph__keypat", // third alternative `[a-fA-F0-9]{40}` matches every SHA-1
    "smartsheets__keypat", // keyword `sheet` matches `worksheet`/`spreadsheet` + 26-37 alnums — Go type names
    "sumologickey__keypat", // keyword `sumo|accessKey` + 64 alnums — `accessKey` too generic
    "swell__idpat",        // keyword `swell` matches `Wellknown`/`isWellFormed` + 6-24 alnums
    "sparkpost__keypat",   // `\b([a-zA-Z0-9]{40})\b` no anchor
    "spotifykey__idpat",   // keyword `id` + 32 alnums — duplicate hits of shopify/box
    "spotifykey__secretpat", // keyword `key|secret` + 32 alnums — matches Go function names
    "tableau__tokennamepat", // keyword `name` is too generic
    "thinkific__domainpat", // keyword `thinkific` + 4-40 alnums — captures generic words like `uploader`/`wordpress`
    "twitterconsumerkey__keypat", // keyword `consumer|key` + 25 alnums — matches Go fn names like `generateClientKeyExchange`
    "unifyid__keypat",            // keyword `unify` matches `unified`/`unifying` + 44 alnums
    "verifier__emailpat", // keyword `verifier` + RFC email pattern — fires on any @-shaped Go module path
    "wit__keypat",        // keyword `wit` matches `width`/`switch`/`with` + 32 uppercase alnums
    "wiz__idpat",         // keyword `wiz` matches `Wizard` + alnums — Go middleware fn names
    "wiz__secretpat",     // keyword `wiz` matches `Wizard`/`bewildering` + 64 alnums
    "trelloapikey__tokenpat", // `\b([a-zA-Z-0-9]{64})\b` no anchor
    "tru__keypat",        // keyword `tru` + UUID — same broken keyword as tru__secrepat
    "tru__secrepat",      // keyword `tru` matches `true`, `trust`, etc.
    "twilio__keypat",     // `\b[0-9a-f]{32}\b` — matches every MD5 / 32-char hex
    "twilioapikey__secretpat", // `\b[0-9a-zA-Z]{32}\b` no anchor
    "user__keypat",       // keyword `user` + 64 chars — matches Google profile photo URL fragments
    "wepay__appidpat",    // `\b(\d{6})\b` — every six-digit number
    "zendeskapi__email",  // email pattern, no provider context
    "zipapi__emailpat",   // RFC-shaped email pattern, no provider context
    "zipbooks__emailpat", // RFC-shaped email pattern, no provider context
    "zipbooks__pwordpat", // keyword `zipbooks|password` fires on every config
    "zulipchat__idpat",   // email pattern, no provider context
    // Round 11 (cloud/devops CLIs: aws-cli, minikube, gitleaks, the
    // TruffleHog binary itself). One id per provider — the structural
    // heuristic sweeps each provider's bare-charclass siblings.
    "geocodio__searchpat", // keyword `geocod` + `\S{7,30}` — captured HTML/JSON fragments in botocore models
    "maxmindlicense_v1__keypat", // matched `PutGeoipDatabase` Go symbol
    "sugester__domainpat", // captured `github.com` near keyword — loose domain match
    "kanbantool__domainpat", // captured `Scanner`/`Agithub` — loose domain match
    "scalr__idpat",        // captured `slack`/`github` Go symbols
    "billomat__idpat",     // captured `bitfinex`/`github`
    "textmagic__userpat",  // captured `Scanner`/`github`
    "cashboard__userpat",  // captured `checklyhq`/`github`
    "companyhub__idpat",   // captured `Scanner`/`Agithub`
    "repairshopr__domainpat", // captured `.Scanner`/`Bgithub.com`
    "salesmate__domainpat", // captured `Scanner`/`github`
    // Round 12 (DB tools): artsy fired on Go symbols.
    "artsy__keypat", // captured `outerBoundaryIsinnerBoundaryIsno` Go symbols
    // Round 13 (APK/xpi/AppImage). Browser-extension filter lists are
    // dense with domains + channel IDs.
    "youtubeapikey__idpat", // captured YouTube channel IDs from ad-filter lists
    "mixpanel__idpat",      // captured tracking domains from filter lists
    "shutterstock__secretpat", // captured words like `fullfilmizlesene`
    "airtableoauth__tokenpat", // captured version strings like `quasar.v1.4.1`
    // Policy: bare-hostname domain/URL detectors capture identifiers, not
    // secrets — pure noise for a scrubber. Credential-bearing connection
    // strings (postgres://, mongodb://user:pass@, ldap://) stay active.
    "auth0oauth__domainpat", // captures `cdn.auth0.com` — a hostname, not a secret
    "hashicorpvaultauth__vaulturlpat", // captures `*.hashicorp.cloud` hostname
    "okta__domainpat",       // captures `*.okta.com` tenant hostname
    "zendeskapi__domain",    // captures `*.zendesk.com` subdomains from filter lists
    // Round 14 (conda/firmware/ethereum): geth fired on TLD data.
    "fastlypersonaltoken__keypat", // keyword `fastly` + 32 alnums — matches punycode TLD data
    // Round 15 (composer/elixir/bitcoin/victoriametrics): composer doc string.
    "atlassian_v1__keypat", // captured `oauth-on-bitbucket-cloud` doc string
    // Round 17 (.NET SDK / NuGet / Nim / Crystal): .NET assembly method names.
    "pepipost__keypat", // captured `BuildArgumentsBaseOnEnumTypeName` .NET method names
    "fixerio__keypat",  // captured `InferTypeInNamedFieldInitializer` .NET method names
    "karmacrm__keypat", // captured `JavaScriptSerializer`
    "typeform_v1__keypat", // bare-charclass on .NET symbols
    // Round 18 (rclone/vector/minio/nats/tailscale Go binaries).
    "cloudinary__cloudnamepat",         // captured `users`
    "imagekit__keypat",                 // Go string concatenations
    "apimatic__apikeypat",              // Go string concatenations
    "splunkobservabilitytoken__keypat", // captured `SplunkEventEncodeError` Go symbols
    "rabbitmq__keypat",                 // captured the word `password`
    // Round 19 (Spark/Kafka/Elasticsearch/wasmtime): ES Lucene/config strings.
    "demio__secretpat", // captured the word `AvantGarde`
    // Round 20 (LLVM/gitlab-runner/step-ca/packer/nomad Go binaries).
    "sentrytoken_v1__keypat", // Go symbols in gitlab-runner
    "accuweather_v1__keypat", // captured `ridgewaterBrightscope…` Go concat
    "miro__keypat",           // captured `cubesilverfishvindicator…` Go concat
];

/// Rules that the structural heuristic ([`pattern_is_structurally_noisy`])
/// would flag, but that we deliberately keep active because they catch
/// real secrets despite a value pattern with no fixed literal anchor.
///
/// - `azure_cosmosdb__dbkeypattern` — `[A-Za-z0-9]{86}==` is unanchored
///   but genuinely dual-use (it caught real Grafana API-key JSON blobs in
///   the issue #9 corpus). Largest remaining hit source on base64-dense
///   files; pending a keyword-anchored replacement in `default.yaml`.
/// - `okta__tokenpat` — `\b00[a-zA-Z0-9_-]{40}\b` has only a 2-char `00`
///   anchor but catches real `00…`-prefixed Okta API tokens at a low
///   measured FP rate (~0.07 hits/MB).
const STRUCTURAL_ALLOWLIST: &[&str] = &["azure_cosmosdb__dbkeypattern", "okta__tokenpat"];

/// Returns `true` when a rule id is part of the active ruleset — i.e. it is
/// neither on the explicit [`TH_QUARANTINE`] list nor flagged by the
/// structural heuristic. Exposed so the TruffleHog compat harness can honor
/// the same curation when consulting the auto-generated `provider_map.json`.
pub fn rule_is_active(id: &str) -> bool {
    !TH_QUARANTINE.contains(&id) && !structural_quarantine().contains(id)
}

/// Provider prefix of a rule id (`anypoint__keypat` → `anypoint`).
fn provider_of(id: &str) -> &str {
    id.split("__").next().unwrap_or(id)
}

/// Set of auto-extracted rule ids flagged by [`pattern_is_structurally_noisy`],
/// computed once from the embedded TruffleHog ruleset.
///
/// This is the durable second layer beyond the hand-verified
/// [`TH_QUARANTINE`] list, but it is deliberately conservative: it only
/// quarantines a rule when that rule's **provider already has at least one
/// explicitly-quarantined rule** *and* the rule's value pattern is a bare
/// character class. In other words, once a provider is proven to emit
/// noise on real artifacts, its sibling rules of the same broken shape are
/// swept up automatically — but a provider we've never seen misbehave is
/// never silently dropped (which would be an unobservable recall loss for
/// a scrubber, where under-redaction is a leak).
///
/// A blanket "no value literal → quarantine" rule would flag ~80% of the
/// 1,149 TruffleHog providers; most of those never actually fire on real
/// inputs because their keyword is distinctive, so dropping them only
/// costs recall. Scoping to known-noisy providers keeps the precision win
/// without the recall cost.
fn structural_quarantine() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static SET: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        let noisy_providers: std::collections::HashSet<&str> =
            TH_QUARANTINE.iter().map(|id| provider_of(id)).collect();
        let file: RulesFile = match serde_yaml::from_str(TRUFFLEHOG_RULES_YAML) {
            Ok(f) => f,
            Err(_) => return std::collections::HashSet::new(),
        };
        file.rules
            .into_iter()
            .filter(|r| {
                noisy_providers.contains(provider_of(&r.id))
                    && pattern_is_structurally_noisy(&r.id, &r.pattern)
            })
            .map(|r| r.id)
            .collect()
    })
}

/// Heuristic: a rule produces unusable scrubber noise when its **value**
/// pattern (what gets captured/redacted, ignoring any leading
/// `PrefixRegex` keyword context) contains no fixed literal alphanumeric
/// run of length ≥ 3.
///
/// Real secret formats carry a distinctive literal — `ghp_`, `AKIA`,
/// `nvapi-`, `sk-ant-`, `xoxb-`, `glsa_`, `BEGIN … PRIVATE KEY`, an
/// `.okta.com` host, etc. A value that is pure character classes +
/// quantifiers + anchors (`\b([0-9a-zA-Z]{32})\b`) matches any identifier
/// of that length, so anchoring it on a keyword produces false positives
/// wherever that keyword appears incidentally (it always does in a binary
/// that vendors the provider's SDK).
///
/// Applied only to rules whose provider is already known noisy (see
/// [`structural_quarantine`]). The [`STRUCTURAL_ALLOWLIST`] exempts
/// deliberately-kept dual-use rules.
fn pattern_is_structurally_noisy(id: &str, pattern: &str) -> bool {
    if STRUCTURAL_ALLOWLIST.contains(&id) {
        return false;
    }
    !has_literal_anchor(value_part(pattern), 3)
}

/// Strip a leading auto-extracted `PrefixRegex` keyword context
/// (`(?i:kw1|kw2)(?:.|[\n\r]){0,N}?`) or a leading `(?i)` global flag,
/// returning the value portion of the pattern. The keyword context only
/// says *where* to look; the value says *what* to capture, and that is
/// what determines whether the match identifies a real secret.
fn value_part(pattern: &str) -> &str {
    let marker = "(?:.|[\\n\\r]){0,";
    if let Some(i) = pattern.find(marker) {
        let after = &pattern[i + marker.len()..];
        if let Some(j) = after.find("}?") {
            return &after[j + 2..];
        }
    }
    pattern.strip_prefix("(?i)").unwrap_or(pattern)
}

/// True if `s` contains a run of at least `min_run` consecutive literal
/// alphanumeric characters — i.e. characters that are part of the matched
/// text, not regex metacharacters, character-class contents, quantifier
/// digits, or escape sequences.
fn has_literal_anchor(s: &str, min_run: usize) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    let mut run = 0usize;
    let mut in_class = false;
    let mut in_brace = false;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            // Escape sequence (`\b`, `\d`, `\.`): consumes the next char,
            // never a literal.
            run = 0;
            i += 2;
            continue;
        }
        match c {
            b'[' if !in_class => {
                in_class = true;
                run = 0;
            }
            b']' if in_class => {
                in_class = false;
                run = 0;
            }
            b'{' if !in_class => {
                in_brace = true;
                run = 0;
            }
            b'}' if in_brace => {
                in_brace = false;
                run = 0;
            }
            _ if in_class || in_brace => {
                run = 0;
            }
            _ if c.is_ascii_alphanumeric() => {
                run += 1;
                if run >= min_run {
                    return true;
                }
            }
            _ => {
                run = 0;
            }
        }
        i += 1;
    }
    false
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize, Clone)]
struct RuleDef {
    id: String,
    pattern: String,
    #[serde(default)]
    min_entropy: Option<f64>,
    /// If set, hits report the n-th capture group instead of the full match.
    #[serde(default)]
    capture_index: Option<usize>,
}

pub struct YamlDetector {
    id: String,
    pattern: Regex,
    min_entropy: Option<f64>,
    capture_index: Option<usize>,
}

impl YamlDetector {
    fn from_def(def: RuleDef) -> Result<Self> {
        let pattern = Regex::new(&def.pattern).map_err(|e| {
            ScrumpError::Other(format!("rule {}: regex compile failed: {}", def.id, e))
        })?;
        Ok(Self {
            id: def.id,
            pattern,
            min_entropy: def.min_entropy,
            capture_index: def.capture_index,
        })
    }
}

impl Detector for YamlDetector {
    fn id(&self) -> &str {
        &self.id
    }
    fn pattern(&self) -> &Regex {
        &self.pattern
    }
    fn min_entropy(&self) -> Option<f64> {
        self.min_entropy
    }
    fn capture_index(&self) -> Option<usize> {
        self.capture_index
    }
}

/// Load detectors from the embedded default ruleset (curated rules +
/// auto-extracted TruffleHog mirror minus the quarantined-for-noise rules
/// + hand-coded detectors that need post-pattern logic regex can't express).
pub fn default_detectors() -> Result<Vec<Box<dyn Detector>>> {
    let mut all = parse_yaml(DEFAULT_RULES_YAML)?;
    let th = parse_yaml_filtered(TRUFFLEHOG_RULES_YAML, rule_is_active)?;
    all.extend(th);

    // Replace every JWT pattern with our HMAC-aware detector. Both the
    // curated `jwt_token` and the auto-extracted `jwt__keypat` are dropped.
    all.retain(|d| d.id() != "jwt_token" && !d.id().starts_with("jwt__"));
    all.push(Box::new(custom::JwtHsAware::new()));

    Ok(all)
}

mod custom {
    use base64::Engine;
    use regex::bytes::Regex;
    use scrump_core::Detector;
    use std::sync::OnceLock;

    /// JWT detector that mirrors TruffleHog's behaviour: matches the
    /// canonical three-segment JWT shape, then base64-decodes the header
    /// and rejects the hit when the `alg` claim is HMAC (`HS256`,
    /// `HS384`, `HS512`, or any other `HS*`). HMAC-signed JWTs are
    /// useless without the shared secret — TruffleHog drops them post-
    /// pattern, and so do we.
    pub struct JwtHsAware;

    impl JwtHsAware {
        pub fn new() -> Self {
            Self
        }
    }

    impl Detector for JwtHsAware {
        fn id(&self) -> &str {
            "jwt_token"
        }
        fn pattern(&self) -> &Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| {
                Regex::new(
                    r"\b(?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{8,}={0,2}\.(?:eyJ|ewo)[A-Za-z0-9_-]{8,}={0,2}\.[A-Za-z0-9_-]{8,}",
                )
                .expect("hand-written JwtHsAware regex must compile")
            })
        }
        fn min_entropy(&self) -> Option<f64> {
            Some(3.5)
        }
        fn post_filter(&self, candidate: &[u8]) -> bool {
            // Extract the header (first segment).
            let dot = match candidate.iter().position(|&b| b == b'.') {
                Some(i) => i,
                None => return false,
            };
            let header_b64 = &candidate[..dot];
            // Strip any base64 padding `=` chars.
            let trimmed = match std::str::from_utf8(header_b64) {
                Ok(s) => s.trim_end_matches('='),
                Err(_) => return false,
            };
            // JWT uses base64url-without-padding.
            let cfg = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let decoded = match cfg.decode(trimmed.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    // Header didn't decode — accept the hit (we'd rather
                    // over-redact than under-redact something we can't
                    // confidently identify).
                    return true;
                }
            };
            let text = match std::str::from_utf8(&decoded) {
                Ok(s) => s,
                Err(_) => return true,
            };
            // Cheap JSON-claim grep — match `"alg":"…"` regardless of spaces.
            let needle = "\"alg\"";
            let Some(p) = text.find(needle) else {
                // No alg field — accept (unknown shape, conservatively redact).
                return true;
            };
            let after = &text[p + needle.len()..];
            // Skip `:` and any whitespace, then look at the value.
            let after = after.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            let after = after.trim_start_matches('"');
            // If `alg` starts with HS (HS256, HS384, HS512, etc.), drop.
            !after.starts_with("HS")
        }
    }
}

/// Load detectors from a YAML file on disk.
pub fn detectors_from_path(p: &Path) -> Result<Vec<Box<dyn Detector>>> {
    let s = std::fs::read_to_string(p)?;
    parse_yaml(&s)
}

fn parse_yaml(s: &str) -> Result<Vec<Box<dyn Detector>>> {
    parse_yaml_filtered(s, |_| true)
}

/// Parse a YAML ruleset, retaining only rules whose id satisfies `keep`.
/// Used to drop quarantined rules from the auto-extracted TruffleHog set.
fn parse_yaml_filtered(s: &str, keep: impl Fn(&str) -> bool) -> Result<Vec<Box<dyn Detector>>> {
    let file: RulesFile =
        serde_yaml::from_str(s).map_err(|e| ScrumpError::Other(format!("yaml parse: {e}")))?;
    file.rules
        .into_iter()
        .filter(|d| keep(&d.id))
        .map(|d| YamlDetector::from_def(d).map(|x| Box::new(x) as Box<dyn Detector>))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ruleset_compiles() {
        let dets = default_detectors().expect("default rules must compile");
        assert!(!dets.is_empty(), "default ruleset must not be empty");
        // sanity: at least the GH PAT rule we know about
        let ids: Vec<&str> = dets.iter().map(|d| d.id()).collect();
        assert!(
            ids.contains(&"github_pat_classic"),
            "missing github_pat_classic in default ruleset: {ids:?}"
        );
    }

    #[test]
    #[ignore = "diagnostic — run with --ignored --nocapture"]
    fn structural_quarantine_stats() {
        let file: RulesFile = serde_yaml::from_str(TRUFFLEHOG_RULES_YAML).unwrap();
        let total = file.rules.len();
        let explicit = TH_QUARANTINE.len();
        let structural = structural_quarantine().len();
        let only_structural = structural_quarantine()
            .iter()
            .filter(|id| !TH_QUARANTINE.contains(&id.as_str()))
            .count();
        let active = file.rules.iter().filter(|r| rule_is_active(&r.id)).count();
        println!("total TH rules:            {total}");
        println!("explicit TH_QUARANTINE:    {explicit}");
        println!("structural-flagged:        {structural}");
        println!("  new (not in explicit):   {only_structural}");
        println!("active after both layers:  {active}");
    }

    #[test]
    fn duplicate_ids_are_loaded_as_separate_detectors() {
        // Sanity check that the YAML parser accepts two rules with the same id
        // (we don't enforce uniqueness; the detection engine just runs both).
        let yaml = "rules:\n  - id: dup\n    pattern: 'aaa'\n  - id: dup\n    pattern: 'bbb'\n";
        let dets = parse_yaml(yaml).unwrap();
        assert_eq!(dets.len(), 2);
    }

    #[test]
    fn bad_regex_surfaces_error() {
        let yaml = "rules:\n  - id: bad\n    pattern: '['\n";
        assert!(parse_yaml(yaml).is_err());
    }
}
