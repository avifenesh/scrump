# Security Policy

`scrump` is a security tool. Its job is to make sure secrets and PII
**don't** survive in shared capture artifacts. A vulnerability here can
mean a leak that the user thought was already redacted — so we take
disclosure handling seriously.

## Reporting a vulnerability

**Please don't open a public GitHub issue for a security bug.** Instead:

- Use GitHub Private Vulnerability Reporting:
  <https://github.com/avifenesh/scrump/security/advisories/new>
- Or email <aviarchi1994@gmail.com> with subject prefix `[scrump-security]`.

You should expect:

| | |
|---|---|
| Initial acknowledgement | within **3 business days** |
| Triage decision (accept / out-of-scope / duplicate) | within **7 business days** |
| Patch released for an accepted, fixable report | **30 days target**, longer if a coordinated CVE is warranted |
| Public disclosure | after a fix ships, or 90 days from triage — whichever comes first, with reporter credit unless you ask otherwise |

If your report involves a real leaked credential captured in the wild,
**rotate it first**, then report — we don't need the live token to
reproduce.

## What's in scope

A bug is in scope if it causes any of the following on a file we claim
to support:

- **Leak past redaction**: `scrump scrub` returns exit 0 on a file that
  still contains a secret matching a default-ruleset rule (in raw bytes,
  decompressed bytes, or as parsed by the format's native tooling).
- **Structural corruption**: `scrump scrub` produces a file the format's
  native tool can no longer open, when the equivalent unscrubbed file
  could.
- **Path-traversal / write-outside-target**: `scrub` or `scan` writes
  outside the intended destination.
- **Crash on adversarial input**: panic, OOM, or pathological CPU
  usage triggered by a malformed but well-formed-enough capture file.
- **Rule-engine RCE**: arbitrary code execution through `--rules-path`
  YAML (we use serde_yaml's safe loader; if there's a way around it,
  we want to know).
- **Verification-mode credential leak**: `scrump verify` sending a
  matched candidate to the wrong endpoint or logging it inappropriately.

## What's out of scope

These aren't security bugs — they're known limitations or design choices:

- **Detection FNs from regex-engine limits**: Rust's `regex` crate
  doesn't support lookbehind / backreferences. Patterns that need them
  (Microsoft Presidio's IP, MAC, Canadian SIN with backref-bound
  separators) are best-effort. Filed as detection-quality issues, not
  security issues.
- **Cross-provider over-detection in the auto-extracted ruleset**:
  trufflehog-mirrored rules occasionally fire on inputs the upstream
  detector wouldn't have. Over-detection in a scrubbing tool is the
  conservative direction (more redaction, not less).
- **Encrypted blob bypass**: scrump doesn't try to decrypt content. If
  a token lives inside an encrypted member, the user must decrypt
  before scrubbing.
- **Side-channel via file length**: zero-fill preserves length, so a
  short-vs-long redaction reveals the secret's length. This is by
  design — the alternative (re-length the file) breaks structural
  validity for every supported format. If your threat model includes
  length-as-channel, follow `scrub` with a re-encode step.
- **Slack page / Discord disclosure**: reports must go through one of
  the channels above. We don't monitor chat for security issues.

## Supported versions

We security-patch the most recent **two minor releases** on the `0.x`
line, and the most recent **two minor releases** on the latest stable
line once we ship `1.0`. Older releases get a CVE entry but no
backported patch.

| Version | Supported |
|---|---|
| `0.1.x` (current) | ✅ |
| earlier `0.0.*` pre-releases | ❌ |

## Disclosure credit

We credit reporters in the release notes and the CHANGELOG, unless the
reporter explicitly requests anonymity. Bug bounty: we don't run one.
