# Security Policy

## Authorized use only

Use ScopeLynx only against systems you own or are explicitly authorized to assess.
`--authorized`, profiles, and wordlists are technical guardrails and do not create legal authority.

## Threat model and controls

Untrusted inputs include targets, DNS, redirects, URLs, headers, compressed bodies, HTML, XML,
JSON, JavaScript text, wordlists, profiles, report files, and output paths.

- Same-origin scope is the default. Expanded hosts, subdomains, private networks, sensitive paths,
  and body storage require explicit acknowledgement. The authorized-sensitive profile enables
  LAN/private destinations by design and therefore cannot run without `--authorized`.
- All destination IPs are validated before pinned connection use. System proxies and automatic
  redirects/retries are disabled.
- Only GET is issued. Candidate and redirect paths associated with logout, account removal,
  revocation, and similar state changes are rejected.
- Real send attempts acquire the global atomic budget. Per-origin pacing and scheduler concurrency
  cap load.
- Aggressive authorized defaults remain bounded and can be reduced per run; live progress is
  throttled to avoid turning console rendering into a scheduler bottleneck.
- Response capture is bounded after transparent decompression. Parsers receive only captured data
  and apply smaller candidate/document limits.
- Reports retain allowlisted headers. `Set-Cookie` values are replaced before analysis; request
  credentials and session state are never imported.
- Central redaction removes URL credentials, fragments, query values, authorization/bearer tokens,
  secret assignments, private keys, cloud credential patterns, and local Windows paths before
  persistence.
- Output host components are sanitized, reserved Windows device names are escaped, pre-existing
  symlinked host directories are rejected, and report writes use a synced temporary file plus
  rename. Stored bodies must match their SHA-256 file name.

## Residual risks

DNS pinning is scoped to a scan/client cache and deliberately ignores legitimate DNS changes during
that lifetime. Heuristic analyzers can produce false positives or negatives. Static parsing does
not model browser execution. Windows output ACLs depend on the containing directory. Secure
checkpoint/resume and authenticated crawling are not implemented.

Reports may still contain public paths, hosts, technology names, email domains (never local parts),
and bounded security evidence. Treat scan output as confidential assessment data. Body storage is
off by default and should be enabled only when necessary.

## Vulnerability reporting

Do not publish a scanner vulnerability before coordinated remediation. Include the affected
version, minimal reproduction, impact, relevant platform, and a suggested mitigation if known. Do
not include live third-party secrets or unauthorized target data.

## Non-goals

Exploit execution, password attacks, account enumeration, CAPTCHA/WAF bypass, stealth/evasion,
payload injection, state-changing requests, form submission, authentication scraping, secret use,
and cross-scope crawling are intentionally unsupported.
