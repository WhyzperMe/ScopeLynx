# ScopeLynx

ScopeLynx is an asynchronous, scope-controlled Rust web vulnerability scanner for authorized
defensive assessment. It discovers public web resources, captures bounded response metadata,
correlates evidence into findings, and emits deterministic report views without submitting forms,
executing JavaScript, or performing exploit probes.

## Safety boundaries

- GET only; no POST, PUT, PATCH, DELETE, login, form submission, or payload injection.
- Same-origin scope by default. Every redirect is scope-checked before the next connection.
- All resolved addresses are validated; public scans block loopback, private, link-local,
  multicast, documentation, benchmark, reserved, and IPv4-mapped private IPv6 destinations.
- Private destinations, extra hosts, subdomains, sensitive paths, and body storage require an
  explicitly authorized configuration. `--authorized` records acknowledgement; it is not proof
  of legal permission.
- DNS results are pinned into host-specific clients, system proxies are disabled, and reqwest's
  implicit retry mechanism is disabled.
- Redirects, retries, normal requests, and soft-404 probes share one atomic wire-request budget.
- Bodies, headers, DNS answers, queues, candidates, errors, evidence, findings, and wordlists are
  bounded.
- URL credentials, fragments, query values, cookie values, authorization values, token patterns,
  private keys, and common cloud credentials are redacted before reporting.

Use the scanner only against assets you own or have explicit permission to assess.

## Windows 11 installation

Install [Rust through rustup](https://rustup.rs/), then open PowerShell 7 or newer:

```powershell
Set-Location -LiteralPath 'C:\Users\Denni\Documents\ScopeLynx'
rustup show
cargo build --release --locked
```

The declared minimum Rust version is 1.85.0; local validation uses the stable toolchain selected by
`rust-toolchain.toml`.

## Safe quick start

First inspect the effective plan. `--dry-run` performs no DNS lookup, network connection, or output
write:

```powershell
cargo run --release -- scan https://example.com `
    --profile .\profiles\safe.toml `
    --dry-run
```

After confirming authorization, remove `--dry-run` to start the scan. The safe profile deliberately
does not accept wordlists.

## CLI reference

```text
scopelynx scan <URL> [OPTIONS]
scopelynx diff <PREVIOUS> <CURRENT> [--output <FILE>]
scopelynx inspect <REPORT>
scopelynx validate-profile <PROFILE>
scopelynx completion <SHELL>
```

Important scan options:

```text
--profile <FILE>                 Strict TOML profile
--wordlist <FILE>                Additional bounded wordlist (repeatable)
--scope <HOST>                   Explicit additional host (repeatable, authorized)
--allow-subdomains               Expand to target subdomains (authorized)
--allow-private                  Permit validated private targets (authorized)
--authorized                     Explicit safety acknowledgement
--max-depth <N>                  Override discovery depth
--max-requests <N>               Override real wire-request budget
--max-urls <N>                   Override queue/inventory URL bound
--max-findings <N>               Override retained-finding bound
--concurrency <N>                Override concurrent scheduler tasks
--rate <N>                       Override requests per origin per second
--timeout <SECONDS>              Override request timeout
--max-body-size <BYTES>          Override post-decompression capture limit
--output <DIRECTORY>             Output root (default: output)
--format <all,json,markdown,text,sarif>
--fail-on <low,medium,high,critical>  CI finding threshold (exit 5)
--store-bodies                   Store classified bounded bodies by SHA-256 (authorized)
--dry-run                        Validate and print plan; never connect
--no-progress                    Disable periodic progress and live finding events
--quiet / --verbose / --json-logs
```

Generate PowerShell completion:

```powershell
cargo run -- completion powershell | Out-String
```

Exit codes are `0` success, `1` internal failure, `2` configuration failure, `3` scope or
authorization rejection, `4` network/resource exhaustion, `5` configured finding threshold
reached, and `6` incompatible report schema.

## Profiles and authorization

- `profiles/safe.toml`: same origin, low rate, small budgets, no JavaScript discovery, no wordlist,
  no sensitive paths, no bodies.
- `profiles/standard.toml`: same origin, bounded 12-task/8-request-per-second discovery including
  static JavaScript and optional non-sensitive wordlists. Private IPs remain blocked unless
  `--allow-private --authorized` is supplied.
- `profiles/authorized-sensitive.toml`: high-throughput 32-task/40-request-per-second LAN+WAN
  assessment with larger bounded discovery and a small sensitive-path vocabulary. It always
  requires `--authorized`; it still does not exploit, submit, authenticate, or evade controls.

Profiles reject unknown fields. CLI overrides are validated against hard upper bounds and the
aggregate in-flight body-memory limit.

Example authorized sensitive scan:

```powershell
cargo run --release -- scan https://owned.example `
    --profile .\profiles\authorized-sensitive.toml `
    --wordlist .\example_wordlist\authorized-sensitive.txt `
    --authorized `
    --output .\output
```

When a target hostname resolves to RFC1918, loopback, or another non-public address, the
authorized-sensitive profile permits the validated pinned address. With other profiles, add both
`--allow-private` and `--authorized` explicitly:

```powershell
cargo run --release -- scan http://192.168.1.101 `
    --profile .\profiles\standard.toml `
    --allow-private `
    --authorized
```

## Live output and performance

Normal scans emit a start event, periodic one-second progress events, medium-or-higher findings as
they are discovered, and the final summary. URLs in output are centrally redacted. `--verbose`
additionally logs every completed request; `--no-progress` disables progress/finding events, and
`--quiet` leaves only errors.

The authorized-sensitive defaults are intentionally aggressive but bounded: 32 concurrent tasks,
40 requests per second per origin, 50,000 real wire attempts, depth 5, and 200,000 discovered URLs.
Redirects, retries, and soft-404 probes consume the same atomic budget. For fragile targets or
production systems, reduce load with `--concurrency`, `--rate`, and `--max-requests`; for example:

```powershell
cargo run --release -- scan https://owned.example `
    --profile .\profiles\authorized-sensitive.toml `
    --authorized `
    --concurrency 8 `
    --rate 5 `
    --max-requests 5000
```

## Discovery and OSINT functions

The scanner performs bounded discovery from HTML links and assets, canonical/alternate resources,
images and `srcset`, frames, GET form actions, meta refresh, OpenGraph/Twitter URL metadata,
JSON-LD, robots allow/sitemap directives, sitemaps and sitemap indexes, Atom/RSS links, web
manifests, static JavaScript URL strings, source maps, public documents, API/GraphQL/OpenAPI-style
paths, and optional wordlists. Robots `Disallow` paths are recorded by neither fetching nor
enqueueing them automatically.

Content is classified using media type, path, magic bytes, and a bounded body prefix. Analyzer
families cover response headers, cookie attributes (never values), forms, technologies, documents,
endpoints, directory listings, source maps, stack traces, and signature-confirmed sensitive
exposures. Findings include stable IDs, confidence, bounded evidence, remediation, tags, and an
analyzer version.

## Reports and change detection

Each scan creates:

```text
output/<sanitized-host>/<timestamp>-<pid>-<sequence>/
├── report.json
├── report.md
├── report.sarif
├── summary.txt
└── bodies/                  # only with --store-bodies
```

`report.json` (schema 4; schema 3 remains readable) is the source of truth. It contains the scan ID, configuration
fingerprint, policy snapshot, wire/scheduler counters, bounded observations, redirect chains,
the exact final-response HTTP-status histogram, semantic soft-404 reasons, inventory, findings, truncation
flags, non-fatal errors, and completion state.
Other formats are derived views.

HTTP status and semantic existence are deliberately separate. A catch-all server may return raw
status 200 for a missing path; the observation retains `status = 200` while `soft_404 = true`
records that the resource is semantically absent. Such responses never reach analyzers. Status 304
is represented as Not Modified, native 404/410 as Not Found, 429 as Rate Limited, and 5xx as Server
Error. Markdown and text reports include the exact per-status counts.

```powershell
cargo run -- inspect .\output\example.org\<run>\report.json
cargo run -- diff .\previous\report.json .\current\report.json
cargo run -- diff .\previous\report.json .\current\report.json --output .\report-diff.json
```

## Checkpoint and resume status

Checkpoint/resume is intentionally not exposed in version 0.3.2. A checkpoint containing only
redacted signed/query-bearing URLs cannot reliably reproduce request semantics, while persisting
raw URLs would violate the privacy contract. Interrupted scans therefore produce no resumable
checkpoint. Implementing encrypted, authenticated checkpoints with explicit key handling is the
recommended next feature; no placeholder flags claim otherwise.

## Quality gates and CI

Run all mandatory local gates from PowerShell:

```powershell
.\scripts\quality.ps1
```

Optional variants:

```powershell
.\scripts\quality.ps1 -IncludeReleaseTests
.\scripts\quality.ps1 -InstallOptionalTools
```

Optional tools are never installed unless requested. CI runs format, Clippy, tests, doc tests, and
release builds on Windows and Linux stable; checks MSRV 1.85.0; and runs pinned cargo-audit,
cargo-deny, and dependency-review jobs. Third-party GitHub Actions are pinned to full commits.

## Known limitations

- JavaScript is statically inspected and never executed, so dynamically generated routes are not
  visible.
- No authenticated crawling, browser state, distributed coordination, exploit verification,
  certificate intelligence, checkpoint/resume, or person-centric OSINT is implemented.
- Soft-404 and technology detections are explainable heuristics and can require authorized manual
  verification.
- Header findings are contextual advice, not proof of exploitability.
- Windows file ACL hardening is not equivalent to Unix mode `0600`; protect output directories.
- No claim is made that the scanner or its dependency graph is vulnerability-free.

See [Architecture](docs/ARCHITECTURE.md), [Audit](docs/AUDIT_REPORT.md), [Gameplan](docs/GAMEPLAN.md),
[Validation](docs/VALIDATION_REPORT.md), and [Security Policy](SECURITY.md).

## License

MIT. See `LICENSE`.
