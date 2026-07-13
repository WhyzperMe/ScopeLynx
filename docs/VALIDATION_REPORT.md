# Validation Report

Validation date and environment: 2026-07-13, Windows 11, PowerShell, x86_64-pc-windows-msvc.

## Toolchain observed

- `rustc 1.95.0 (59807616e 2026-04-14)`
- `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
- stable toolchain selected by `rust-toolchain.toml`

## Baseline results

- `cargo check --workspace --all-targets --all-features`: passed.
- `cargo fmt --all -- --check`: failed because the delivered source was not rustfmt-clean.
- Production-pattern scan found six direct `unwrap()` calls, all in unreferenced
  `src/scanner.rs`; that file was removed after reference audit.
- The supplied directory was not a Git worktree, so requested Git status/branch/log/diff commands
  returned `fatal: not a git repository`.

## Implemented test coverage

- URL canonicalization and request-URL separation.
- URL/text/evidence/cookie redaction and stable finding identifiers.
- Same-origin scope and public/private IPv4/IPv6 classification.
- Authorized-profile LAN enablement, public WAN literals, and progress opt-out configuration.
- HTML, robots, sitemap, JavaScript, JSON-LD, feed, and manifest discovery.
- Content sniffing and binary/text separation.
- Analyzer evidence and password-form behavior.
- Priority and canonical queue deduplication.
- Explainable multi-baseline soft-404 classification.
- Catch-all-200 seed retention, global soft-404 analyzer gating, origin-scoped technology
  correlation, and exact 200/304/404/503 separation.
- Real local HTTP redirects, redirect loops, cross-origin rejection, Retry-After/retries, global
  wire budgets, repeated Set-Cookie, large bodies, gzip post-decompression limits, and soft-404
  probe budget accounting.
- Atomic initial writes, verified content-addressed body storage, and mismatched-digest rejection.
- Property invariants for canonicalization, redaction, and private IPv4 blocking.

## Final gate record

- `cargo metadata --locked --no-deps --format-version 1`: passed.
- `cargo check --workspace --all-targets --all-features --locked`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed with zero
  warnings.
- `cargo test --workspace --all-targets --all-features`: passed; 52 tests, 0 failed, 0
  ignored.
- `cargo test --doc`: passed; the crate currently has no doctest cases.
- `cargo build --release --locked`: passed.
- `cargo test --release --workspace --all-targets --all-features`: passed; the same 52
  tests passed under optimized code generation.
- `scripts/quality.ps1`: passed every mandatory gate (toolchain, locked metadata, rustfmt,
  Clippy, tests, documentation tests, and release build).
- Release CLI `validate-profile`: `safe`, `standard`, and `authorized-sensitive` passed.
- Release CLI PowerShell completion generation: passed.
- Release CLI `--dry-run`: passed; query values were redacted, no network scan was started, and
  the asserted output path was not created.
- Safe-profile wordlist refusal: passed with the documented exit code 2.
- Production-pattern search for direct `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`,
  `dbg!`, and `unsafe`: zero matches under `src`.
- `cargo tree --duplicates --locked`: completed successfully and reported 11 duplicate-version
  root entries, all transitive (principally the `phf` 0.10/0.11 and `rand` 0.8/0.9 families).
- Stale iteration-name search outside the pre-regeneration manifest: zero matches.
- Proptest regression artifacts outside `target`: zero.
- `scripts/update-manifest.ps1`: generated 103 sorted entries; every listed SHA-256 digest,
  path, exclusion rule, and source-file count was independently rechecked successfully.

## Historical authorized LAN/WAN validation for 0.3.1

- The supplied target hostname resolved locally to an RFC1918 destination. The unchanged 0.3.0
  policy correctly rejected it before any connection; the 0.3.1 authorized-sensitive profile
  explicitly enables validated private destinations while still requiring `--authorized`.
- The exact supplied release command completed with exit code 0: 15 wire requests, 12 scheduled
  tasks, 12 observations, 0 request errors, 12 findings, `complete = true`, and no abort reason.
- The resulting schema-3 report records scanner version 0.3.1 and
  `policy.allow_private_networks = true`.
- Live start, concurrent soft-404 baseline, dispatch, completion, and summary events were visibly
  emitted even with an inherited `RUST_LOG=warn`. A separate bounded run verified the request
  budget in the live counters.
- A dry-run of the same command reported LAN permission, 32-task concurrency, 40 requests/second,
  a 50,000 wire-request budget, depth 5, and 200,000 URL limit without making a connection.

The 12 path-level nginx findings in this historical run exposed the correlation defect corrected
and revalidated below; they are not presented as valid results.

## Catch-all and status validation for 0.3.2

- Browser inspection confirmed that `/config.json` and `/backup.zip` render the same development
  landing representation as unrelated paths. A browser may show 304 after sending
  `If-Modified-Since`; the scanner intentionally sends no conditional cache validator and therefore
  receives the current 200 representation for body classification.
- The exact authorized release command completed with exit code 0 and schema 4: 27 wire requests,
  23 observations, 0 request errors, 5 origin/content findings, `complete = true`, and no abort
  reason.
- The raw status histogram was `200=14, 400=1, 403=4, 404=4`. Semantic counters separately reported
  8 catch-all soft 404s, 4 native 404/410 responses, 4 forbidden responses, 0 not-modified
  responses, 0 rate limits, and 0 server errors.
- `/config.json` and `/backup.zip` retained raw status 200, response class `success`, soft-404 score
  1.00, exact body/baseline match, and `soft_404 = true`.
- No finding location referenced `.env`, `.git/config`, `backup.sql`, `backup.zip`, `config.json`,
  `config.yml`, `phpinfo.php`, or `server-status`: observed false-positive findings = 0.
- A deterministic catch-all local server proves that only the explicit successful root seed remains
  analyzable, while identical non-seed 200 responses are excluded globally. Separate local
  responses prove unambiguous 200 Success, 304 Not Modified, 404 Not Found, and 503 Server Error
  classes; 304, native 404/410, and 5xx can never be relabeled as soft 404.
- Release `inspect` successfully read both the historical schema-3 report and the new schema-4
  report, confirming backward read compatibility.

## Gates not run locally

- `cargo audit`: **SKIPPED**, because `cargo-audit` was not installed. The tool was not installed
  automatically; CI pins and runs cargo-audit 0.22.2.
- `cargo deny check`: **SKIPPED**, because `cargo-deny` was not installed. The tool was not
  installed automatically; CI pins and runs cargo-deny 0.20.2.
- Rust 1.85 MSRV build: **NOT RUN**, because only the stable 1.95.0 toolchain was installed. The
  dedicated CI job enforces Rust 1.85.
- Git status/diff: **UNAVAILABLE**. `git status --short` returned exit 128 (`not a git
  repository`); `git diff --stat` returned exit 129. No source-control diff can be truthfully
  reported for the supplied directory.

## Validation boundaries

- Automated tests use loopback or literal-address policy resolution only. They do not contact
  external scan targets.
- Real GET-only validation runs were executed only against the user-supplied, explicitly authorized
  hostname; in this environment it resolved to the user's LAN. No other live target was scanned.
- Checkpoint/resume and TLS certificate fixture tests are not claimed.
- No benchmark result is claimed; performance is protected through explicit budgets, bounded
  allocations, cached parsers, and behavioral tests rather than an unmeasured number.
