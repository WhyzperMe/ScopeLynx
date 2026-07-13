# Engineering and Security Audit Report

Audit date: 2026-07-13. Scope: all repository source, tests, profiles, scripts, CI, documentation,
lockfile package entries, and wordlist constraints. `target/` and `.idea/` were excluded as build or
editor state. The supplied directory contains no `.git`, so historical ownership and a Git diff
could not be established.

## Baseline assessment

| Area | Before | After implementation |
|---|---:|---:|
| Security | 6.5/10 | 8.6/10 |
| Architecture | 7.0/10 | 8.7/10 |
| Correctness | 6.4/10 | 8.5/10 |
| Performance | 7.0/10 | 8.0/10 |
| Maintainability | 6.6/10 | 8.6/10 |
| Testability | 5.4/10 | 8.8/10 |
| Observability | 5.8/10 | 7.6/10 |
| Privacy | 6.2/10 | 8.9/10 |
| Developer Experience | 6.0/10 | 8.7/10 |
| Documentation | 5.0/10 | 8.8/10 |
| Release Readiness | 4.8/10 | 8.4/10 |

Scores are engineering judgments, not certification. The post-change score remains below 10
because authenticated staging validation, fuzzing, encrypted resume, independent review, and full
real-world corpus evaluation remain outstanding.

## Critical

No confirmed critical vulnerability was found in the inspected baseline. Sensitive exposure probes
were already signature-gated and disabled outside the authorized profile.

## High

### Error and evidence paths could retain secrets

Transport errors could include request URLs; analyzers had no central output sanitizer. Implemented
central URL/text/header/evidence redaction, removed URLs from reqwest errors, bounded evidence, and
redacted error records before logging/persistence. Query names remain useful; values, credentials,
fragments, bearer/JWT-like material, secret assignments, cloud credentials, keys, and local Windows
paths are removed.

### Findings and local transport verification were unbounded/incomplete

The profile bounded errors and URLs but not findings, and no real local HTTP integration fixture
proved the transport contracts. Added strict `max_findings`, bounded evidence, local deterministic
servers, and tests for redirects, retry budgets, soft-404 probe budgets, repeated cookies, gzip
post-decompression limits, and storage.

### Standard discovery could request sensitive or state-changing GET paths

Wordlists and discovered links could enqueue logout/destructive or sensitive configuration paths.
Added percent-decoded destructive-path rejection at discovery, enqueue, target, and redirect
boundaries. Sensitive configuration paths require the authorized-sensitive profile. Safe profile
now refuses wordlists; robots `Disallow` entries are not automatically fetched.

## Medium

### Content handling trusted `Content-Type` too strongly

Responses without accurate headers were excluded from text discovery. Added bounded classification
for HTML, JavaScript, CSS, JSON, XML, sitemap, RSS, Atom, plain text, PDF, Office, image, manifest,
source map, binary, and unknown content using media type, path, magic, structure, and control-byte
density.

### DNS answer limits silently truncated the validation set

Collection used `.take(max)`. Connections were pinned only to validated addresses, preventing a
direct bypass, but the behavior did not meet the all-answer policy. Resolution now collects at most
`max + 1` and rejects oversized sets. Reserved IPv4/IPv6 coverage was expanded.

### Finding IDs changed with incidental evidence

Evidence was part of the identifier and could make report diff noisy. IDs now use analyzer version,
kind/title, and redacted location; tests prove stability when evidence changes.

### Report and CLI contracts were incomplete

Added schema 3 validation, scan ID, configuration fingerprint, completion/abort state, soft-404
reasons, `--dry-run`, `inspect`, completion, resource overrides, extra-host/private/subdomain
controls, output formats, and SARIF. JSON remains mandatory.

### Output naming and body storage needed stricter invariants

Added collision-resistant exclusive run directory creation, symlink/non-directory rejection for
the sanitized host component, Windows reserved-name escaping, and SHA-256/body consistency checks.
Atomic replacement of an existing destination is deliberately not emulated with delete-then-rename
on Windows; such writes fail safely instead of creating a non-atomic window.

## Low

- Removed unreferenced `src/scanner.rs`, which duplicated analysis, stored full emails/comments, and
  contained direct `unwrap()` calls.
- Removed obsolete intermediate documentation and all iteration naming.
- Centralized report ordering for observations, findings, inventory, and errors.
- Added feed/manifest/JSON-LD/OpenGraph/Twitter discovery and source-traceable candidates.
- Updated CI with full-SHA action pins, least permissions, timeouts, caches, Windows/Linux stable,
  MSRV, dependency review, cargo-audit, and cargo-deny.

## Informational and residual risk

- Version 0.3.2 fixes an observed false-positive chain where responses correctly scored as soft
  404 still reached cookie/technology analysis. Soft-404 responses now cross a single analyzer
  gate, and technology identity is correlated at origin scope.
- The report contract now separates raw HTTP status from semantic existence and records exact
  status counts. 304 and 5xx classifications are protected by explicit regression tests.

- Version 0.3.1 enables private/LAN resolution only in the profile that already mandates explicit
  authorization, and increases its bounded throughput to 32 tasks and 40 requests per second.
  Operators must reduce these values for fragile production targets.
- Progress reporting is scheduler-owned and time-throttled; it does not add synchronization to the
  HTTP hot path. Medium-or-higher finding events use already-redacted finding fields.

- Soft-404, exposure, and technology analysis are heuristic and require authorized human review.
- Static JavaScript discovery is intentionally incomplete.
- Header absence can be contextual; low/informational severity reflects that uncertainty.
- Parser fuzzing, slowloris/partial-body stress, TLS fixture coverage, and large corpus benchmarks
  remain future work.
- No secure checkpoint/resume exists. This is explicitly documented rather than represented by an
  unsafe placeholder.
- Windows ACL inheritance cannot be made portable through Tokio alone.
- Dependency audits describe known advisories only and do not prove supply-chain safety.
