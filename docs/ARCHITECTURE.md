# Architecture

## Pipeline and trust boundaries

```text
CLI/profile validation
  -> target and authorization validation
  -> URL scope + destructive-action policy
  -> DNS resolution + IP classification + pinning
  -> rate limit + atomic wire budget + GET transport
  -> bounded post-decompression capture
  -> content classification
  -> discovery + structured analyzers
  -> central redaction + deterministic correlation
  -> JSON source report + Markdown/Text/SARIF views
```

URLs, DNS results, redirects, headers, compressed responses, parser input, wordlists, report files,
and output paths are untrusted. `http::ScannerHttpClient` is the sole production network boundary.
Discovery and analyzers never issue requests themselves.

## Dependency direction

- `cli` and `config` construct a validated `ScanConfig`; dry-run stops here without DNS or writes.
- `target` owns the exact request URL for the seed. `scope` owns host/scheme/port and network
  admissibility.
- `redaction` is a leaf utility consumed before log/report/checkpoint-like persistence boundaries.
- `http` depends on scope and policy, returns bounded raw bytes plus a report-safe observation.
- `engine` owns priority, canonical deduplication, scheduling, soft-404 baselines, and correlation.
- `discovery` converts one bounded document into candidates; the scheduler rechecks every candidate.
- `analyzers` consume observations and optional bounded text, producing immutable findings.
- `model` contains stable serialized contracts. Public maps/sets use ordered collections.
- `storage` owns safe components, synced temporary files, rename, and content-addressed bodies.
- `report` derives all views from schema-versioned `report.json` data.

No cyclic module dependency or secondary scanner pipeline remains. The former `src/scanner.rs` was
unreferenced legacy code and was removed after its useful HTML concepts were confirmed present in
the bounded discovery/analyzer modules.

## URL identities

Three representations have separate purposes:

1. `url::Url` request URL: retains query order and values and is sent without semantic rewriting.
2. Canonical key: removes fragments/default ports/tracking parameters and sorts remaining pairs
   only for deduplication.
3. Report URL: removes credentials/fragments and replaces every query value.

Signed URLs therefore remain valid for acquisition while reports and logs remain data-minimized.

## Scope, DNS, and transport

Same-origin is default. Same-host/subdomain modes originate in strict profiles; explicit extra
hosts are normalized through the URL/IDNA parser. Expanded scope requires authorization.
The authorized-sensitive profile also permits validated non-public LAN destinations, but its
sensitive/private policy makes `--authorized` mandatory before any scan starts. Other profiles
require the separate `--allow-private --authorized` pair.

Before use, each hostname is resolved with a bounded `max + 1` collection. Oversized DNS answer
sets are rejected instead of silently truncating validation. Every returned IPv4/IPv6 address is
classified. A client is then built for the scheme/host/port and pinned to the validated address
set. Cached clients and rate state are bounded by the profile.

Reqwest uses rustls, no system proxy, no implicit redirect, and no implicit retry. Every actual send
attempt atomically increments the shared budget. Safe transient connect/timeouts and 429/502/503/504
statuses may retry with bounded backoff/Retry-After. Redirect URLs are resolved relative to the
effective URL, checked for loops, destructive paths, and scope, and then consume another wire unit.

Bodies stream into a fixed maximum after reqwest decompression. Dropping the stream stops further
capture. Content classification uses only the captured bytes. Header persistence is allowlisted and
bounded; repeated fields are preserved.

## Scheduler and bounded state

`RequestQueue` is a binary heap ordered by priority, lower depth, insertion sequence, then URL.
Canonical keys in an ordered set prevent duplicate scheduling. Queue/seen state, inventory,
candidates per response, depth, observations (implicitly bounded by wire budget), errors, findings,
evidence, redirects, cached hosts, wordlists, and body bytes all have configured ceilings.

Soft-404 setup uses up to three unique missing paths and the same HTTP client/budget. Classification
reports native status, exact hash, normalized similarity, baseline coverage, confidence, score, and
reasons. Scan completion becomes false when a material configured bound truncates work.
The probes deliberately use root-level, `.well-known`, and nested resource shapes. Similarity can
only classify non-empty 2xx representations; it can never relabel 304, other 3xx, 4xx except native
404/410, or 5xx. The explicitly requested successful origin root remains the seed representation,
while matching non-seed paths are semantic soft 404s and are never passed to analyzers.

Final-response transport truth and semantic interpretation remain separate: every observation
retains its exact numeric status and response class, while `soft_404` describes existence
semantics. Reports carry an exact final-response status histogram; redirect and retry attempts
remain represented by their dedicated counters and chains. Technology fingerprints are
origin-scoped so a shared server header does not create path-level duplicates.

## Privacy and evidence

Findings are stable by analyzer version, rule kind/title, and redacted location; changing incidental
evidence does not create a new identity. Evidence is redacted, sorted, deduplicated, item-limited,
and byte-limited. Email extraction stores domains only. Cookie analysis sees names and attributes
after the value is replaced.

The raw body exists only in bounded memory unless explicit authorized storage is enabled. Binary or
unknown content is not stored. Accepted stored bodies are addressed by a verified SHA-256 digest.

## Concurrency and cancellation

One Tokio scheduler task owns mutable report state. A bounded `FuturesUnordered` batch performs
network acquisition concurrently; results are merged by the owner and sorted before serialization.
Shared client maps and rate clocks use Tokio mutexes. The wire counter is atomic and cannot exceed
its limit under concurrency. Cancellation can spend a budget unit for an attempted request, which
is conservative and accurate to possible network activity.

Live output is emitted by the scheduler owner: start and completion records, throttled one-second
counter snapshots, and redacted medium-or-higher finding events. No progress task, channel, or lock
is added to the request hot path. `--no-progress` and `--quiet` disable these events.

## Deliberate omissions

Checkpoint/resume is omitted until redacted signed-URL semantics and encrypted persistence can be
made compatible. JavaScript/browser execution, authentication, distributed scheduling, invasive
probes, person profiling, and probabilistic evidence graphs are outside the safety model.
