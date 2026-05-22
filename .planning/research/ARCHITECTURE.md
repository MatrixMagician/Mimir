# Architecture Research

**Domain:** Go secret/credential scanner (CLI + CI gate + pre-commit hook)
**Researched:** 2026-05-22
**Confidence:** HIGH (architecture validated against gitleaks, trufflehog, detect-secrets source/docs; concurrency patterns are standard Go)

## Standard Architecture

The mature tools in this space (gitleaks, trufflehog, detect-secrets) all converge on the same shape: **a layered pipeline where pluggable Sources produce Fragments, a stateless Engine turns Fragments into candidate Findings via prefilter → regex → entropy, a Filter layer drops suppressed/baseline findings, an optional Verifier layer confirms liveness, and Reporters serialize the survivors.** The CLI is a thin shell over this pipeline. Mimir should follow the same separation because it cleanly maps onto the four entry points (working tree, git history, config files, staged diff) sharing one engine.

### System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLI / Command Layer  (cmd/, cobra)            │
│   scan · git · staged · verify · baseline   →  flag parse, exit codes  │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ builds Config + selects Source
┌───────────────────────────────▼──────────────────────────────────────┐
│                       SOURCE / ENUMERATION LAYER                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ ┌────────────────┐        │
│  │ FS Walk  │ │ Git WT   │ │ Git History  │ │ Staged Diff    │        │
│  │ (dir)    │ │ (tracked)│ │ (commit walk)│ │ (index)        │        │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ └──────┬─────────┘        │
│       └────────────┴───── emit ───┴────────────────┘                  │
│                        Fragment{Raw, FilePath, CommitInfo}            │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │  chan Fragment (fan-out to workers)
┌───────────────────────────────▼──────────────────────────────────────┐
│                          SCANNING ENGINE  (stateless per-fragment)     │
│   keyword prefilter (Aho-Corasick)  →  candidate rules                 │
│        ↓                                                               │
│   regex matchers  +  entropy scorer  +  connstring detector            │
│        ↓                                                               │
│   raw candidate Findings (with line/col, capture group, secret)       │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │  chan Finding (fan-in)
┌───────────────────────────────▼──────────────────────────────────────┐
│                       SUPPRESSION / FILTER LAYER                       │
│   inline comment  ·  ignore-file (paths/globs)  ·  allowlist regex     │
│   ·  baseline (fingerprint set)  ·  dedupe                             │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │  surviving Findings
┌───────────────────────────────▼──────────────────────────────────────┐
│                     VERIFICATION LAYER  (opt-in, network)             │
│   registry[ruleID] → Verifier.Verify(secret) → Active/Inactive/Unknown │
│   (AWS GetCallerIdentity, GitHub /user)  · rate-limit · timeout        │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │  final Findings
┌───────────────────────────────▼──────────────────────────────────────┐
│                            REPORTERS                                   │
│   Human (file:line, rule, redacted)   ·   JSON   →   exit code map     │
└──────────────────────────────────────────────────────────────────────┘

         Rules/Config (built-in + user merge)  ─── feeds ──→  Engine + Verifier registry
```

### Component Responsibilities

| Component | Responsibility | Typical Implementation |
|-----------|----------------|------------------------|
| **CLI / commands** | Parse flags, build Config, pick Source, run pipeline, map findings → exit code | cobra commands in `cmd/`; one per mode |
| **Source (interface)** | Enumerate targets, emit `Fragment`s onto a channel | One impl per mode; all satisfy `Fragments(ctx) <-chan Fragment` |
| **Fragment** | A unit of scannable content + provenance (raw bytes, path, commit) | Plain struct; the pipeline's "currency" |
| **Engine / Detector** | Stateless: `Detect(Fragment) []Finding`. Prefilter, run rules, score entropy, detect connstrings | A `Detector` holding compiled rules + Aho-Corasick trie |
| **Rules / Ruleset** | Hold compiled regex, keywords, entropy threshold, allowlist; merge built-in + user | `Rule` struct; `Config` with `[]Rule`; TOML/YAML loader |
| **Finding** | Result record: path, line/col, rule ID, redacted match, secret, fingerprint | Plain struct; serialized by reporters |
| **Suppression / Filter** | Drop findings by inline comment, ignore-file, allowlist, baseline; dedupe | Functions over `[]Finding`; baseline = `map[fingerprint]struct{}` |
| **Verifier (interface)** | Confirm a secret is live via provider API; opt-in | Registry keyed by rule ID; `Verify(ctx, secret) (Status, error)` |
| **Reporter (interface)** | Serialize findings to a writer | `Human`, `JSON`; satisfy `Write(io.Writer, []Finding) error` |
| **Config loader** | Resolve flags + file + defaults into one `Config` | Layered: defaults → file → flags |

## Recommended Project Structure

Go convention: put non-importable application code under `internal/` (the compiler forbids external imports, which is exactly right for a single-binary tool). Keep `main` in `cmd/`. Mirror the pipeline in package names so boundaries are obvious.

```
mimir/
├── cmd/
│   └── mimir/
│       └── main.go              # wires cobra root, calls into internal/cli
├── internal/
│   ├── cli/                     # cobra commands; flag→Config; exit-code mapping
│   │   ├── root.go
│   │   ├── scan.go              # working-tree / dir scan
│   │   ├── git.go               # history scan
│   │   ├── staged.go            # pre-commit (index) scan
│   │   ├── verify.go            # standalone verification of a finding/secret
│   │   └── baseline.go          # generate/update baseline
│   ├── source/                  # enumeration; everything emits Fragment
│   │   ├── source.go            # Source interface + Fragment struct
│   │   ├── filesystem.go        # directory walk (skip binaries, .git, size cap)
│   │   ├── gitworktree.go       # tracked working-tree files
│   │   ├── githistory.go        # commit-walker over diffs
│   │   └── staged.go            # staged-diff reader (git index)
│   ├── engine/                  # the scanning core (no I/O, no network)
│   │   ├── detector.go          # Detector + Detect(Fragment) []Finding
│   │   ├── prefilter.go         # Aho-Corasick keyword trie
│   │   ├── entropy.go           # Shannon entropy scorer
│   │   └── connstring.go        # connection-string detector
│   ├── rules/                   # ruleset model + config merge
│   │   ├── rule.go              # Rule struct (regex, keywords, entropy, allowlist)
│   │   ├── builtin.go           # embedded default ruleset (//go:embed)
│   │   └── config.go            # load + merge user config over built-ins
│   ├── finding/                 # shared result model (avoids import cycles)
│   │   ├── finding.go           # Finding struct
│   │   └── fingerprint.go       # stable fingerprint + redaction
│   ├── filter/                  # suppression / baseline
│   │   ├── inline.go            # // mimir:ignore comment scanner
│   │   ├── ignorefile.go        # .mimirignore path/glob matcher
│   │   ├── allowlist.go         # rule/global allowlist evaluation
│   │   └── baseline.go          # load baseline, IsNew(), write baseline
│   ├── verify/                  # opt-in liveness checks
│   │   ├── verifier.go          # Verifier interface + registry
│   │   ├── aws.go               # STS GetCallerIdentity
│   │   └── github.go            # GET /user
│   ├── report/                  # output
│   │   ├── reporter.go          # Reporter interface
│   │   ├── human.go
│   │   └── json.go
│   └── pipeline/                # orchestration: source→engine→filter→verify→report
│       └── pipeline.go          # worker pool, errgroup, channel wiring
├── config/
│   └── mimir.toml               # documented default config (also embedded)
├── go.mod
└── go.sum
```

### Structure Rationale

- **`internal/`:** Single binary, no public API to maintain. `internal/` forbids external import so packages can refactor freely.
- **`finding/` is its own package:** Both `engine` and `filter` and `report` need the `Finding` type. Putting it in a leaf package with no dependencies prevents import cycles (the most common Go architecture mistake here).
- **`engine/` does no I/O:** It only transforms `Fragment → []Finding`. This makes it trivially unit-testable (feed bytes, assert findings) and reusable across all four sources. Keep `os`, `net/http`, and `git` out of it.
- **`pipeline/` is the only place goroutines live:** Concurrency wiring is centralized so sources, engine, and reporters stay simple and sequential to reason about.
- **`source/` and `verify/` and `report/` are interface-first:** These are the three extensibility seams. Define the interface, add implementations without touching callers.
- **`rules/builtin.go` uses `//go:embed`:** Ship the default ruleset compiled into the binary so the single-binary distribution goal holds (no external rule files required).

## Architectural Patterns

### Pattern 1: Source interface with channel output (producer)

**What:** Every input mode satisfies one interface and streams `Fragment`s. The pipeline never knows which source it's reading from.
**When to use:** Always — this is the core decoupling that lets one engine serve four entry points.
**Trade-offs:** Channel-based streaming keeps memory flat on huge repos (don't materialize all files); slight complexity over returning a slice. Worth it.

**Example:**
```go
// internal/source/source.go
type Fragment struct {
    Raw      string   // content to scan
    FilePath string   // for reporting + path allowlists
    Commit   *Commit  // nil for working-tree/dir; set for history
    StartLine int     // base line offset (diffs)
}

type Source interface {
    // Fragments emits scannable units; closes the channel when done.
    // Errors are sent on errc; ctx cancellation stops enumeration.
    Fragments(ctx context.Context) (<-chan Fragment, <-chan error)
}
```

### Pattern 2: Stateless Detector with keyword prefilter then regex+entropy

**What:** `Detect(Fragment) []Finding` is pure. It first runs an Aho-Corasick trie of all rule keywords over the fragment; only rules whose keyword appeared get their (expensive) regex run. Regex matches are then gated by an entropy threshold and capture-group extraction.
**When to use:** Always. Prefiltering is the single biggest performance lever — gitleaks and trufflehog both do it. Skipping it makes large-repo scans 10x+ slower.
**Trade-offs:** Rules must declare keywords (small authoring cost). Go's `regexp` (RE2) has no lookahead/lookbehind — design rules around that limitation rather than fighting it.

**Example:**
```go
// internal/engine/detector.go
func (d *Detector) Detect(f source.Fragment) []finding.Finding {
    hits := d.prefilter.Match(f.Raw)          // Aho-Corasick: which keywords present
    if len(hits) == 0 {
        return nil                            // fast bail — most fragments end here
    }
    var out []finding.Finding
    for _, rule := range d.rulesForKeywords(hits) {
        for _, loc := range rule.Regex.FindAllStringIndex(f.Raw, -1) {
            secret := extractGroup(rule, f.Raw, loc)
            if rule.Entropy > 0 && shannon(secret) < rule.Entropy {
                continue                      // entropy gate
            }
            out = append(out, finding.New(f, rule, loc, secret))
        }
    }
    return out
}
```

### Pattern 3: Pipeline as fan-out worker pool with errgroup

**What:** One goroutine drains the source channel; a fixed pool of N workers calls `Detect` concurrently; a fan-in collects `Finding`s. `errgroup.WithContext` ties them together so the first error (or cancel/timeout) tears everything down cleanly.
**When to use:** The whole scan. Detection is CPU-bound and embarrassingly parallel per fragment.
**Trade-offs:** Need a bounded worker count (default to `runtime.NumCPU()`), not unbounded goroutines. Findings collection needs a mutex or a results channel — prefer a results channel for clean ownership.

**Example:**
```go
// internal/pipeline/pipeline.go
func Run(ctx context.Context, src source.Source, det *engine.Detector, workers int) ([]finding.Finding, error) {
    g, ctx := errgroup.WithContext(ctx)
    frags, srcErr := src.Fragments(ctx)
    results := make(chan finding.Finding, 1024)

    for i := 0; i < workers; i++ {
        g.Go(func() error {
            for f := range frags {           // fan-out: workers share the channel
                for _, fd := range det.Detect(f) {
                    select {
                    case results <- fd:
                    case <-ctx.Done():
                        return ctx.Err()
                    }
                }
            }
            return nil
        })
    }
    go func() { g.Wait(); close(results) }()  // close when all workers done

    var found []finding.Finding              // fan-in
    for fd := range results {
        found = append(found, fd)
    }
    if err := g.Wait(); err != nil { return nil, err }
    if err := <-srcErr; err != nil { return nil, err }
    return found, nil
}
```

### Pattern 4: Verifier registry (opt-in, keyed by rule)

**What:** A `map[ruleID]Verifier`. Verification runs *after* suppression (never verify a secret you're going to drop) and only when `--verify` is set. Each verifier owns its provider's API call, timeout, and rate-limit handling.
**When to use:** v1 = AWS + GitHub. The registry means adding a provider is one file + one map entry, no engine changes.
**Trade-offs:** Network calls are slow and can leak secrets in logs — verification gets its own low-concurrency pool (trufflehog runs verification at 1x while detection runs at 8x) and must never log the secret value.

**Example:**
```go
// internal/verify/verifier.go
type Status int
const (StatusUnknown Status = iota; StatusActive; StatusInactive)

type Verifier interface {
    Verify(ctx context.Context, secret string) (Status, error)
}
var registry = map[string]Verifier{}        // ruleID → verifier
func Register(ruleID string, v Verifier) { registry[ruleID] = v }
```

## Data Flow

### How a candidate becomes a reported finding

```
[CLI command]                    parse flags, load+merge rules, pick Source
    ↓
[Source.Fragments(ctx)]          enumerate → emit Fragment{raw, path, commit}
    ↓ (chan Fragment, fan-out to N workers)
[Engine.Detect(fragment)]        prefilter keywords → regex match → entropy gate
    ↓                            → connstring detect → raw candidate Findings
    ↓ (chan Finding, fan-in)
[Filter layer]                   inline comment? ignore-file path? allowlist regex?
    ↓                            already in baseline? duplicate fingerprint?  → DROP
    ↓ (surviving findings)
[Verify layer]   (only if --verify)   registry[ruleID].Verify(secret) → Active/Inactive/Unknown
    ↓ (findings + verification status)
[Reporter]                       redact secret → write human/JSON
    ↓
[CLI exit-code map]              findings>0 → exit 1 ; error → exit 2 ; clean → exit 0
```

### Key Data Flows

1. **Fragment provenance flow:** The `Commit` field on `Fragment` is `nil` for dir/working-tree scans and populated for history scans. The same `Finding` struct carries optional commit metadata so reporters and fingerprints work identically across modes — one model, four sources.

2. **Fingerprint / baseline flow:** Each finding gets a stable fingerprint (`filepath:ruleID:startLine`, plus `commit:` prefix for history). Baseline mode loads a `map[fingerprint]struct{}`; `IsNew(finding)` drops anything already present. Generating a baseline is just "run a scan, write all fingerprints." This is the make-or-break false-positive control and must be designed in from the start, not bolted on.

3. **Redaction flow:** The raw secret lives on the `Finding` only long enough for verification. Reporters call a `Redact()` that masks all but a short prefix/suffix. Default output never prints the full secret; verification logs never print it either.

### State Management

The scan is mostly stateless — `Detect` is pure, sources stream. The only shared mutable state is:
- the **findings accumulator** (owned by the fan-in via a results channel, not a shared slice + mutex if you can avoid it),
- the **baseline set** (read-only after load),
- the **dedupe set** (small mutex-guarded map, or dedupe at fan-in).

Keep all goroutine-shared state in `pipeline/`; the engine, rules, and reporters stay pure/sequential.

## Build Order (dependency graph)

Build leaf packages first, then layers that depend on them. This order lets you have a working end-to-end scanner early and add modes/extensibility incrementally.

```
1. finding/        (no deps)          ── Finding struct, fingerprint, redaction
2. rules/          (deps: -)          ── Rule, Config, embedded built-ins, user merge
3. engine/         (deps: finding,rules) ── prefilter, regex, entropy, connstring  ← unit-test heavily
4. source/         (deps: -)          ── Fragment + Source iface; start with filesystem.go only
5. pipeline/       (deps: source,engine,finding) ── worker pool / errgroup wiring
   ── MILESTONE: end-to-end dir scan works (no suppression, no verify, no JSON yet)
6. report/         (deps: finding)    ── human first, then JSON
7. filter/         (deps: finding)    ── inline → ignore-file → allowlist → baseline (in that order)
8. cli/            (deps: all above)  ── scan command first, then exit-code mapping
   ── MILESTONE: usable CLI scanner with suppression + JSON
9. source: gitworktree, staged, githistory   ── add modes; each is a new Source impl
10. verify/        (deps: finding,rules) ── interface + AWS + GitHub; --verify flag in cli
11. cli: git/staged/baseline/verify subcommands + pre-commit install helper
```

**Critical ordering constraints:**
- `finding/` and `rules/` are foundations — nothing works without the data model and the ruleset.
- `engine/` must exist and be tested before `pipeline/` (you're parallelizing a thing that must first be correct serially).
- The **filesystem source is enough to validate the whole pipeline**; git sources are additive and should come *after* the core works, not block it.
- **Suppression and baseline come before verification** — false-positive control is the adoption driver per PROJECT.md; verification is high-value-but-deferrable.
- Verification is last because it's the only network-touching, opt-in layer and adding it should require zero changes to engine/filter/report.

## Scaling Considerations

(For a scanner, "scale" = repo size / history depth / files-per-scan, not users.)

| Scale | Architecture Adjustments |
|-------|--------------------------|
| Small repo / pre-commit (staged only) | Single-pass, tiny worker pool; latency matters more than throughput. Scan only the staged diff, never the whole tree. |
| Large working tree (10k–100k files) | Worker pool = NumCPU; skip binaries by content sniff + extension; size-cap large files; Aho-Corasick prefilter is essential. |
| Deep history (50k+ commits) | Stream diffs, never load all commits in memory; scan per-diff not per-full-blob; dedupe identical blobs across commits; allow `--since`/depth limits. |

### Scaling Priorities

1. **First bottleneck — regex over every byte of every file.** Fix: Aho-Corasick keyword prefilter so most fragments never hit regex. This is the highest-ROI optimization and should be in v1.
2. **Second bottleneck — git history I/O.** Fix: stream `git log -p` diffs (or go-git diffs) rather than checking out blobs; dedupe identical content; bound concurrency on the source side so you don't OOM buffering diffs.
3. **Third bottleneck — verification network latency.** Fix: separate low-concurrency verification pool, cache results per unique secret, only verify post-suppression survivors.

**Git source decision:** Two viable approaches — shell out to `git log -p` (gitleaks' approach; fast, requires git on PATH) or use `go-git` (pure Go, no external dependency, slower on huge repos). Given the single-static-binary + lean-dependencies goals in PROJECT.md, lean toward **shelling out to `git`** for history/staged (git is universally present in CI and dev) and keep the door open for go-git behind the same `Source` interface. Confidence: MEDIUM — validate the perf/UX tradeoff during the git-source phase.

## Anti-Patterns

### Anti-Pattern 1: Engine that does its own I/O or git access

**What people do:** Let the detector open files, walk git, or call APIs.
**Why it's wrong:** Couples detection to input mode, makes it untestable, and forces every new source to touch the engine.
**Do this instead:** Engine takes `Fragment` (bytes + metadata) and returns `[]Finding`. Sources do I/O; verifiers do network. Engine is pure.

### Anti-Pattern 2: Skipping the keyword prefilter, running every regex on every file

**What people do:** Loop over 100+ rules × full file content.
**Why it's wrong:** Quadratic-feeling slowdown on real repos; the tool becomes "too slow for pre-commit" and gets disabled.
**Do this instead:** Build an Aho-Corasick trie of rule keywords; only run a rule's regex when its keyword is present in the fragment.

### Anti-Pattern 3: Treating suppression/baseline as a v2 afterthought

**What people do:** Ship detection first, add ignore/baseline later.
**Why it's wrong:** PROJECT.md is explicit — false positives are make-or-break; a noisy scanner gets uninstalled before baseline ever ships.
**Do this instead:** Design `Finding.Fingerprint` and the filter layer in the first usable release. Baseline is "scan + persist fingerprints"; cheap if the fingerprint exists from day one.

### Anti-Pattern 4: Verifying before suppressing, or logging raw secrets

**What people do:** Run network verification on every regex hit, log secrets for debugging.
**Why it's wrong:** Wastes API quota verifying secrets you'll drop, hits rate limits, and leaks live credentials into logs/CI output.
**Do this instead:** Verify only post-filter survivors, behind `--verify`, in a low-concurrency pool, with redaction enforced everywhere including error paths.

### Anti-Pattern 5: Import cycle from a fat shared package

**What people do:** Put Finding, Rule, Config, and helpers in one `types` package that imports everything.
**Why it's wrong:** Go forbids cycles; you'll fight the compiler and end up with a tangled god-package.
**Do this instead:** `finding/` is a dependency-free leaf. `rules/` is a near-leaf. Higher layers depend downward only.

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| AWS STS | `GetCallerIdentity` via signed request | v1 verifier; treat any 200 as "active". Don't pull the whole AWS SDK if a minimal signed HTTP call suffices (keeps binary lean). |
| GitHub API | `GET /user` with token | v1 verifier; 200 = active, 401 = inactive. Respect rate-limit headers. |
| `git` binary | shell out for `log -p`, `diff --staged`, `ls-files` | Universally present in CI/dev; alternative is `go-git` behind the same Source interface. |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| Source ↔ Pipeline | `<-chan Fragment` + `<-chan error` | Streaming, ctx-cancellable; source owns enumeration, pipeline owns concurrency. |
| Pipeline ↔ Engine | direct call `Detect(Fragment) []Finding` | Engine is pure/sequential; pipeline parallelizes it. |
| Pipeline ↔ Filter | function calls over `[]Finding` | Filter is pure; runs at fan-in or post-collection. |
| Filter ↔ Verify | direct, post-suppression only | Never verify dropped findings. |
| Verify ↔ Reporter | `Finding` carries `VerificationStatus` | Reporters render status; no coupling to providers. |
| CLI ↔ everything | builds Config, picks Source, picks Reporter, maps exit code | Thin shell; all logic lives in `internal/`. |

### CI / pre-commit integration specifics

- **Exit codes:** `0` clean, `1` findings present, `2` execution error. CI gate keys off `1`. Keep this mapping in one place in `cli/`.
- **Pre-commit:** the `staged` command scans only the index (`git diff --cached`), must be fast (small worker pool, no history), and should respect inline `// mimir:ignore` so developers can unblock themselves. Ship a pre-commit hook installer/sample config.
- **JSON output:** stable schema for automation; must include fingerprint so downstream tooling can build/update baselines.

## Sources

- gitleaks repository & DeepWiki (detect engine, Detector struct, Aho-Corasick prefilter, fingerprint format, allowlist, baseline, sources git/dir/stdin, semaphore concurrency) — HIGH
  - https://github.com/gitleaks/gitleaks
  - https://deepwiki.com/gitleaks/gitleaks
  - https://github.com/zricethezav/gitleaks/blob/master/detect/detect.go
  - https://deepwiki.com/gitleaks/gitleaks/4-rule-system
- trufflehog DeepWiki (Detector interface FromData/Keywords/Type, verification Active/Inactive/Unknown, source manager, worker pools at multipliers, dedupe cache) — HIGH
  - https://deepwiki.com/trufflesecurity/trufflehog
  - https://github.com/trufflesecurity/trufflehog/blob/main/hack/docs/Adding_Detectors_external.md
- detect-secrets (plugin architecture, baseline-of-hashes model, inline `pragma: allowlist secret`) — HIGH
  - https://github.com/Yelp/detect-secrets
- Go concurrency patterns (errgroup.WithContext, worker pool fan-out/fan-in) — HIGH (standard Go)
  - https://medium.com/@ninucium/golang-concurrency-patterns-for-select-done-errgroup-and-worker-pool-645bec0bd3c9
  - https://dev.to/serifcolakel/go-concurrency-patterns-worker-pool-fan-in-fan-out-pipeline-49pd
- betterleaks (Aho-Corasick keyword filter + RE2 + default parallelization confirming prefilter pattern) — MEDIUM
  - https://github.com/betterleaks/betterleaks

---
*Architecture research for: Go secret/credential scanner*
*Researched: 2026-05-22*
