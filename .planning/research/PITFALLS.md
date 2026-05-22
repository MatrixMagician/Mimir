# Pitfalls Research

**Domain:** Secret/credential scanner (Go CLI + CI gate + pre-commit hook)
**Researched:** 2026-05-22
**Confidence:** HIGH for most items (drawn from gitleaks/trufflehog/detect-secrets issue trackers, official docs, and direct prior-art behavior); MEDIUM where based on community blog synthesis.

This is the make-or-break document for Mimir. The single largest cause of death for secret scanners is not missed secrets — it is false-positive fatigue that gets the tool disabled, and security own-goals where the scanner itself leaks the secret it found. Both are addressed below as Critical.

## Critical Pitfalls

### Pitfall 1: False-positive explosion kills adoption

**What goes wrong:**
The scanner fires on test fixtures, lockfiles (`package-lock.json`, `Pipfile.lock`, `go.sum`, `yarn.lock`), minified/bundled JS, base64 blobs, SVG path data, UUIDs, git hashes, integrity hashes (`sha512-…`), CSS, and high-entropy-but-not-secret strings. Developers see dozens of false alerts on the first run, lose trust, and either disable the hook (`--no-verify`) or stop reading the CI output entirely. A scanner that cries wolf gets turned off — at which point real secrets sail through.

**Why it happens:**
Entropy was designed to measure randomness, not "is this a credential." Many legitimate strings (hashes, minified identifiers, base64 assets) have high entropy. Regex rules with loose context match variable names and placeholders. Generic/keyword rules (`password = ...`, `token = ...`) match test data and docs. The default rule set is tuned for recall (catch everything) at the expense of precision.

**How to avoid:**
- Layer suppression as a first-class feature, not an afterthought: per-finding inline ignore (`mimir:ignore`), path/glob ignore file, AND baseline. (Mimir's PROJECT.md already commits to all three — good.)
- Ship sensible default allowlists: skip known-noisy paths (`*.lock`, `*-lock.json`, `go.sum`, `vendor/`, `node_modules/`, `*.min.js`, `*.map`, `dist/`, `*.svg`, test/fixture directories) with the ability to override.
- Pair entropy with context: only treat high-entropy strings as candidates when they appear near a secret-suggesting key, assignment, or known prefix. Raw entropy alone produces unusable noise.
- Add stop-word / placeholder filtering: drop matches containing `example`, `xxxx`, `placeholder`, `your-`, `dummy`, `changeme`, `test`, repeated chars, sequential chars.
- Entropy threshold defaults matter: a threshold around 3.5 ignores most short passwords; tune per-rule rather than globally. Make thresholds per-rule, not one global knob.
- Validate detected key shapes (length, charset, checksum/prefix) before reporting — e.g., AWS keys start `AKIA`/`ASIA` and are fixed-length; GitHub tokens have `ghp_`/`gho_`/`ghs_` prefixes and a checksum. Prefix+structure validation eliminates huge swaths of entropy noise for known providers.
- Measure precision/recall against a fixtures corpus in CI so rule changes can't silently regress noise.

**Warning signs:**
First-run on a real repo produces >5–10 findings per 1000 files that are not real secrets; users start passing `--no-verify`; CI failures get rubber-stamped/overridden; issues filed about "noise on my lockfile."

**Phase to address:**
Detection-engine phase (entropy + regex) must build context-gating and default allowlists from day one. Suppression phase (inline/ignore/baseline) is its required partner — do not ship detection without at least the ignore file. Treat a precision/recall benchmark corpus as a phase deliverable, not optional.

---

### Pitfall 2: The scanner leaks the secret it found

**What goes wrong:**
The tool that exists to protect secrets becomes the leak vector — printing the full secret value in human output, embedding it unredacted in JSON, writing it into a report file, logging it at debug/verbose level, putting it in an error/panic message, or capturing it in a stack trace. CI logs are widely readable and often archived; a "finding" line containing the live key is now leaked to everyone with build-log access. This is the worst-case failure for a security tool.

**Why it happens:**
Redaction is implemented at the print layer only, so JSON/report/error/log paths bypass it. Verbose/debug modes dump raw match buffers. Error wrapping (`fmt.Errorf("failed to verify %s: %w", secret, err)`) accidentally embeds the value. Test snippets in output show enough surrounding context to reconstruct the secret. Crash dumps include the in-memory match.

**How to avoid:**
- Model secrets with a wrapper type whose `String()`/`MarshalJSON`/`Format` methods redact by default (Go's `fmt.Stringer` + `json.Marshaler`). Make the raw value reachable only via an explicit `.Reveal()` accessor used in exactly one place (the verification call). This makes leaking opt-out instead of opt-in.
- Redact at the data layer, not the presentation layer, so every output channel (human, JSON, report file, logs, errors) is covered by construction.
- Default JSON output to redacted; require an explicit, loudly-documented flag (e.g., `--show-secrets`) to include raw values, and never default it on in CI.
- Include a stable, non-reversible hash (or short prefix + length) of the secret instead of the value, so users can correlate findings without exposure.
- Never put raw secret bytes into error messages or `panic`. Audit all `Errorf`/`Wrap`/`log` call sites. Add a lint/grep check that flags secret-typed values passed to logging/error functions.
- Strip secrets from any verbose/debug logging. Verbose should log rule IDs and locations, not match contents.
- Be careful with the "snippet" shown around a finding: redact the secret span within the snippet, and bound snippet width so the value can't be reconstructed from context.

**Warning signs:**
Raw key visible in `--format json` without an explicit flag; secret appears in `stderr` on error; grepping the codebase finds the secret type passed to `log.*`/`fmt.Errorf`; report files contain plaintext keys.

**Phase to address:**
Foundational — the secret wrapper type belongs in the core data model phase, before any output or verification code exists. Output/reporting phase and verification phase both depend on it. Add an automated test that scans Mimir's own output for known-fixture secret values and fails if found.

---

### Pitfall 3: Live verification triggers lockouts, rate-limit bans, and canary alerts

**What goes wrong:**
Opt-in verification makes real network calls with found credentials. Done naively it: (a) hammers the same endpoint when the same key appears across many commits/files, hitting rate limits and getting the scanner's IP throttled or temp-banned; (b) trips account-lockout policies on password-style credentials; (c) sets off honeytokens/canary tokens — a fake AWS key planted as a tripwire will alert the planting security team the instant Mimir validates it, even when the user just wanted to clean up their repo; (d) leaks the credential to a third party if verification is pointed at the wrong endpoint or over plain HTTP.

**Why it happens:**
No dedup/caching, so the same secret is verified N times (once per commit it appears in). No backoff/rate-limit handling. Verification runs by default or runs in pre-commit where it adds latency and surprise network calls. Developers don't realize "validate this AWS key" is an observable, attributable action (`aws sts get-caller-identity` reveals caller identity to the key's owner and to canary infrastructure).

**How to avoid:**
- Verification is strictly opt-in (PROJECT.md already mandates this) and should NOT run in the pre-commit path by default — pre-commit must stay fast and offline.
- Verification-result caching keyed by secret hash: verify each distinct secret at most once per run; reuse the result for every other occurrence. This is the single most important mitigation (it's exactly what trufflehog added to prevent endpoint overload/lockouts).
- Respect provider rate limits: read `Retry-After`/rate-limit headers (GitHub exposes these), exponential backoff, a global concurrency cap on verification, and a hard timeout per call so a hung endpoint can't stall the scan.
- Use the least-invasive validation call per provider (a read-only identity/whoami call, not anything that mutates or that counts against auth-failure lockout). For AWS use `sts:GetCallerIdentity` (read-only, no permissions required); for GitHub use a token-scoped read.
- Document the canary risk prominently and consider a "verification may alert the credential owner / trip honeytokens" warning before first use. Optionally detect known canary tells (e.g., Thinkst beacon domain in the STS caller identity) and surface "this looks like a canary token" instead of blindly validating.
- Always verify over TLS to the correct, pinned provider hostname. Never send a found secret anywhere except its own provider.
- Mark verification failures as `unknown`, not `false` — a network error doesn't mean the secret is invalid.

**Warning signs:**
Verification makes N calls for N duplicate findings; HTTP 429s appear in logs; CI IP gets throttled; a user reports their security team got a canary alert from running Mimir; verification adds seconds to pre-commit.

**Phase to address:**
Live-verification phase (AWS + GitHub). Build the dedup cache, rate-limit handling, and opt-in gating into the first verification implementation — retrofitting these is painful. The canary warning is a docs + UX deliverable of the same phase.

---

### Pitfall 4: Git-history scanning blows up memory and time on large repos

**What goes wrong:**
Scanning full history (required for finding already-committed and deleted secrets) loads the whole commit graph and/or large blobs into memory and runs the rule set against every version of every file. On a big monorepo this produces multi-GB memory use (gitleaks has hit ~24GB / OOM on pathological repos) and minutes-to-hours runtimes. If history scanning is too slow it can't run in CI, and the deleted-secret detection value is lost.

**Why it happens:**
- Pure-Go git libraries (go-git) trade memory for portability: reported ~8x the memory of native git, and `log --all` flattens the entire commit list, which is O(commits) memory and slow on big repos.
- Scanning every blob version re-scans unchanged content repeatedly. The right unit is the diff/patch (what each commit *added*), not the full file at every revision.
- Recursive base64/hex/archive decoding amplifies memory: each decode layer allocates new buffers, and unbounded depth on encoded-heavy repos is what produced the gitleaks OOM reports (mitigated by capping decode depth, default 0 = off).

**How to avoid:**
- Scan diffs/patches (added lines per commit), not full file snapshots — this is both faster and gives you the deleted-secret coverage. Stream commits rather than materializing the whole graph.
- Decide deliberately between go-git and shelling out to the system `git` (e.g., `git log -p`/`git rev-list` + patch parsing). Shelling out is far lighter on memory and faster for history, at the cost of requiring `git` on the host; go-git is self-contained but memory-hungry. Document the tradeoff; many teams shell out for history specifically.
- Bound everything: cap max file/blob size scanned (skip or flag oversized blobs), cap decode recursion depth (default off or shallow), cap archive recursion depth, and stream-read blobs instead of loading whole.
- Use Go concurrency with a bounded worker pool — but cap it, since unbounded goroutines each holding a blob in memory is its own OOM path.
- Provide scope controls: scan a commit range, since a baseline, or shallow depth, so CI doesn't re-scan all history every run.
- Benchmark against a large real repo (e.g., a Linux-kernel-sized or busy monorepo clone) as a phase gate, watching peak RSS and wall time.

**Warning signs:**
Peak RSS grows with repo size rather than staying flat; OOM kills in CI containers (memory-limited); history scan takes minutes; users disable history scanning to keep CI green.

**Phase to address:**
Git-history scanning phase. Make "scan diffs, stream commits, bound memory" the core design constraint, and include a large-repo memory/time benchmark in the phase's done criteria.

---

### Pitfall 5: Baselines silently break when line numbers shift

**What goes wrong:**
The baseline / fingerprint feature exists so teams can adopt the scanner on a dirty repo by acknowledging existing findings and only alerting on NEW ones. If fingerprints incorporate volatile data (line number, commit hash, absolute path), then any unrelated edit above a finding shifts its line number, the fingerprint changes, the old finding looks "new," and the baseline floods the team with re-alerts on already-accepted findings. Trust collapses and the baseline gets ignored.

**Why it happens:**
The obvious fingerprint is `commit:file:rule:line` (gitleaks' format). Line is unstable across edits; commit is unstable across rebases/amends; absolute path is unstable across machines and CI build agents (gitleaks has documented non-portable fingerprints where build-agent paths differ from dev paths). Including the secret value in the fingerprint leaks it into the committed `.gitleaksignore`-style file.

**How to avoid:**
- Design the fingerprint deliberately and document it as a stability contract. Prefer components that survive code movement: relative (repo-root) path + rule ID + a hash of the secret/match content, rather than line number. Line/commit can be informational metadata on the finding but should not be load-bearing for baseline matching (or should be a soft, lower-priority match).
- Normalize paths to repo-relative, forward-slash form so fingerprints are identical on Windows, macOS, Linux, and CI agents.
- Do NOT put the raw secret in the fingerprint or baseline file — use a non-reversible hash so the committed baseline is safe.
- Provide a "secret content moved within file" tolerance: match on (path, rule, content-hash) and treat line as advisory.
- Version the fingerprint scheme so you can evolve it; offer a baseline-migration/regenerate command for when the scheme changes.
- Test fingerprint stability explicitly: insert blank lines above a finding, move the finding to another file, rename the repo dir, and assert the baseline still suppresses it.

**Warning signs:**
Adding a comment at the top of a file causes previously-baselined findings to re-fire; baseline works on the dev's machine but floods CI; the same finding has different fingerprints on Windows vs Linux; raw secrets visible in the committed baseline file.

**Phase to address:**
Suppression/baseline phase. The fingerprint scheme is the keystone — get its stability and path-normalization right before baselines ship, since changing the scheme later invalidates everyone's committed baselines.

---

### Pitfall 6: Go RE2 has no lookahead/backreferences — ported rules silently break

**What goes wrong:**
Go's standard `regexp` is RE2: no lookahead, no lookbehind, no backreferences. Most public secret-detection rule sets (and many Stack Overflow patterns) are written for PCRE/.NET and use `(?=...)`, `(?!...)`, `(?<=...)`, `\1`. Pasting those into Mimir either fails to compile or — worse — a "simplified" port silently changes semantics and quietly stops matching real secrets (a false negative, which a scanner never surfaces on its own).

**Why it happens:**
RE2 deliberately omits constructs that require backtracking, to guarantee linear-time matching and safety against catastrophic-backtracking ReDoS from untrusted patterns. Developers porting gitleaks/trufflehog/detect-secrets rules assume regex is regex.

**How to avoid:**
- Embrace RE2 as a feature: it gives you ReDoS safety, which matters because Mimir accepts user-supplied custom rules. Do NOT reach for `dlclark/regexp2` as a default — it restores backtracking and reintroduces catastrophic-backtracking risk on untrusted custom patterns.
- Re-express lookarounds idiomatically: replace negative-lookahead boundary assertions with explicit character-class boundaries, capture-group post-filters, or a two-stage match (broad regex to find candidates, then Go code to validate/reject). Most secret patterns reduce cleanly to "prefix + fixed charset + length," which RE2 handles natively.
- Validate every custom rule at config-load time: compile it, reject patterns with unsupported syntax with a clear error pointing at the RE2 limitation, and ideally run it against a tiny positive/negative fixture the user supplies.
- For each ported built-in rule, write positive and negative test cases so a bad port is caught as a false negative in tests, not in production.
- Guard against ReDoS even in RE2's safer model: cap pattern complexity and apply a per-match timeout/size limit, since pathological inputs (very long lines, huge files) can still be slow.

**Warning signs:**
Custom rule fails to compile; a rule ported from gitleaks compiles but matches nothing; tests pass but a known fixture secret isn't found; users report "this pattern works in gitleaks but not Mimir."

**Phase to address:**
Detection-engine / rule-system phase. Build rule compilation/validation and the positive+negative fixture harness here, and write the "porting PCRE rules to RE2" guidance into custom-rule docs.

---

### Pitfall 7: Slow pre-commit hook gets disabled

**What goes wrong:**
Pre-commit runs on every commit. If it scans the whole working tree or full history on each commit, it adds seconds-to-minutes of latency, and developers reflexively start using `git commit --no-verify`. Once bypassing is habitual the hook protects nothing — and worse, gives false confidence.

**Why it happens:**
The pre-commit path reuses the full-scan engine instead of scanning only staged changes; verification (network calls) leaks into the hook; rule-set loading/compilation happens per invocation with no caching; the hook scans files git would ignore. Rule of thumb from the ecosystem: >10s and developers hate it; ~30–60s and they bypass it.

**How to avoid:**
- Pre-commit must scan ONLY staged changes (the diff being committed), never the working tree or history. Mimir already lists "scan only staged changes" — make the hook use exactly that mode.
- Keep the hook fully offline: no live verification in pre-commit, ever, by default.
- Minimize startup cost: a single static Go binary (Mimir's plan) helps; precompile/lazy-load rules; avoid per-run network/IO.
- Target sub-second on a typical staged change; budget the latency explicitly as a non-functional requirement.
- Make the bypass honest: when a real secret is blocked, give a crisp message with the file:line, the rule, and the exact inline-ignore syntax, so the legitimate path to proceed is "suppress this specific false positive," not "--no-verify everything."

**Warning signs:**
Hook runtime over ~1s on a small commit; team chat mentions `--no-verify`; commit latency complaints; the hook scans unstaged or ignored files.

**Phase to address:**
Pre-commit / staged-scan phase. Latency is a first-class success criterion; benchmark hook time on a representative staged diff as a phase gate.

---

### Pitfall 8: Exit-code / CI semantics conflate "found secrets" with "tool errored"

**What goes wrong:**
CI needs to distinguish three states: clean (pass), secrets found (fail the build), and tool error (config broken, repo unreadable). If "secrets found" and "internal error" share an exit code — or if the tool returns 0 even when findings exist (gitleaks historically returned 0 unless an *error* occurred, requiring `--exit-code`/`--error-on-leak`) — then either real leaks pass CI silently, or a broken config looks like a clean repo. A scanner that exits 0 on a misconfiguration is invisible failure: the gate appears green while protecting nothing.

**Why it happens:**
Naive `os.Exit(len(findings) > 0)` collapses error and findings. Argument-parse errors or unreadable repos can slip through with exit 0 (gitleaks had a bug returning 0 on invalid flags). No documented exit-code contract, so CI integrators guess.

**How to avoid:**
- Define and document an explicit exit-code contract from the start, e.g.: `0` = clean, `1` = secrets found (the CI-blocking case), `2` = usage/config error, other codes for distinct internal failures. (trufflehog uses a dedicated code like 183 for "results found" precisely to keep it unambiguous.)
- Make the "findings → non-zero" behavior the default for the CI/gate path (no opt-in flag needed to fail on leaks), with a documented escape hatch for "scan but don't fail."
- Ensure ALL error paths (bad config, missing repo, regex compile failure, IO error) return a non-findings error code and write to stderr — never silently exit 0.
- Test the contract: assert exit codes for clean repo, repo-with-secret, invalid config, and missing-path. Make these regression tests.

**Warning signs:**
CI is green on a repo you know contains a secret; a typo'd config produces a passing build; integrators ask "how do I make it fail on findings?"; exit code is the same for "found" and "crashed."

**Phase to address:**
CLI/output phase and CI-gate phase. Lock the exit-code contract early because changing it later breaks every user's CI pipeline.

---

## Technical Debt Patterns

Shortcuts that seem reasonable but create long-term problems.

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Redact only at the print layer | Fast to ship human output | JSON/report/error/log paths leak raw secrets; security own-goal | Never — use a redacting secret type at the data model |
| Fingerprint = `commit:file:rule:line` | Trivial to compute, matches gitleaks | Baselines break on every edit/rebase/cross-platform run | Never as the primary key; line/commit OK as advisory metadata only |
| Use go-git for history because it's pure Go | Self-contained binary, no `git` dependency | ~8x memory, OOM on large repos, slow `log --all` | Acceptable for small repos / if you cap blob size and stream; benchmark first |
| Global entropy threshold, one number | Simple config | Either floods (low) or misses (high); can't tune per rule | MVP only; move to per-rule thresholds before adoption push |
| Skip the precision/recall fixture corpus | Ship rules faster | No regression safety; rule edits silently raise noise or drop coverage | Never for a tool whose core value is low false positives |
| Reach for regexp2 (backtracking) to port PCRE rules | Existing rule sets paste in unchanged | ReDoS exposure on untrusted custom rules; loses RE2 linear-time guarantee | Never for custom/user rules; possibly for trusted built-ins with timeouts |
| Verify every occurrence of a secret | Simplest verification loop | Rate-limit bans, lockouts, repeated canary alerts | Never — cache by secret hash, verify once |
| Scan full file at every revision for history | Easy to reason about | Re-scans unchanged content; slow + memory-heavy; misses "added line" framing | Never at scale — scan diffs/patches |

## Integration Gotchas

Common mistakes when connecting to external services.

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| AWS verification | Using a call that mutates or counts toward auth-failure lockout; verifying duplicates repeatedly | Use read-only `sts:GetCallerIdentity`; cache by secret hash; back off on throttling; watch for Thinkst canary tell in caller identity |
| GitHub verification | Ignoring rate-limit headers; one call per duplicate | Honor `Retry-After`/rate-limit headers; exponential backoff; least-privileged read call; cap concurrency |
| Honeytokens / canary tokens | Validating a planted fake key and tripping the owner's alert | Warn users verification is observable/attributable; optionally detect canary tells and report instead of validating |
| System `git` (if shelling out) | Assuming `git` is on PATH and behaves identically across versions/locales | Detect presence; pin to porcelain/plumbing commands with `-z`/stable flags; set `LC_ALL=C`; handle missing-git gracefully |
| go-git | Assuming memory parity with native git | Cap blob size, stream, bound workers; benchmark peak RSS; document the memory tradeoff |
| Provider endpoints generally | Sending a found secret over plain HTTP or to a misconfigured host | TLS only, correct/pinned provider hostname, hard per-call timeout, treat network failure as `unknown` not `invalid` |

## Performance Traps

Patterns that work at small scale but fail as usage grows.

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Full-history full-file scan | Peak RSS scales with repo size; OOM in CI | Scan diffs, stream commits, cap blob size | Large monorepos / long histories (10k+ commits) |
| Unbounded base64/hex/archive decode recursion | Memory amplification, OOM (gitleaks hit ~24GB) | Default decode depth off/shallow; cap archive depth | Repos heavy in encoded/escaped/archived content |
| Raw entropy on everything | Slow + noisy; scans every high-entropy token | Context-gate entropy; allowlist noisy file types | Repos with lockfiles, minified JS, base64 assets |
| Unbounded goroutine fan-out | Many workers each holding a blob; OOM | Bounded worker pool sized to cores/memory | Many large files scanned concurrently |
| Re-loading/compiling rules per invocation | Pre-commit feels sluggish | Compile once; lazy-load; single static binary | Every pre-commit on a busy dev's machine |
| Verifying duplicate secrets | 429s, throttling, lockouts; slow scans | Cache verification by secret hash; verify once | Any secret committed across many files/commits |
| No max-file-size guard | Tool hangs/times out on a huge or mislabeled-binary file | Skip/flag files over a size cap; robust binary detection | A single multi-GB blob or unmarked binary |

## Security Mistakes

Domain-specific security issues beyond general web security.

| Mistake | Risk | Prevention |
|---------|------|------------|
| Secret value in human/JSON/report output by default | Leak to anyone with CI-log/report access | Redact by default at the data layer; raw only behind explicit `--show-secrets`, never default-on in CI |
| Secret in error/panic/log messages | Leak via stderr, crash dumps, log aggregation | Secret wrapper type with redacting `String()`/`MarshalJSON`; audit all `Errorf`/`log` call sites; lint for secret-typed args to logging |
| Writing secrets to disk (reports, temp files, caches, baselines) | Persistent plaintext leak; baseline committed to git | Reports/baselines store hashes, not values; no plaintext temp files; redact report writers too |
| Verification leaks credential to wrong endpoint | Sending a live key to an attacker-controlled or wrong host | TLS only; correct/pinned provider hostname; never transmit a secret anywhere but its own provider |
| Reconstructable snippet around a finding | Surrounding context reveals the redacted value | Redact the secret span inside the snippet; bound snippet width |
| Backtracking regex on user-supplied rules | ReDoS DoS via malicious custom pattern | Stay on RE2; reject unsupported syntax; per-match timeout and input-size caps |
| Verification trips canary/lockout | Alerts credential owner; locks accounts | Opt-in only; never in pre-commit; cache per secret; read-only calls; canary-tell warning |

## UX Pitfalls

Common user experience mistakes in this domain.

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| No easy way to suppress one specific false positive | Users disable the whole tool to escape one bad finding | Make inline-ignore syntax appear IN the finding message; offer fingerprint to paste into ignore file |
| Findings re-fire after unrelated edits (unstable baseline) | Baseline becomes useless; team ignores output | Stable, line-insensitive, path-normalized fingerprints |
| Noisy first run on a dirty repo | Adoption stalls; "this thing is useless" | Ship `--baseline` create flow + curated default allowlists so first run is calm |
| Cryptic exit codes | CI integrators misconfigure the gate | Documented exit-code contract; clear stderr on errors |
| Pre-commit too slow | `--no-verify` becomes muscle memory | Staged-only, offline, sub-second hook |
| Cross-platform inconsistency (paths/line endings) | Ignore/baseline that works on Linux fails on Windows | Repo-relative forward-slash paths; line-ending-tolerant matching and fingerprints |
| Output not machine-parseable cleanly | Automation breaks | Stable JSON schema, redacted by default, separate from human output stream |

## "Looks Done But Isn't" Checklist

Things that appear complete but are missing critical pieces.

- [ ] **Redaction:** Often only covers human output — verify JSON, report files, error messages, verbose logs, and snippet context are ALL redacted (test by scanning Mimir's own output for known fixture secrets).
- [ ] **Baseline:** Often works only on the authoring machine — verify fingerprints survive line shifts, file moves, rebases, and Windows↔Linux path differences.
- [ ] **Custom rules:** Often "supported" but unvalidated — verify a PCRE rule with `(?!...)` is rejected with a clear RE2 error, not silently broken into a false negative.
- [ ] **History scanning:** Often demoed on a small repo — verify peak RSS stays bounded and wall time is acceptable on a large real repo; verify deleted secrets are actually found.
- [ ] **Verification:** Often verifies naively — verify duplicate secrets are verified once (cache), rate limits are honored, it's off in pre-commit, and network failure yields `unknown` not `invalid`.
- [ ] **Exit codes:** Often only the happy path — verify clean=0, found=nonzero-by-default, config-error=distinct-nonzero, and that a broken config never exits 0.
- [ ] **Binary/large/encoded files:** Often assumed text — verify binary detection, a max-file-size skip, UTF-16 (BE/LE, with/without BOM) handling, and bounded decode depth.
- [ ] **Pre-commit:** Often reuses full-scan engine — verify it scans only staged content, runs offline, and is sub-second on a typical diff.
- [ ] **Allowlists:** Often missing the noisy defaults — verify lockfiles, minified JS, vendored deps, and SVGs don't fire out of the box.

## Recovery Strategies

When pitfalls occur despite prevention, how to recover.

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Secret leaked in output/logs | HIGH | Treat as a real incident: assume the secret is compromised, advise rotation, patch the leak path, add a self-output regression test |
| False-positive explosion | MEDIUM | Add allowlists + context gating, ship a baseline workflow, tune per-rule thresholds, build the fixtures corpus retroactively |
| Unstable fingerprints break baselines | MEDIUM | Redesign fingerprint (path-relative + content-hash, drop line), version the scheme, ship a baseline-regenerate command |
| go-git OOM on large repos | MEDIUM–HIGH | Switch history path to shelled-out `git log -p` diff streaming; add blob-size and decode-depth caps |
| Verification caused lockout/canary alert | MEDIUM | Add per-secret verification cache, backoff, opt-in gating, canary-tell detection; document the risk |
| Ported regex silently broken (false negatives) | LOW–MEDIUM | Add positive+negative fixtures per rule; re-express lookarounds; CI catches regressions thereafter |
| Pre-commit being bypassed | LOW | Switch to staged-only offline scan, cut latency, improve the suppression message |
| Exit-code confusion | LOW | Define/document the contract, add exit-code regression tests, communicate the change |

## Pitfall-to-Phase Mapping

How roadmap phases should address these pitfalls. (Phase names are indicative; align with the actual roadmap.)

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Secret leakage (output/logs/disk/snippet) | Core data model (secret wrapper type) | Automated test scans Mimir's own output/logs for known fixture secrets; grep for secret-typed args to log/error |
| False-positive explosion | Detection engine + Suppression | Precision/recall benchmark on a fixtures corpus stays above threshold; first-run on a real repo is calm |
| RE2 lookahead/backreference breakage | Detection engine / rule system | Custom PCRE rule rejected with clear error; positive+negative fixtures per built-in rule |
| Live-verification lockout/rate-limit/canary | Live verification | Duplicate secret verified once (cache test); 429 backoff test; verification absent from pre-commit; canary warning present |
| Git-history memory/time blowup | Git-history scanning | Peak RSS bounded + acceptable wall time on a large real repo; deleted secret found |
| Baseline/fingerprint instability | Suppression / baseline | Fingerprint survives line shift, file move, and Windows↔Linux path normalization; no raw secret in baseline file |
| Slow pre-commit → bypass | Pre-commit / staged-scan | Sub-second on a representative staged diff; offline; staged-only |
| Exit-code / CI semantics | CLI/output + CI gate | Exit-code regression tests: clean / found / config-error / missing-path |
| Binary/large/encoded/cross-platform handling | File-reading layer (cuts across phases) | Binary skip, max-size skip, UTF-16 BE/LE+BOM, bounded decode depth, repo-relative paths verified |
| Rule quality drift over time | Detection engine (ongoing) | Fixtures corpus runs in CI on every rule change; precision/recall tracked over time |

## Sources

- Gitleaks issue #2019 — memory blowup / `--max-decode-depth` behavior (OOM up to ~24GB): https://github.com/gitleaks/gitleaks/issues/2019
- Gitleaks issue #1830 — entropy detection flagging plaintext variable names/placeholders: https://github.com/gitleaks/gitleaks/issues/1830
- Gitleaks issue #97 — entropy checks discussion (entropy ≠ "is a secret"): https://github.com/gitleaks/gitleaks/issues/97
- Gitleaks issue #575 — too many false positives: https://github.com/gitleaks/gitleaks/issues/575
- Gitleaks issue #1284 — baseline entries require more than the fingerprint: https://github.com/gitleaks/gitleaks/issues/1284
- Gitleaks issue #1565 — paths and fingerprints are platform-specific / not portable: https://github.com/gitleaks/gitleaks/issues/1565
- Gitleaks PR #1354 — fingerprint generation/validation against `.gitleaksignore` for no-git scans: https://github.com/gitleaks/gitleaks/pull/1354
- Gitleaks issue #478 — add exit code 1 on detected leak: https://github.com/gitleaks/gitleaks/issues/478
- Gitleaks issue #1464 — exit 0 on invalid flags (silent failure): https://github.com/gitleaks/gitleaks/issues/1464
- Gitleaks release v8.20.0 — decode-depth / archive-depth recursive decoding: https://github.com/gitleaks/gitleaks/releases/tag/v8.20.0
- Gitleaks "How Gitleaks Works" deep dive (fingerprint format `commit:file:rule:line`): https://gitleaks.org/how-gitleaks-works-deep-dive-into-secret-detection-scanning-engine-and-security-automation/
- TruffleHog docs — verification caching (prevents endpoint overload / account lockouts): https://docs.trufflesecurity.com/verification-caching
- TruffleHog blog — detecting AWS canaries without setting them off (canary tell in STS caller identity): https://trufflesecurity.com/blog/canaries
- TruffleHog blog — secret scanning encoded and archived data (UTF-8/UTF-16/base64/escaped unicode): https://trufflesecurity.com/blog/secret-scanning-encoded-and-archived-data
- TruffleHog GitHub README — find/verify/analyze leaked credentials, `--fail` exit semantics: https://github.com/trufflesecurity/trufflehog
- go-git issue #447 — memory/performance cloning large repos (~8x native git): https://github.com/src-d/go-git/issues/447
- go-git issue #1087 — `git log --all` flattening hurts big-repo performance: https://github.com/src-d/go-git/issues/1087
- Checkmarx Go-SCP — Go regular expressions / RE2 limitations and untrusted-input safety: https://checkmarx.gitbooks.io/go-scp/content/general-coding-practices/regular-expressions.html
- dlclark/regexp2 — backtracking regex engine (and its lack of linear-time guarantee): https://github.com/dlclark/regexp2
- GitGuardian — keeping secrets out of logs (hash-not-value redaction strategy): https://blog.gitguardian.com/keeping-secrets-out-of-logs/
- "From pre-commit to Prek" / pre-commit performance (>10s = hated, 30–60s = bypassed): https://medium.com/@zwbf/from-pre-commit-to-prek-the-evolution-of-code-quality-automation-08f4bab00710
- GitLab issue #341639 — Secret Detection times out on large file not identified as binary: https://gitlab.com/gitlab-org/gitlab/-/issues/341639
- DevSecOps School — security regression testing / rule quality and drift: https://devsecopsschool.com/blog/security-regression-tests/
- Mimir PROJECT.md — project context, constraints, and key decisions (read directly)

---
*Pitfalls research for: Go-based secret/credential scanner (CLI + CI gate + pre-commit hook)*
*Researched: 2026-05-22*
