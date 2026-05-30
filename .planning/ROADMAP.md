# Roadmap: Mimir

## Milestones

- ✅ **v1.0 MVP** — Phases 1–4 (shipped 2026-05-30)

## Phases

<details>
<summary>✅ v1.0 MVP (Phases 1–4) — SHIPPED 2026-05-30</summary>

- [x] Phase 1: Usable End-to-End Scanner (3/3 plans) — completed 2026-05-22
- [x] Phase 2: False-Positive Control (Suppression + Baseline) (4/4 plans) — completed 2026-05-29
- [x] Phase 3: Full Source Coverage (Git History + Staged + Pre-commit) (3/3 plans) — completed 2026-05-30
- [x] Phase 4: Opt-in Live Verification (AWS + GitHub) (3/3 plans) — completed 2026-05-30

Full phase details, success criteria, and the milestone summary are archived in
[`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md). Requirements and the
completion audit are in [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md)
and [`milestones/v1.0-MILESTONE-AUDIT.md`](milestones/v1.0-MILESTONE-AUDIT.md).

</details>

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Usable End-to-End Scanner | v1.0 | 3/3 | Complete | 2026-05-22 |
| 2. False-Positive Control | v1.0 | 4/4 | Complete | 2026-05-29 |
| 3. Full Source Coverage | v1.0 | 3/3 | Complete | 2026-05-30 |
| 4. Opt-in Live Verification | v1.0 | 3/3 | Complete | 2026-05-30 |

**Milestone v1.0 shipped 2026-05-30** — all 21 v1 requirements satisfied (4 phases, 13 plans,
~3,289 LOC Go + 3,531 LOC tests). One tracked tech-debt item: path-glob suppression
(`.mimirignore`/default-excludes) is not yet applied to `--git`/`--staged` scans — see the
archived milestone audit. Next: `/gsd-new-milestone` for v1.1/v2.
