# Claude Cyber-Classifier Detection Toolkit

Two diagnostic tools + research artifacts for diagnosing why Anthropic's **cyber
safety classifier** flags innocuous prompts (`"hi"`) in your Claude Code
sessions — silently downgrading Opus 5.5 → Opus 4.8 for the rest of the session
(`scope:"session"` pinning).

Verified against `claude` CLI **2.1.328** on this machine (2026-11-19).

---

## Tools

### 0. `triage_context.py` — unified triage *(start here; zero API calls)*

One command over any scope, ending in either a **deterministic culprit** or an
**INCONCLUSIVE → invoke the cyber-context-triage skill** verdict:

```bash
./triage_context.py --scope all                                  # fleet pain ranking
./triage_context.py --list                                       # slugs only
./triage_context.py --scope project "--slug=<project-slug>"      # events + injector inventory + content provenance
./triage_context.py --scope session "--slug=<slug>" --session-id af631de3   # turn-by-turn anatomy
```

It auto-detects context injectors (memory-management plugins via signature
registry, MCP servers, SessionStart/UserPromptSubmit hooks from user +
project settings) and shows which injector's payload carries the flagged
security vocabulary.

### 1. `mine_refusals.py` — offline token attribution *(zero API calls)*

Mines the project's own transcript history: every refusal is attributed to the
exact assembled request that triggered it (`api-request-blob` rows), then
token-lift ranks what distinguishes tripped compositions from clean ones.

```bash
./mine_refusals.py                      # DevSecOps Deployment slug (default)
./mine_refusals.py --list               # see all project slugs + session counts
./mine_refusals.py --slug <other-slug> --top 30
```

Reports land in `results/attribution-*.md`.

### 2. `scan_memory.py` — live hypothesis testing (~$0.05/call)

Tests whether a *specific* context file chunk trips the classifier under
isolated headless replay. Each candidate gets its **own throwaway cwd** mapping
to its own synthetic project memory; detection parses the run's transcript for
the ground-truth signals (camelCase `apiRefusalCategory`, see below). Gated by
N0/P1 calibration controls with hard-abort semantics.

```bash
./scan_memory.py --dry-run                    # plan only, zero cost
./scan_memory.py --calibrate-only             # N0/P1 controls, ~6 calls
./scan_memory.py                              # full sweep: ~400 calls ≈ $12–45
./scan_memory.py --chunk-mode section --limit 20 -v
```

⚠️ Know its limitation (see Findings): headless memory-replay had **0/9 repro**
— the real-world trigger mix includes in-session state. Use it to test *hypotheses*
("does this one rewritten line still trip?"), not blind sweeps.

---

## Findings (evidence-backed)

| # | Finding | Evidence |
|---|---------|----------|
| F1 | Ground truth signal = transcript system record `{type:"system", subtype:"model_refusal_fallback", apiRefusalCategory:"cyber", originalModel→fallbackModel}` (+ assistant `stop_reason:"refusal"`). The snake_case `api_refusal_category` name and the `StopFailure` hook approach from the original sketch are both wrong — StopFailure only fires on API errors, while the cyber fallback is a successful retry. | Real transcripts on this machine |
| F2 | A fresh headless session launched **inside the real project dir** with probe `hi` completed CLEAN on Opus 5.5 today. | direct probe |
| F3 | Full MEMORY.md as sole memory in isolated temp-project replays: **0/9 trips**. Memory-content-alone does not reproduce the flagging. | calibration runs |
| F4 | Auto-memory DOES load headlessly from `~/.claude/projects/<slug>/memory/MEMORY.md` (sentinel round-trip confirmed); slug = absolute cwd path with non-alphanumerics → `-`. | U2 probe |
| F5 | **The offender is in-session task-state, not the memory file**: discriminative tokens in tripped requests (`webauthn`, `threat-model`, `tainted-path-traversal`, `stride`, Semgrep/Burp task summaries) appear in 5/7 tripped turns vs 1/939 clean turns, and have ZERO coverage in MEMORY.md lines. They ride in via rolling todo/conversation attachments inside long-lived sessions. | `mine_refusals.py` output |
| F6 | Refusal events per project are rare (single digits), but each pins the session to the weaker model — matching "everything feels degraded all day". Today's cascade shows Claude Code injecting its own recovery prompt after the initial flag, multiplying visible refusals. | event timeline scan |

## Remediation ladder (cheapest → most durable)

1. **Start fresh sessions** for mundane work instead of pushing through pinned
   ones — a flag pins the weaker model until the next fresh session.
2. **Find & remove the context injector.** In the proven 2026-11-19 case the
   culprit was the `claude-mem` plugin: its SessionStart machinery reinjected
   ~100KB of pentest-history digests ("Work state, still open" + date-headed
   journals) into every *fresh* session automatically — no /resume needed.
   Full cleanup = uninstall + drop `enabledPlugins` entry in settings.json +
   delete cache/marketplace/data dirs under `~/.claude/plugins/`.
3. Prune/neutralize the recurring flagged ingredients surfaced by
   `mine_refusals.py` from whatever attachment/import keeps re-injecting them.
4. Apply to the **Cyber Verification Program** (link embedded in every refusal
   payload) — since this is legitimate security work, it's the official fix:
   https://support.claude.com/en/articles/14604842-cyber-verification-program

## Skill for other agents

`skills/cyber-context-triage/SKILL.md` (also installed at
`~/.claude/skills/cyber-context-triage/`) encodes the full forensic procedure:
ground-truth facts, automated triage via these tools, offline hypothesis
generation, deterministic replay verification, remediation proof-loop, and
anti-contamination rules for the investigating agent. Any future agent hitting
this class of problem should load that skill first.

## Key files

- `triage_context.py` — unified triage: sessions / projects / fleet + injector auto-detection
- `mine_refusals.py` — token-level offline attribution
- `scan_memory.py` — live isolated chunk-replay hypothesis tester (use sparingly)
- `skills/cyber-context-triage/SKILL.md` — agent skill: the full manual forensic procedure
- `REPORT_classifier_bisect_spec.md` — expert analysis & implementation spec
- `results/` — reports (attribution-*.md, report-*.md, results-*.jsonl)

## Anti-contamination notes

- Throwaway scans never touch existing state: only brand-new temp cwds +
  synthetic project dirs (auto-removed after each verdict).
- Reports print hashes/ranges/token names; full text stays on disk.
- This repo/session deliberately avoided ingesting large verbatim chunks of the
  polluted memory.
