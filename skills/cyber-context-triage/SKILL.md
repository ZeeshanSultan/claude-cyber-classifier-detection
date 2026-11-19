---
name: cyber-context-triage
description: >
  Diagnose & fix false-positive Anthropic CYBER-classifier flags in Claude Code:
  innocuous prompts ("hi") triggering model_refusal_fallback / Opus→smaller-model
  session pinning. Use when a user reports "every message gets flagged as cyber",
  "model downgraded to Opus 4.x", refusal banners about Cyber safeguards, or asks
  which file/plugin/chunk of their context trips the classifier. Also use after
  triage_context.py prints INCONCLUSIVE — this skill is the manual forensic
  procedure (hypothesis → isolation → headless replay → n-of-m voting).
---

# Cyber-Classifier Context Triage (manual forensics)

Verified against claude CLI 2.1.328 (macOS) on 2026-11-19. Re-validate field
names if versions drift (see §0).

## Ground truth facts (do not re-derive)

1. **Signal lives in transcript JSONL**, not hooks. A trip = system record
   `{type:"system", subtype:"model_refusal_fallback", apiRefusalCategory:"cyber"
   (camelCase!), originalModel→fallbackModel, scope:"session"}` plus assistant
   rows with `"stop_reason":"refusal"` / `message.stop_details.category`.
2. **StopFailure hook will NOT catch this** — the cyber fallback is a successful
   retry on another model; StopFailure fires only on API errors.
3. **scope:"session"** means one flag pins the weaker model until a *fresh*
   session. Cascades multiply visible refusals via CC's own recovery prompt.
4. Classifier scores the WHOLE assembled request: system prompt, CLAUDE.md,
   memory files, **git status**, tool/skill listings, AND every SessionStart/
   UserPromptSubmit injection (memory-manager digests, todo journals).
5. Fresh sessions usually probe clean; long/resumed/re-injected ones don't.
6. Headless auto-memory DOES load: cwd slug = absolute path with non-alnum → "-";
   file at `~/.claude/projects/<slug>/memory/MEMORY.md`. Sentinel-test before trusting.

## Phase 0 — Calibration of tools

```bash
CLAUDE_BIN=$(command -v claude || echo ~/.local/bin/claude)
"$CLAUDE_BIN" --version        # note version; field names verified on 2.1.328
cd /tmp && "$CLAUDE_BIN" --print --output-format json --max-turns 1 "Reply AUTH_OK"
# expect result=AUTH_OK. If auth fails under relocated CLAUDE_CONFIG_DIR, run
# probes with DEFAULT config dir but unique throwaway cwds instead (proven path).
```

Schema probe (if refusing runs exist):
`grep -m1 'model_refusal_fallback' <any-transcript>.jsonl | jq '.apiRefusalCategory'`
If null/missing → investigate current schema before proceeding.

## Phase 1 — Automated triage (run first)

Use the toolkit in `Claude-Cyber-Classifier-Detection/`:

```bash
./triage_context.py --scope all                     # fleet pain ranking
./triage_context.py --scope project --slug <slug>   # event anatomy + provenance
./triage_context.py --scope session --slug <slug> --session-id <8chars>
```

- DETERMINISTIC CULPRIT → jump to Phase 4.
- Clean/no events → user's complaint may be stale; verify with live probe (§3).
- INCONCLUSIVE → Phase 2.

## Phase 2 — Hypothesis generation (offline)

1. Rank discriminator tokens: `./mine_refusals.py --slug <slug>` — lift of
   tripped vs clean requests (`results/attribution-*.md`). Look for >50%-coverage
   tokens absent from memory files.
2. For each high-coverage token find its physical origin: search inside the
   flagged mega-request blob for its offset, then walk back to the nearest
   heading. Candidate origins by pattern:
   - Date headings (`### Nov 17, 2026`) + "Work state, still open" → a
     **memory-manager journal** (claude-mem or kin): check `enabledPlugins`,
     its SessionStart/UserPromptSubmit hooks, and its storage dir.
   - `<system-reminder>` walls listing todos → in-session task-state growth;
     solution is fresh sessions, not file edits.
   - Skill/personality docs (`Ponytail`, caveman…) → plugin payloads; normally
     benign unless dense with security vocabulary.
3. Memory-file acquittal test: `grep -ic '<token>' MEMORY.md` for each top
   token. Zero/near-zero coverage ⇒ memory is innocent (typical outcome).

## Phase 3 — Deterministic verification only when cheap signals disagree

Isolated headless replay (proven recipe):

- Per candidate chunk: create temp cwd `/tmp/cctx_<rand>/<caseN>`; pre-write
  `~/.claude/projects/<slug(cwd)>/memory/MEMORY.md` with ONLY that content;
  run `"$CLAUDE_BIN" --print --output-format json --max-turns 1 --model
  <the-flagged-originalModel> "hi"` from that cwd.
- Harvest that run's own transcript under the NEW slug dir; trip =
  `subtype=="model_refusal_fallback"` OR `stop_reason=="refusal"`.
- Vote K=3 (trip iff ≥2). Parallelize ≤2 lanes; jitter 1–3 s.
- Controls MANDATORY: N0 benign (must be 0/3) and P1 full real content
  (needs repro ≥ ~1/3). Abort if controls fail — do not publish verdicts.
- Cost guardrail: ~$0.03–0.12/call; full sweeps ≈ $12–45. Prefer offline phases.
- Known failure mode: memory-only replays often DON'T reproduce (trigger rides
  in injected journal/todo payloads) — a clean P1 falsifies the hypothesis,
  it does NOT mean the problem is gone.

## Phase 4 — Remediate, then prove it fixed

Ladder (cheapest first):
1. Fresh session per workstream; never push through a pinned session.
2. Remove/disable the culprit memory manager for affected projects; prune its
   stored digests (its data dirs under `~/.claude/plugins/data/…`).
3. Leftovers sweep: `find ~/.claude -iname '*<tool>*' -not -path '*node_modules*'`;
   drop dangling `enabledPlugins` entries (backup settings.json first);
   MCP-server keys referencing deleted plugins in `~/.claude.json` are inert.
4. Rewrite offender phrasing in sources you control (weapon-nouns → plain ops).
5. Official escape hatch for legit security work — advise applying:
   https://support.claude.com/en/articles/14604842-cyber-verification-program

Proof loop: new session → `"hi"` probe → confirm no fallback banner and
`modelUsage` shows the original model; next day re-run
`./triage_context.py --scope all` expecting zero new events.

## Anti-contamination rules for YOU (the investigating agent)

- Never open the polluted memory/digests in your own session when avoidable;
  prefer grep offsets & hashes over reading full bodies.
- Any file needing eyes-on: read ≤80 lines around a located offset.
- Run all throwaway `claude -p` calls with `cwd` = fresh temp dirs; delete them
  and their synthetic project dirs afterwards.
