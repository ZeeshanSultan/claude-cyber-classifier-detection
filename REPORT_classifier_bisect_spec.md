# Cyber-Classifier Chunk-Bisection Scanner — Research Report & Implementation Spec
_Environment verified live: claude CLI **2.1.328**, macOS, machine `zeeshan`. Date 2026-11-19._

---

## 1. Confirmed understanding of the idea (restated)

**Claim chain:** Claude Code's *auto-memory* for project `-Users-zeeshan-Desktop-DevSecOps-Operating-Model-Deployment` lives in that project dir's `memory/MEMORY.md` (18.7 KB, 127 lines, one summary line per topic file). Its content is overwhelmingly AppSec/pentest/scanner vocabulary (Semgrep, Trivy, DefectDojo, pentest, SSRF, OTP/MFA bypass, "Agentic Pentest", kudo-strix/Kali, sandbox bypass…). Claude Code injects this memory into every request it assembles for that project. The provider-side **cyber safety classifier** scores that assembled request. Therefore even an innocuous prompt ("hi") arrives wrapped in cyber-flavored context, gets `[cyber]`-flagged, and Claude Code silently falls back to a lesser model (`claude-opus-5-5 → claude-opus-4-8`, `scope: "session"` → pinned for the rest of the session).

**Proposed fix mechanism:** treat MEMORY.md chunks as hypotheses. For each chunk, spawn an isolated throwaway `claude -p "hi"` run whose context contains *only* that chunk, detect whether the run got flagged, and blame any tripping chunk. Refine by bisection. Never feed dirty content into the operator's main session.

This idea is **sound and worth building** — see §3–4 for what changes relative to the sketch ( chiefly: hook choice and detection signal).

### Local evidence snapshot
- `~/.claude/projects/-Users-zeeshan-Desktop-DevSecOps-Operating-Model-Deployment/memory/` = 129 files. `MEMORY.md` = 18,746 B / 127 lines; largest linked topics include `portal-auth-rbac-oidc-feasibility.md` (29 KB), `chain305-deploy-2026-10-05.md` (24 KB), `scanner01-production-freeze.md` (15 KB).
- Only `MEMORY.md`'s index (first-line summaries) is plausibly injected wholesale each turn; linked files load on demand. Note the summaries themselves are dense with security nouns ("OTP/MFA bypass", "PAT-in-payload leak paths", "pentest", "SSRF tuning"), so the index alone is already a strong trigger candidate.
- Transcripts in this project dir contain hundreds of refusal events concentrated on 2026-11-11 during ordinary frontend work (Edits to `.ts` files!) — consistent with session-level contamination, and notably one `model_refusal_fallback` fired immediately after an `Edit` **to the memory file itself**.

---

## 2. Fact sheet

| # | Assumption | Verdict | Evidence |
|---|---|---|---|
| A1 | `StopFailure` hook event exists (v2.x, 2026) | ✅ **CONFIRMED** | Official hooks reference (`code.claude.com/docs/en/hooks`): fires "when the turn ends due to an API error"; matchers are error types (`rate_limit`, `server_error`, …); stdin payload `{session_id, transcript_path, cwd, hook_event_name, error_type, error, error_message, last_assistant_message}`. |
| A2 | `StopFailure` receives `api_refusal_category`-style data / is usable to detect the cyber refusal | ❌ **REFUTED as designed** (usable only as an edge-case net) | (a) Payload has **no** refusal/category field — only generic API-error fields. (b) Field name in the wild is camelCase `apiRefusalCategory`, not snake_case, and it is **not** in the StopFailure payload at all. (c) Crucially, the cyber fallback is `trigger:"refusal", direction:"retry"`: the CLI *retries successfully on the fallback model*. The turn does **not** end in an API error ⇒ `StopFailure` almost certainly **never fires** for this case. Hook output/exit codes are ignored on this event anyway (observational only). |
| A3 | Transcript JSONL exposes classifier verdicts | ✅ **CONFIRMED** (ground truth from this very machine + corroborated publicly) | Exact records observed locally in `60d5a173…jsonl` L45 and `ffbae4d6…jsonl`, and reproduced in anthropics/claude-code issues #87938, #83073, #91209, #66657: |
| A4 | Assistant-message-level marker exists | ✅ **CONFIRMED** | `message.stop_details = {"type":"refusal","category":"cyber","explanation":"Cyber safeguards flagged this message…Cyber Verification Program…","fallback_has_prefill_claim":false,"cyber_verification":{"type":"inactive"}}` and `"stop_reason":"refusal"` (261× end_turn vs 4× refusal counts seen; the refusal ones sit inside `stop_details` on assistant rows). |
| A5 | Headless `claude -p` supports isolating context | ✅ **CONFIRMED** | Documented flags: `-p/--print`, `--output-format json\|stream-json`, `--model`, `--settings <file>`, `--append-system-prompt`, `--allowedTools`, `--strict-mcp-config`. New documented flag **`--safe-mode`**: "disables customizations such as CLAUDE.md, skills, MCP servers, and hooks" — a perfect **negative-control switch**. `CLAUDE_CONFIG_DIR` env var redirects the entire config root (~/.claude → temp profile) — confirmed by third-party format catalog (cv/docs/FORMATS.md) and standard usage. |
| A6 | Classifier input = memory file only | ❌ **REFUTED — broader** | Anthropic docs (model-config → "Check what triggered fallback"): *"Fallback can trigger on the first request of a session… because the first request carries workspace context such as your CLAUDE.md content **and git status**. A repository that contains security or biology material can trip the classifier on that context alone."* Plus locally: refusals attributed to turns whose newest entry was an assistant Edit/tool_result; GH issue #66657 documents a bare `hello` being flagged via the static preamble alone. ⇒ Experiment must control for: cwd/dirname, git status, settings/skills/hooks, MCP list — not just memory text. |

**Exact ground-truth transcript fragments** (verbatim, truncated):

```json
{"parentUuid":"21488f7c-…","type":"system","subtype":"model_refusal_fallback",
 "level":"warning","trigger":"refusal","direction":"retry","scope":"session",
 "originalModel":"claude-opus-5-5","fallbackModel":"claude-opus-4-8",
 "requestId":"req_011ChC17xbgZU8hvqKUW7euT",
 "apiRefusalCategory":"cyber",
 "apiRefusalExplanation":"Cyber safeguards flagged this message. If this is legitimate security work, you can apply for the Cyber Verification Program: https://support.claude.com/en/articles/14604842-cyber-verification-program.",
 "apiRefusalCyberVerification":{"type":"inactive"},
 "retractedMessageUuids":[],"refusedUserMessageUuid":"994d784f-…",
 "uuid":"ad5a43c0-…","timestamp":"2026-11-19T08:54:14.577Z",
 "sessionId":"60d5a173-…","version":"2.1.328",
 "cwd":"/Users/zeeshan/Desktop/DevSecOps Operating Model/Deployment"}
```

Assistant row fragment:

```json
{"type":"assistant","message":{"…","stop_reason":"refusal",
 "stop_details":{"type":"refusal","category":"cyber",
   "explanation":"Cyber safeguards flagged this message.…",
   "fallback_has_prefill_claim":false,
   "cyber_verification":{"type":"inactive"}}, …}}
```

Public corroboration of the exact user symptom: **GH #66657** — "Fable 5 cyber-classifier … flags a bare `hello` — scores the static request preamble, not the user message… no repo content, no tool calls in context" (`apiRefusalCategory:null` there, banner says "cybersecurity"); **GH #91209** — cyber FP on plain local diagnostics pins the whole session to Opus 4.8 because `scope:"session"`.

Support-article URL embedded in the payload: `https://support.claude.com/en/articles/14604842-cyber-verification-program` (legitimate-work verification escape hatch — worth mentioning to the user as the official remediation alongside cleanup).

**Remaining UNCERTAIN items** (+ one-shot probes to settle them):
- U1: Does the temp-profile run authenticate without copying credentials? macOS keychain credential (`Claude Code-credentials`) is likely profile-independent; otherwise copy `~/.claude/.credentials.json` (if present) or export `ANTHROPIC_API_KEY`. *Probe:* `CLAUDE_CONFIG_DIR=$(mktemp -d) claude -p "say ok" --output-format json` and inspect for auth error.
- U2: Does auto-memory (`memory/MEMORY.md`) actually load in `-p` mode, and from `$CLAUDE_CONFIG_DIR/projects/<slug>/memory/`? *Probe:* run twice in a temp cwd; between runs write a sentinel `MEMORY.md` ("SENTINEL-BANANA") into the discovered slug dir; then `claude -p "What is the first word of your project memory file? Reply with only that word."` Expect `SENTINEL-BANANA`.
- U3: Do `--output-format stream-json` streams surface the `model_refusal_fallback` event (e.g., as an SDK system message)? *Probe:* force a tripping setup (full real memory copied) and run with stream-json; grep for `refus`. Until answered, rely on transcript parsing (signal S1 below), which needs nothing from stdout.
- U4: Whether the fallback event's absence could ever coexist with a silent degrade *without* any transcript marker. Considered unlikely (marker is written even when category/explanation are null — see #66657). Treat "no marker + correct model" as clean.

---

## 3. Refined detection strategy (ranked, with fallbacks)

Detection target per run: *"did THIS run's request get refused/fallen back?"*

| Rank | Signal | How | Why |
|---|---|---|---|
| **S1 (primary)** | `model_refusal_fallback` record in the run's own transcript JSONL | After each run, locate the newest `sessions/*.jsonl` under `<TEMP_CLAUDE_CONFIG>/projects/<slug-of-tempdir>/` (or track `session_id` from stream-json `init`) and assert: count of lines where `jq 'select(.type=="system" and .subtype=="model_refusal_fallback")' > 0`; grab `.apiRefusalCategory // "unknown-category"` | Deterministic, offline, covers null-category cases; works identically in interactive-equivalent and `-p` runs. Highest precision. |
| **S2 (tiebreak/refinement)** | Model downgrade delta | Requested model M = `--model claude-opus-5-5`; inspect assistant rows' `message.model`: if any row ≠ M while S1 absent, investigate; if S1 present, record `(M → fallbackModel)` from the event | Free corroboration; also confirms the *severity* claim (lesser model answering). |
| **S3 (belt-and-braces)** | refusal-shaped stop details | Scan assistant rows for `message.stop_details.type=="refusal"` or `"stop_reason":"refusal"` | Catches refusals that end in a hard refusal instead of fallback (documented for bio on some models; possible edge behavior changes). |
| **S4 (net)** | `StopFailure` hook writing a marker file | Keep the user's hook concept but fixed: matcher on error types only; log `${error_type}` to `/tmp/scan_stops.log` | Will NOT catch the normal retry-fallback path (A2) — kept only because if classification ever escalates to a hard API failure/hard refusal, this becomes the only signal. Cheap insurance; do not build the scanner around it. |
| **S5 (stderr heuristic, optional)** | Human banner text leaks to CLI output in some versions ("flagged this session… Details: `[cyber]`") | `grep -iE "flagged|safeguard|Opus .* is answering|Switched to" stderr/stdout` | Version-dependent noise; rank last, never sole basis. |

**Precise jq one-liners (validated against real records):**

```bash
trip_count=$(jq -s '[.[] | select(.type=="system" and .subtype=="model_refusal_fallback")] | length' "$tr")
cat=$(   jq -rs '[.[] | select(.subtype=="model_refusal_fallback") | .apiRefusalCategory] | unique | join(",")' "$tr")
models=$(jq -rs '[.[] | select(.type=="assistant") | .message.model] | unique | join(",")' "$tr")
```

(Guard: the transcript may lag writes — poll until mtime stable / last line parses; usually instant for finished `-p` runs.)

---

## 4. Isolation strategy (verified mechanisms)

Goal: each throwaway run sees **clean everything + exactly one chunk** of memory, in a **different project identity** than the polluted one, with **zero leakage** into the operator's real session.

**Recommended: temp `CLAUDE_CONFIG_DIR` profile + synthetic project.** `CLAUDE_CONFIG_DIR` relocates ALL state (projects, memory, settings, plugins/hooks, skill listings, MCP config) — this simultaneously removes: claude-mem & friends (their banner appeared on our own test invocation!), Burp/gbrain/shellpilot MCP tools, skills, and the real project's memory — while keeping the same binary + auth. This matters doubly because classifier input includes tool/skill listings and settings (#66657 showed tool deltas score).

Layout created per scan batch:

```
$WORK/
  profile/                       # CLAUDE_CONFIG_DIR
    settings.json                # {"includeCoAuthoredBy": false} + disable autoupdates; NO hooks needed
    projects/
      <slug-of-case-dir>/        # pre-created using slug() below
        memory/
          MEMORY.md              # THE CHUNK (single hypothesis)  ← variable part
          [optionally: one renamed topic file if scanning linked .md files]
  cases/
    chunk-<NNN>/
      CLAUDE.md                  # empty or fixed benign 1-liner constant across cases
  results/results.jsonl
```

Slug function (empirically matched on this machine, e.g. `/Users/zeeshan/Desktop/DevSecOps Operating Model/Deployment` → `-Users-zeeshan-Desktop-DevSecOps-Operating-Model-Deployment`): map every char outside `[A-Za-z0-9]` to `-`, preserve existing casing, keep leading `-`; then confirm by doing the U2 discovery run first and reading the actual created dirname rather than trusting the formula.

Run recipe per case:

```bash
CASE=$1                     # a case dir under $WORK/cases
cd "$CASE"
CLAUDE_CONFIG_DIR="$WORK/profile" \
claude --print \
       --model claude-opus-5-5 \        # SAME model the pollution manifests on (originalModel in real events)
       --output-format json \
       --max-turns 1 \
       --tools "" \                     # minimize tool schema surface → constant across cases
       --strict-mcp-config \
       "hi" 2>"$WORK/logs/$CASE.err" >"$WORK/logs/$CASE.out"
# then S1/S2/S3 read of  newest transcript under $WORK/profile/projects/<slug>/
```

Key choices justified:
- **Model pinning is mandatory**: the cyber classifier exists on specific frontier models (observed `originalModel: claude-opus-5-5`; docs classify Fable/Opus 5.5/Sonnet 5.5/Opus 5 as classifier-bearing with different fallback targets). Scanning on a smaller model could yield systematically false "clean" verdicts. Must read the user's configured/default model and use it verbatim.
- **Prompt exactly `"hi"`** (constant probe), matching the real-world symptom.
- **Same temp cwd for all cases** ⇒ identical slug, dirname, git-status(none), CLAUDE.md; the ONLY varying datum is `memory/MEMORY.md`. That is the experimental design that makes chunk attribution valid.
- **No `--continue`, fresh session each run**: subagent concern is right — resuming would inherit a session-pinned fallback model (`scope:"session"`!), destroying independence between cases. Each case = brand-new session id.
- **Controls** (non-negotiable for validity):
  - **N0 negative control:** `MEMORY.md` = empty/benign ("# Notes\nNothing here yet."). Must come back clean; if N0 trips, the harness itself is broken or the environment/model flags regardless → redesign before trusting any verdict.
  - **P1 positive control:** verbatim copy of the full real `MEMORY.md`. Should trip ≥1× reliably; calibrates vote thresholds and proves the pipeline detects the phenomenon. (If P1 does *not* reproduce, the memory hypothesis itself is falsified — pivot to hunting other inputs: settings, CLAUDE.md, skills.)
  - Optionally **P2 placebo:** full real MEMORY.md under `--safe-mode` … not applicable in profile-isolation (customizations already gone); instead do a duplicate-run stability pair.
- **Auth inside temp profile (U1):** attempt order — (1) rely on existing `ANTHROPIC_API_KEY` (present in this shell env per the CLI banner), (2) copy `~/.claude/.credentials.json` into the profile if it exists, (3) macOS keychain credential (verify with U1 probe; expected to work because it isn't stored under the config dir).
- **Anti-contamination guarantee:** the operator's real `~/.claude` is never written to (profile redirect); the throwaway runs' transcripts land wholly under `$WORK/profile`.

---

## 5. Algorithm (pseudocode)

Two-stage: exhaustive linear scan over atomic units, then union/complement disambiguation — plain **binary bisection is skipped deliberately** because (a) classifier outputs are stochastic (bisecting assumes deterministic OR-composition, which voting barely tames), (b) multiple independent offenders are plausible (dozens of security-heavy lines), and (c) n ≈ 128 lines is small enough that a linear sweep + interaction repair is affordable and gives strictly more information.

```text
INPUT: MEMORY_MD (real), MODEL (from user's live config), WORK tmpdir
UNITS := lines of MEMORY_MD            # default granularity: 1 line = 1 topic-link
CONFIG: VOTES_K=3, PASS_NEEDS=2_trips? -> trip iff trips >= ceil(K/2); MAX_PARALLEL=2..3
                                   # three voters, majority; linear cost O(3n) calls

0. SETUP: build profile skeleton; auth smoke test (U1); slug discovery run (U2);
          sentinel check that memory loads.
1. CALIBRATE:
     c_clean := probe(N0 benign, ×VOTES_K)         # expect all-clean
     c_dirty := probe(P1 full-real, ×VOTES_K)      # expect ≥1 trip
     if c_clean trips anywhere → ABORT with diagnosis (env-level flagging)
     if c_dirty never trips → ABORT: "memory hypothesis unsupported;
                                    audit other inputs (settings/CLAUDE.md/skills)"
     repro_rate := trips(c_dirty)/K                 # remember it; interpret marginal chunks relative to it
2. LINEAR SWEEP (pool, parallel ≤ MAX_PARALLEL, jittered):
     for u in UNITS:
         trips(u) := votes via run(chunk=u)
         record {unit_id, line_range, text_hash, cat, orig→fallback models, requests_ids, votes}
3. INTERACTION REPAIR (chunks are probabilistically additive, not monotone):
     accused := [u : trips(u) ≥ threshold_u]        # threshold scaled: max(2, ceil(repro_rate*K)-? ) 
     union_probe := probe(concat(accused, in file order))          # sanity
     complement_probe := probe(MEMORY_MD minus accused)            # if STILL trips → missed contributors:
                                                                    # add next-best marginals greedily until clean
     keep-offenders := greedy cover: start empty set S; while probe(S ∪ next-accused) trips
                       and probe(S) is clean margin-wise, grow S by max-marginal-cost(unit)
4. OUTPUT report:
     offending units sorted by trip-rate desc, with verbatim line, category mix,
     requestId evidence, and union/complement verdicts
     → human action: rewrite/neuter those lines in MEMORY.md (keep links, strip
       weapon-ish nouns: bypass/exploit/PAT/token/pentest framing),
     THEN rerun P1-style validation on the edited file expecting ≈ clean,
     and note Cyber Verification Program as official long-term remedy.
run(chunk):
     atomically write $PROFILE/projects/<slug>/memory/MEMORY.md = chunk
     cd $CASEDIR; launch claude -p "hi" (§4 recipe); wait; harvest transcript
     return {tripped: S1 count, categories, asked_vs_answered_model, raw_events}
```

Determinism guards: serialize writes to `profile/projects/<slug>/memory/` (mutex/queue) since parallel workers share one slug; alternatively give each worker its own case dir + profile copy (cleaner: per-worker case dirs make slugs differ — acceptable because slug/dirname is *constant within* a comparison set only; prefer one case dir + serialized writes, parallelizing at the vote level of *distinct* chunks… simplest safe scheme: **parallelize across distinct chunks by giving each parallel lane its own case dir AND its own profile copy**; folder names themselves stay out of the memory text either way).

Overlapping/offender dedupe: if adjacent lines both trip and the two-line pair trips harder, merge into one span in the report.

Estimated calls: calibration 2·K + sweep n·K + repair ≈ (6 + 384 + ~30) ≈ **~420 calls** at defaults (n=127, K=3).

**Cost estimate** (tiny fixed prompt, no cache reuse across fresh profiles, mostly ~15–25 KB total input incl. tool schemas & memory chunk, ≤50 output tokens; assume user-subscription rate or blended Opus-class pricing $5–15/M input, $25–75/M output): ≈ **$0.03–0.12 per call worst case**, i.e. **≈ $12–45 total** — bracketing the user's guessed $0.01–0.05/call; comfortably under a Max-plan quota for the day, but add `--max-turns 1` and stagger to respect RPM. Halve by K=2 unanimity logic (trip on 2/2, re-probe singles at K=3 only near threshold).

---

## 6. Risks / gotchas

1. **Stochastic classifier** → false negatives on good chunks. Mitigate with K-vote majority + report *rates*, never booleans; preserve raw `requestId`s for manual follow-up.
2. **Non-monotone composition**: pairs can trip where parts don't (and vice versa); linear+biset-repair design handles; bisect-first designs would corrupt the offense set. Conversely two individually "dirty" lines might mask each other — hence step 3's complement probe.
3. **Session-scope pinning leakage inside a case** — a tripped throwaway stays on the fallback model *for that session only*; irrelevant since sessions are single-turn disposable. But do NOT reuse `--continue`.
4. **Habitual hooks/plugins in the profile** (claude-mem, StopFailure test hooks) can inject extra context unpredictably → ship the temp profile *deliberately empty* of hooks; optionally run one variant WITH the user's real hooks later if deltas matter.
5. **Rate limits / bans**: burst of ~400 short calls; enforce `MAX_PARALLEL≤3`, inter-call jitter 1–3 s, retry-on-429 with backoff (and never count a 429'd turn as a verdict — surface it distinctly: `rate_limit` ≠ `cyber`).
6. **Transcript lag**: hook docs warn transcript writes are async; poll for file quiescence (size stable ×2 @200 ms) before parsing.
7. **Version drift**: field names verified on **2.1.328**; if the main agent runs newer, re-run the schema probe (`jq 'paths(scalars)' | grep -i refus`) on one live refusal before trusting patterns.
8. **N0 failing = environment-level flagging** (e.g., user org/account currently in a bad state, or `--tools ""` oddities). Hard-stop rule protects against publishing garbage attributions.
9. **Memory-loading uncertainty in `-p`** (U2): if sentinel fails, fall back to embedding the chunk through the one injection channel that provably reaches the model — but note `--append-system-prompt` content lands in the *system* block, whereas project memory lands elsewhere; spot-check equivalence with the P1/P0 differential before scanning all 127 units.
10. **Don't ingest dirty chunk text into the operator's main session**: run the scanner itself (this design keeps loop logic outside claude), or at minimum ensure the orchestrating agent reads only *hashes/ranges/results* — the current subagent already absorbed some content; the main implementation agent should avoid printing chunk bodies beyond reporting hashes.

---

## 7. Concrete implementation spec for the main agent

- **Language: Python 3 (stdlib only)** — bash+jq buckles under JSONL polling, mutexes, retries, backoff, and pool management; Python gives `concurrent.futures` + `fcntl` locks in ~250 LOC. Ship `scan_memory.py`; a 10-line `scan_memory.sh` wrapper is optional sugar.
- **File layout:**
  ```
  Claude-Cyber-Classifier-Detection/
    scan_memory.py
    README.md               # usage + interpretation guide
    results/                # gitignored
  ```
- **CLI:**
  ```
  ./scan_memory.py [--memory PATH]  (default the DevSecOps slug path)
                   [--model claude-opus-5-5]      # MUST match user's live model; refuse silently-wrong guesses: read default from `claude config get model` if undecidable
                   [--votes 3] [--max-parallel 2] [--chunk-mode line|section|file]
                   [--probe "hi"] [--keep-work DIR] [--dry-run] [-v]
  ```
- **Module outline:**
  - `slugify(path)` + `discover_slug()` (U2 run-one-read-back)
  - `Profile(workdir)` – builds/cleans `$work/profile`, `cases/chunk-%03d`, writes settings.json, imports auth per §4 order
  - `Runner.run_case(case_dir, probe, model) → CaseResult{transcript_path, stdout_path, exit}`
    (spawn `subprocess.run([claude,--print,...], env={**os.environ, CLAUDE_CONFIG_DIR: …}, cwd=case_dir, timeout=180)`)
  - `harvest(transcript_path) → Verdict{tripped, cats, models_seen, request_ids}` implementing S1>S2>S3 (+ stable-file wait)
  - `Calibration` guard executing N0/P1 with hard-abort semantics
  - `Scanner.scan(units)` thread pool with per-lane case dirs/profile copies; fcntl lock on shared report append
  - `Repair.accused_disambiguation()` per algorithm step 3
  - `report(out_path)` → Markdown table + JSONL sidecar `{unit_id,line_range,sha256[:12],votes,cats,requestIds}`
- **Output sketch:**
  ```
  == Cyber classifier chunk scan (model=claude-opus-5-5, K=3) ==
  Calibration: clean_control 0/3 trips · full_file 3/3 trips (repro 1.00)
  Top offender candidates (by trip rate):
    line 96  sha=ab12cd34ef56  trips 3/3  cyber  req_011C…
    line 33  sha=77aa01fe90bb  trips 2/3  cyber  req_011C…
  Union(accused)=TRIPS · Complement(file∖accused)=CLEAN ✔
  Suggested edit: neutralize lines 96,33 (see results/edit-suggestions.md)
  Validation on edited file: 0/3 trips → SHIP IT
  ```
- **Settings JSON skeleton actually shipped in the temp profile** (adapted to verified reality — note the moved-away-from-StopFailure decision):
  ```json
  {
    "includeCoAuthoredBy": false,
    "env": { "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1" }
  }
  ```
  …plus, *only if* S4 logging is desired during interactive validation later, a separate opt-in snippet dropped into the USER's real `~/.claude/settings.json` (never the scan profile), shaped for the true event contract:
  ```json
  { "hooks": { "StopFailure": [ { "matcher": "*",
      "hooks": [ { "type": "command",
        "command": "jq -r '\"[StopFailure] \\(.error_type) \\(.error)\"' >> /tmp/cc_stopfailures.log" } ] } ] } }
  ```
  (Command reads event JSON on stdin — the original `transcript_path | tail | grep 'api_refusal_category'` pattern is wrong twice over: snake_cased name doesn't exist, and the category never travels through that event's payload.)

**Bottom line for the main agent:** build `scan_memory.py` exactly as specced; detect trips from the run's own transcript (`subtype:"model_refusal_fallback"`, `apiRefusalCategory`, stop-details) — not from StopFailure; isolate via `CLAUDE_CONFIG_DIR` + per-case dirs + pinned classifier-bearing model; always gate on N0/P1 controls; expect ~$12–45 and ~40 min wall-clock for the default full sweep.
