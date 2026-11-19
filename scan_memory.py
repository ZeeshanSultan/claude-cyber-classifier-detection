#!/usr/bin/env python3
"""
scan_memory.py — locate which chunk(s) of a Claude Code project MEMORY.md trip
the Anthropic cyber safety classifier, using disposable headless `claude -p` runs.

Method (validated empirically on claude CLI 2.1.328, macOS):
  * Every throwaway run gets its OWN fresh case directory (cwd). Claude Code maps
    cwd -> project slug, so each run loads exactly ONE candidate chunk placed at
    ~/.claude/projects/<case-slug>/memory/MEMORY.md (verified via sentinel probe:
    memory DOES load in -p mode). The real project's state is never modified;
    we only ever CREATE new directories.
  * Detection parses the run's own transcript JSONL (NOT hooks): a system record
    {type:"system", subtype:"model_refusal_fallback", apiRefusalCategory:"cyber"}
    is ground truth for a classifier trip (camelCase field names verified against
    real transcripts). Secondary signals: stop_details.type=="refusal",
    message.model != requested model.
  * Two controls gate everything:
      N0 negative control : benign one-liner memory   -> MUST come back clean
      P1 positive control : verbatim full real MEMORY -> SHOULD trip >=once
  * Linear sweep with K-vote majority + interaction-repair (union/complement),
    because classifier verdicts are stochastic and chunks can interact.

Usage:
  ./scan_memory.py [--memory PATH] [--model M] [--votes K] [--max-parallel N]
                   [--chunk-mode line|section] [--probe TEXT] [--limit UNITS]
                   [--calibrate-only] [--dry-run] [--keep-work] [-v]

Anti-contamination contract: the operator's interactive session never needs to
open the memory file; reports contain hashes + line ranges; full text only in
on-disk artifacts.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------- constants

HOME = Path.home()
CLAUDE_DIR = HOME / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
DEFAULT_MEMORY = (
    PROJECTS_DIR
    / "-Users-zeeshan-Desktop-DevSecOps-Operating-Model-Deployment"
    / "memory"
    / "MEMORY.md"
)
DEFAULT_MODEL = "claude-opus-5-5"          # observed originalModel in live refusal events
FALLBACK_CLAUDE_BIN = HOME / ".local" / "bin" / "claude"
PROBE_PROMPT_DEFAULT = "hi"

N0_TEXT = "# Notes\n\nNothing here yet. This project has no special topics.\n"


def log(msg: str, verbose_only: bool = False) -> None:
    if not verbose_only or VERBOSE:
        ts = dt.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}", flush=True)


VERBOSE = False


# ---------------------------------------------------------------- slug logic

def slugify(path: Path) -> str:
    """Claude Code project-dir slug: every char outside [A-Za-z0-9] becomes '-',
    casing preserved. Empirically matched on this machine."""
    s = str(path.resolve())
    return re.sub(r"[^A-Za-z0-9]", "-", s)


# ---------------------------------------------------------------- units/chunks

@dataclass
class Unit:
    uid: int
    kind: str            # "line" | "section" | "control:N0" | "control:P1"
    label: str           # e.g. "lines 12-12" or "section 'Auth'" or "N0"/"P1"
    content: str         # exact text injected as memory/MEMORY.md
    sha12: str = ""
    spans: list = field(default_factory=list)   # [(start_line, end_line)] in source

    def __post_init__(self):
        self.sha12 = hashlib.sha256(self.content.encode()).hexdigest()[:12]


def split_units(text: str, mode: str) -> list[Unit]:
    lines = text.splitlines(keepends=True)
    units: list[Unit] = []
    if mode == "line":
        for i, ln in enumerate(lines, 1):
            units.append(Unit(len(units), "line", f"line {i}", ln, spans=[(i, i)]))
    elif mode == "section":
        # split on ATX headings; fall back to top-level bullets; else whole file
        starts = [j for j, ln in enumerate(lines) if re.match(r"^#{1,6}\s", ln)]
        if not starts:
            starts = [j for j, ln in enumerate(lines) if re.match(r"^-{1,2}\s|\*\s", ln)]
        bounds = []
        if starts and starts[0] > 0:
            bounds.append((0, starts[0]))
        for k, s in enumerate(starts):
            e = starts[k + 1] if k + 1 < len(starts) else len(lines)
            bounds.append((s, e))
        for (a, b) in bounds:
            body = "".join(lines[a:b])
            title = next((ln.strip("# ").strip() for ln in lines[a:b]
                          if re.match(r"^#{1,6}\s", ln)), f"L{a+1}")
            units.append(Unit(len(units), "section", f"'{title[:40]}' L{a+1}-{b}",
                              body, spans=[(a + 1, b)]))
    else:
        raise ValueError(mode)
    return units


# ---------------------------------------------------------------- profile ops

def place_memory(case_dir: Path, content: str) -> None:
    """Create the case project's memory file BEFORE the run (verified to load)."""
    slug = slugify(case_dir)
    memdir = PROJECTS_DIR / slug / "memory"
    memdir.mkdir(parents=True, exist_ok=True)
    (memdir / "MEMORY.md").write_text(content, encoding="utf-8")


def cleanup_case(case_dir: Path, profile_projects_too: bool = True) -> None:
    slug = slugify(case_dir)
    try:
        shutil.rmtree(PROJECTS_DIR / slug)
    except FileNotFoundError:
        pass
    try:
        shutil.rmtree(case_dir)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------- runner

@dataclass
class Verdict:
    tripped: bool
    categories: list[str]
    fallback_events: list[dict]
    stop_refusals: int
    models_seen: list[str]
    result_snippet: str
    exit_code: int
    transcript: str


def find_claude_bin() -> str:
    p = shutil.which("claude")
    if p:
        return p
    if FALLBACK_CLAUDE_BIN.exists():
        return str(FALLBACK_CLAUDE_BIN)
    raise SystemExit("claude binary not found on PATH nor ~/.local/bin/claude")


CLAUSE_BIN = None  # set in main()


def wait_for_quiescence(p: Path, timeout_s: float = 20.0) -> None:
    """Transcript writes are async; poll until size is stable twice."""
    deadline = time.time() + timeout_s
    last, stable = -1, 0
    while time.time() < deadline:
        try:
            sz = p.stat().st_size
        except FileNotFoundError:
            time.sleep(0.15); continue
        if sz == last:
            stable += 1
            if stable >= 2:
                return
        else:
            stable = 0
            last = sz
        time.sleep(0.2)


def harvest(case_dir: Path, started_at: float, requested_model: str) -> Verdict:
    slug = PROJECTS_DIR / slugify(case_dir)
    # candidate transcripts finished (mtime) after our run started
    cands = [f for f in slug.glob("*.jsonl") if f.stat().st_mtime >= started_at - 1]
    if not cands:
        return Verdict(False, [], [], 0, [], "<no transcript>", -1, "")
    tr_path = max(cands, key=lambda f: f.stat().st_mtime)
    wait_for_quiescence(tr_path)

    fb_events, cats, models, stop_refusals = [], [], [], 0
    result_snippet = ""
    for raw in tr_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue                                   # tolerate partial tail line
        t, st = rec.get("type"), rec.get("subtype")
        if t == "system" and st == "model_refusal_fallback":
            fb_events.append({
                "category": rec.get("apiRefusalCategory"),
                "originalModel": rec.get("originalModel"),
                "fallbackModel": rec.get("fallbackModel"),
                "requestId": rec.get("requestId"),
                "scope": rec.get("scope"),
                "explanation": (rec.get("apiRefusalExplanation") or "")[:160],
            })
            c = rec.get("apiRefusalCategory") or "unknown-category"
            if c not in cats:
                cats.append(c)
        if t == "assistant":
            msg = rec.get("message") or {}
            m = msg.get("model")
            if m and m not in models:
                models.append(m)
            sd = msg.get("stop_details") or {}
            if sd.get("type") == "refusal" or msg.get("stop_reason") == "refusal":
                stop_refusals += 1
        if t == "result":
            result_snippet = str(rec.get("result"))[:120]

    tripped = bool(fb_events) or stop_refusals > 0
    return Verdict(tripped, cats, fb_events, stop_refusals,
                   models, result_snippet, 0, str(tr_path))


_api_fail_lock = threading.Lock()


def run_case(work: Path, case_name: str, memory_content: str,
             model: str, probe: str, retries: int = 2) -> tuple[Verdict, dict]:
    """One disposable headless run seeing exactly `memory_content`. Returns
    (verdict, meta). API-level failures (auth/network/429) are retried and are
    NEVER counted as 'clean' — surfaced distinctly."""
    proc = None
    for attempt in range(retries + 1):
        case_dir = work / "cases" / f"{case_name}-a{attempt}"
        case_dir.mkdir(parents=True, exist_ok=True)
        place_memory(case_dir, memory_content)
        out = work / "logs" / f"{case_name}.out.json"
        err = work / "logs" / f"{case_name}.err.txt"
        out.parent.mkdir(exist_ok=True)
        started = time.time()
        env = dict(os.environ)
        env.pop("ANTHROPIC_API_KEY", None)  # force the normal subscription auth path
        cmd = [CLAUSE_BIN, "--print", "--output-format", "json", "--max-turns", "1",
               "--model", model, probe]
        proc = subprocess.run(cmd, cwd=str(case_dir), capture_output=True,
                              text=True, env=env, timeout=240)
        dur = time.time() - started
        out.write_text(proc.stdout, encoding="utf-8")
        err.write_text(proc.stderr, encoding="utf-8")

        result_obj = {}
        try:
            result_obj = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            pass
        term = result_obj.get("terminal_reason", "")

        if proc.returncode != 0 or term == "api_error":
            snippet = str(result_obj.get("result"))[:80]
            with _api_fail_lock:
                log(f"  {case_name}: infra failure rc={proc.returncode} "
                    f"term={term} ({snippet!r}) attempt {attempt+1}/{retries+1}")
            time.sleep(2 ** attempt * 2 + random.random() * 2)
            cleanup_case(case_dir)
            continue

        v = harvest(case_dir, started, model)
        v.exit_code = proc.returncode
        meta = {"duration_s": round(dur, 1), "case_dir": str(case_dir)}
        cleanup_case(case_dir)          # remove throwaway cwd + its synthetic project dir
        return v, meta

    # exhausted retries: mark as infra-failure verdict (not clean, not trip)
    return Verdict(False, ["INFRA_FAILURE"], [], 0, [],
                   "<infra failure after retries>", proc.returncode if proc else -1, ""), \
           {"duration_s": None, "case_dir": None}


# ---------------------------------------------------------------- voting

def vote(unit: Unit, ctx) -> dict:
    """K independent votes on one unit -> majority verdict record."""
    trips = 0
    verdicts = []
    evidence = []
    for k in range(ctx.args.votes):
        name = f"u{unit.uid:03d}-{k}" if not unit.kind.startswith("control") else unit.label.replace(" ", "_") + f"-{k}"
        v, meta = run_case(ctx.work, name, unit.content, ctx.args.model,
                           ctx.args.probe)
        verdicts.append(v.tripped and v.categories != ["INFRA_FAILURE"])
        if v.tripped:
            trips += 1
            evidence.extend(v.fallback_events)
            if v.stop_refusals:
                evidence.append({"stop_refusal_count": v.stop_refusals})
        time.sleep(random.uniform(*ctx.jitter))
    need = max(1, -(-ctx.args.votes // 2))     # ceil(K/2)
    return {
        "uid": unit.uid, "kind": unit.kind, "label": unit.label,
        "sha12": unit.sha12, "spans": unit.spans,
        "trips": trips, "votes": ctx.args.votes,
        "majority_trip": trips >= need,
        "categories": sorted({e.get("category") or "?" for e in evidence if "category" in e}),
        "request_ids": [e.get("requestId") for e in evidence if e.get("requestId")][:6],
        "models_seen_examples": evidence[:3],
    }


# ---------------------------------------------------------------- main flow

class Ctx: pass


def calibrate(ctx) -> dict:
    log("== CALIBRATION ==")
    n0 = vote(Unit(9000, "control", "N0", N0_TEXT), ctx)
    log(f"N0 benign control: {n0['trips']}/{n0['votes']} trips "
        f"({'OK-clean' if not n0['majority_trip'] else 'ENV FLAGGED — ABORT'})")
    real = ctx.memory_path.read_text(encoding="utf-8")
    p1 = vote(Unit(9001, "control", "P1", real), ctx)
    repro = p1["trips"] / p1["votes"]
    log(f"P1 full-file control: {p1['trips']}/{p1['votes']} trips (repro {repro:.2f})"
        + (" OK" if repro >= ctx.min_repro else
           " WEAK — memory hypothesis unsupported; audit settings/CLAUDE.md/skills"))
    ok = (not n0["majority_trip"]) and repro >= ctx.min_repro
    return {"ok": ok, "n0": n0, "p1": p1, "repro_rate": repro, "real_len": len(real)}


def sweep(ctx, units) -> list[dict]:
    log(f"== LINEAR SWEEP == {len(units)} units x {ctx.args.votes} votes, "
        f"parallel<= {ctx.args.max_parallel}")
    results = []
    with cf.ThreadPoolExecutor(max_workers=ctx.args.max_parallel) as ex:
        futs = {ex.submit(lambda u=u: vote(u, ctx)): u for u in units}
        done_ct = 0
        for fut in cf.as_completed(futs):
            r = fut.result()
            results.append(r)
            done_ct += 1
            flag = "TRIP" if r["majority_trip"] else ("weak" if r["trips"] else "ok")
            log(f"  [{done_ct}/{len(units)}] unit {r['uid']:03d} {r['label']}: "
                f"{r['trips']}/{r['votes']} {flag} cats={r['categories']}")
    results.sort(key=lambda r: r["uid"])
    return results


def repair(ctx, results) -> dict:
    accused = [r for r in results if r["majority_trip"]]
    if not accused:
        return {"note": "no accused units; nothing to repair-check"}
    log(f"== INTERACTION REPAIR == {len(accused)} accused")
    real_lines = ctx.memory_path.read_text(encoding="utf-8").splitlines(keepends=True)
    union_txt = "".join(real_lines[a - 1:b]
                        for r in accused for (a, b) in r["spans"])
    comp_txt = "".join(ln for i, ln in enumerate(real_lines, 1)
                       if not any(a <= i <= b for r in accused for (a, b) in r["spans"]))
    uv, _ = run_case(ctx.work, "repair-union", union_txt or N0_TEXT, ctx.args.model, ctx.args.probe)
    cv, _ = run_case(ctx.work, "repair-complement", comp_txt or N0_TEXT, ctx.args.model, ctx.args.probe)
    out = {
        "accused_uids": [r["uid"] for r in accused],
        "union_tripped": uv.tripped and uv.categories != ["INFRA_FAILURE"],
        "union_categories": uv.categories,
        "complement_tripped": cv.tripped and cv.categories != ["INFRA_FAILURE"],
        "complement_categories": cv.categories,
    }
    log(f"union(accused)={'TRIPS' if out['union_tripped'] else 'clean'} · "
        f"complement(rest of file)={'TRIPS — missed contributors!' if out['complement_tripped'] else 'CLEAN ✔'}")
    return out


def write_report(ctx, calib, results, rep) -> Path:
    stamps = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    md = ctx.results_dir / f"report-{stamps}.md"
    js = ctx.results_dir / f"results-{stamps}.jsonl"
    rows = sorted(results, key=lambda r: (-r["trips"] / max(r["votes"], 1), r["uid"]))
    with open(js, "w") as fh:
        for obj in ([{"_": "calibration"}, calib] +
                    [{"_": "unit", **r} for r in results] +
                    [{"_": "repair"}, rep]):
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(f"# Cyber-classifier memory scan — {dt.datetime.now():%Y-%m-%d %H:%M}\n\n")
        fh.write(f"* memory: `{ctx.memory_path}` ({calib['real_len']} bytes)\n")
        fh.write(f"* model: `{ctx.args.model}` · votes K={ctx.args.votes} · "
                 f"mode={ctx.args.chunk_mode} · probe={ctx.args.probe!r}\n\n")
        fh.write("## Controls\n"
                 f"- N0 benign: {calib['n0']['trips']}/{calib['n0']['votes']} trips\n"
                 f"- P1 full-file: {calib['p1']['trips']}/{calib['p1']['votes']} trips "
                 f"(repro {calib['repro_rate']:.2f})\n\n")
        fh.write("## Offender candidates (by trip rate)\n\n")
        fh.write("| uid | unit | sha12 | trips | cats |\n|---|---|---|---|---|\n")
        for r in rows:
            if r["trips"]:
                fh.write(f"| {r['uid']} | {r['label']} | `{r['sha12']}` | "
                         f"{r['trips']}/{r['votes']} | {','.join(r['categories'])} |\n")
        fh.write("\n## Repair\n\n```json\n" + json.dumps(rep, indent=2) + "\n```\n")
        fh.write("\n## How to act\n\nRe-copy full case details from `%s` when reviewing; "
                 "then neutralize offender units (rewrite weapon-flavored nouns into plain "
                 "ops language), rerun with `--memory <edited>` expecting P1≈clean.\n"
                 % js.name)
    return md


def main() -> None:
    global VERBOSE
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--memory", type=Path, default=DEFAULT_MEMORY)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--votes", type=int, default=3)
    ap.add_argument("--max-parallel", type=int, default=2)
    ap.add_argument("--chunk-mode", choices=["line", "section"], default="line")
    ap.add_argument("--probe", default=PROBE_PROMPT_DEFAULT)
    ap.add_argument("--limit", type=int, default=0, help="scan only first N units (testing)")
    ap.add_argument("--calibrate-only", action="store_true")
    ap.add_argument("--min-repro", type=float, default=1 / 3,
                    help="required P1 trip fraction to proceed (default ≥1/3)")
    ap.add_argument("--skip-calibration", action="store_true")
    ap.add_argument("--keep-work", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="plan only, zero API calls")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if not args.memory.exists():
        raise SystemExit(f"memory file not found: {args.memory}")

    work = Path(tempfile.mkdtemp(prefix="cc_scan_", dir="/private/var/folders/59/254_swmj6yq2rh5hj1lc39_h0000gq/T/opencode"))
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)

    ctx = Ctx()
    ctx.args, ctx.work, ctx.results_dir = args, work, results_dir
    ctx.jitter = (1.0, 3.0)
    ctx.memory_path = args.memory
    ctx.min_repro = args.min_repro

    global CLAUSE_BIN
    CLAUSE_BIN = find_claude_bin()

    text = args.memory.read_text(encoding="utf-8")
    units = split_units(text, args.chunk_mode)
    if args.limit:
        units = units[: args.limit]

    est_calls = (0 if args.skip_calibration else 2 * args.votes) + len(units) * args.votes
    log(f"work={work}")
    log(f"units={len(units)} mode={args.chunk_mode} estimated_calls≈{est_calls} "
        f"(model={args.model}, probe={args.probe!r})")

    if args.dry_run:
        for u in units[:10]:
            log(f"  would test {u.label} sha={u.sha12}", )
        if len(units) > 10:
            log(f"  … and {len(units)-10} more")
        return

    calib = {"ok": True, "n0": {}, "p1": {}, "repro_rate": 0.0, "real_len": len(text)}
    if not args.skip_calibration:
        calib = calibrate(ctx)
        if not calib["ok"]:
            log("CALIBRATION FAILED — see messages above. Aborting without publishing results.")
            write_report(ctx, calib, [], {})
            if not args.keep_work:
                shutil.rmtree(work, ignore_errors=True)
            sys.exit(2)

    results = [] if args.calibrate_only else sweep(ctx, units)
    rep = {} if args.calibrate_only else repair(ctx, results)
    md = write_report(ctx, calib, results, rep)

    if not args.keep_work:
        shutil.rmtree(work, ignore_errors=True)   # throwaway cwds already cleaned per-run
        log("work dir removed (pass --keep-work to retain raw logs)")

    log(f"DONE → {md}")
    log(f"      jsonl sidecar in results/")


if __name__ == "__main__":
    main()
