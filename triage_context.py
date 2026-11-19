#!/usr/bin/env python3
"""
triage_context.py — unified cyber-classifier context triage (offline, zero API calls).

Answers: "WHY do my innocuous prompts get cyber-flagged?" for any scope:

  --scope session  <slug> [sessionIdPrefix]   one session, turn-by-turn anatomy
  --scope project  <slug>                     whole project: events + injectors
  --scope all                                 every project ranked by pain

Pipeline (methodology proven 2026-11-19 against a real claude-mem pollution case):
  1. HARVEST   classifier events (model_refusal_fallback / hard refusals) and
               attribute each to its actual assembled request (api-request-blob).
  2. INVENTORY auto-detect context injectors: memory-management plugins, MCP
               servers, and hooks (SessionStart / UserPromptSubmit / PreToolUse…)
               from ~/.claude/settings.json + project settings + marketplaces.
  3. ATTRIBUTE measure each injector's payload share and security-vocabulary
               density inside flagged requests vs clean baseline.
  4. ACQUIT    check MEMORY.md / CLAUDE.md / memory-topic files against the
               discriminator tokens (usually innocent — verify, don't assume).
  5. VERDICT   deterministic culprit if one injector dominates flagged-request
               payload mass; otherwise INCONCLUSIVE → invoke the
               `cyber-context-triage` skill for manual forensic procedure.

Usage:
  ./triage_context.py --list
  ./triage_context.py --scope project -Users-zeeshan-Desktop-DevSecOps-Operating-Model-Deployment
  ./triage_context.py --scope session <slug> af631de3
  ./triage_context.py --scope all --top 15
"""

from __future__ import annotations
import argparse, collections, datetime as dt, glob, json, os, re, sys

HOME = os.path.expanduser("~")
PROJ_ROOT = os.path.join(HOME, ".claude", "projects")
SETTINGS = os.path.join(HOME, ".claude", "settings.json")
DOTCLAUDE_JSON = os.path.join(HOME, ".claude.json")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mine_refusals import blob_text, WORD, STOP          # shared, tested parsing

SEC_VOCAB = [
    "bypass", "webauthn", "oauth", "threat-model", "threat model", "pentest",
    "semgrep", "trivy", "burp", "ssrf", "xxe", "xsrf", "csrf", "xss", "sqli",
    "sql injection", "path traversal", "privilege escalation", "exploit",
    "otp", "mfa", "2fa", " credential", "payload", "ransom", "malware",
    "c2 server", "shellcode", "keylogger", "recon", "exfiltrat", "token theft",
]

# Fingerprints of KNOWN memory/context managers (extend freely).
KNOWN_INJECTORS = {
    "claude-mem": {"kind": "plugin", "markers": ["claude-mem", "work state", "claudemem"]},
    "cmem":       {"kind": "plugin", "markers": ["cmem-", "claude-mem"]},
    "supermemory":{"kind": "plugin", "markers": ["supermemory"]},
    "gbrain":     {"kind": "plugin", "markers": ["gbrain"]},
    "codebase-memory-mcp": {"kind": "mcp", "markers": ["codebase-memory-mcp", "search_graph"]},
}
MEM_NAME_RE = re.compile(r"(mem|recall|memento|remember)", re.I)


# --------------------------------------------------------------- inventory

def discover_injectors(project_cwd: str | None) -> list[dict]:
    """Return [{name, kind, source_file, detail}] of anything that may push
    content into every request: plugins, MCP servers, hooks."""
    out: list[dict] = []

    def add(name, kind, src, detail=""):
        if name:
            out.append({"name": name, "kind": kind, "source": src, "detail": detail})

    # 1. enabled plugins
    try:
        s = json.load(open(SETTINGS))
        for pname in (s.get("enabledPlugins") or {}):
            base = pname.split("@")[0]
            kind = "plugin"
            for kn, kv in KNOWN_INJECTORS.items():
                if kn.lower() == base.lower():
                    kind = kv["kind"]
            add(pname, kind, SETTINGS)
            # hooks inside settings point at script basenames too
        # 2. hooks of every event that can inject into context
        for ev in ("SessionStart", "UserPromptSubmit", "PreToolUse", "Stop",
                   "PostToolUse", "SessionEnd", "PermissionRequest", "Notification"):
            for blk in (s.get("hooks", {}).get(ev) or []):
                for hk in (blk.get("hooks") or []):
                    cmd = str(hk.get("command", ""))
                    base = os.path.basename(cmd.strip("\"' ")) or cmd[:40]
                    label = f"{ev}:{base}"
                    d = "injector?" if MEM_NAME_RE.search(base) or ev == "SessionStart" \
                        else "context-hook?"
                    add(label, "hook", SETTINGS, cmd[:100])
    except FileNotFoundError:
        pass

    # 3. MCP servers anywhere in ~/.claude.json (incl. per-project)
    try:
        raw = json.load(open(DOTCLAUDE_JSON))

        def walk(o, proj=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k == "mcpServers" and isinstance(v, dict):
                        for mn in v:
                            add(f"mcp:{mn}", "mcp", DOTCLAUDE_JSON, proj)
                    elif k != "mcpServers":
                        walk(v, proj or "")
        walk(raw)
    except Exception:
        pass

    # 4. project-local settings (may override/add hooks)
    if project_cwd:
        for cand in (os.path.join(project_cwd, ".claude", "settings.json"),
                     os.path.join(project_cwd, ".claude", "settings.local.json"),
                     os.path.join(project_cwd, ".mcp.json")):
            try:
                ps = json.load(open(cand))
                for ev, blocks in (ps.get("hooks") or {}).items():
                    for blk in (blocks or []):
                        for hk in (blk.get("hooks") or []):
                            cmd = str(hk.get("command", ""))
                            add(f"{ev}:{os.path.basename(cmd)}", "hook", cand, cmd[:100])
                if isinstance(ps.get("mcpServers"), dict):
                    for mn in ps["mcpServers"]:
                        add(f"mcp:{mn}", "mcp", cand)
            except (FileNotFoundError, json.JSONDecodeError):
                continue
    return out


def identify_known(injectors):
    """Tag inventory entries matching KNOWN_INJECTORS signatures."""
    tagged = []
    for inj in injectors:
        sig = None
        for kn, kv in KNOWN_INJECTORS.items():
            if kn.lower() in inj["name"].lower():
                sig = {"known": kn, "markers": kv["markers"]}
                break
        inj["sig"] = sig
        tagged.append(inj)
    return tagged


# --------------------------------------------------------------- transcripts

def session_rows(slug_dir: str, sid_prefix: str | None):
    """Yield (sid, rows) for matching transcripts, newest first."""
    files = sorted(glob.glob(os.path.join(slug_dir, "*.jsonl")),
                   key=os.path.getmtime, reverse=True)
    for f in files:
        sid = os.path.basename(f)[:8]
        if sid_prefix and not sid.startswith(sid_prefix):
            continue
        try:
            yield sid, [json.loads(l) for l in open(f) if l.strip()]
        except Exception:
            continue


def refusal_marks(rows):
    """row-index -> kinds for any classifier-event row, attributed later to the
    nearest preceding api-request-blob."""
    marks = {}
    for i, r in enumerate(rows):
        t, st = r.get("type"), r.get("subtype")
        kinds = []
        if t == "system" and st == "model_refusal_fallback":
            kinds.append("fallback:" + str(r.get("apiRefusalCategory")))
        m = r.get("message") or {}
        sd = m.get("stop_details") or {}
        if sd.get("type") == "refusal" or m.get("stop_reason") == "refusal":
            kinds.append("hard-refusal:" + str(sd.get("category")))
        if kinds:
            for j in range(i - 1, -1, -1):
                if rows[j].get("type") == "api-request-blob":
                    marks.setdefault(j, []).append((str(r.get("timestamp")), kinds))
                    break
    return marks


def cwds_of(rows):
    for r in rows:
        if r.get("cwd"):
            return r["cwd"]
    return None


def sec_density(text: str) -> tuple[int, dict[str, int]]:
    low = text.lower()
    per = {}
    total = 0
    for tok in SEC_VOCAB:
        c = low.count(tok)
        if c:
            per[tok] = c
            total += c
    return total, per


def inject_share(blob_rows, injectors) -> dict[str, int]:
    """For each injector: number of REQUESTS whose text contains any of its
    markers (presence-based, immune to request-size skew)."""
    hits: dict[str, int] = collections.Counter()
    for rec in blob_rows:
        t = blob_text(rec)
        low = t.lower()
        for inj in injectors:
            mk = inj.get("sig", {}).get("markers") if inj.get("sig") else [inj["name"].split(":")[-1]]
            for m in mk or []:
                if len(m) >= 4 and m.lower() in low:
                    hits[inj["name"]] += 1
                    break
    return dict(hits)


# --------------------------------------------------------------- scopes

def scope_session(args):
    slug_dir = os.path.join(PROJ_ROOT, args.slug)
    hits = {}
    for sid, rows in session_rows(slug_dir, args.session_id):
        marks = refusal_marks(rows)
        if marks:
            hits[sid] = (rows, marks)
    if not hits:
        print("No classifier events in matching sessions. Nothing to triage.")
        return
    inj = identify_known(discover_injectors(cwds_of(next(iter(hits.values()))[0])))
    for sid, (rows, marks) in hits.items():
        print(f"\n=== SESSION {sid} — anatomy ===")
        blobs = [(i, r) for i, r in enumerate(rows) if r.get("type") == "api-request-blob"]
        first = True
        prev_kb = 0
        for bi, (i, r) in enumerate(blobs):
            t = blob_text(r)
            kb = len(t) // 1024
            dens, per = sec_density(t)
            tag = ""
            if i in marks:
                tag = f" <<< FLAGGED {marks[i]}"
            growth = "" if first else f" (+{kb - prev_kb})"
            print(f"  turn {bi}: {kb:>5}KB{growth} · secvocab={dens}{tag}")
            if i in marks and first is not None and kb > 30:
                _print_block_anatomy(t)
                first = False
            prev_kb = kb
        sh = inject_share([r for _, r in blobs], inj)
        print("  injector marker-hits:", dict(sorted(sh.items(), key=lambda x: -x[1])[:8]))


def _print_block_anatomy(t: str):
    """Locate the giant injected text block(s) and describe composition."""
    # biggest single text field
    best = ""
    def wnode(o):
        nonlocal best
        if isinstance(o, dict):
            for v in o.values():
                wnode(v)
        elif isinstance(o, list):
            for x in o:
                wnode(x)
        elif isinstance(o, str) and len(o) > len(best):
            best = o
    wnode(t)
    if len(best) < 4096:
        return
    heads = [m.group(0)[:60] for m in re.finditer(r"^#{1,2} [^\n]{3,60}$", best, re.M)]
    d, per = sec_density(best)
    print(f"    └─ largest injected block: {len(best)//1024}KB · secvocab={d}")
    for h in heads[:14]:
        print("         |", h)


def _load_all_events(slug_dir):
    """(sid, rows, marks) triples for sessions having >=1 event."""
    for sid, rows in session_rows(slug_dir, None):
        marks = refusal_marks(rows)
        if marks:
            yield sid, rows, marks


def scope_project(args):
    slug_dir = os.path.join(PROJ_ROOT, args.slug)
    events = list(_load_all_events(slug_dir))
    if not events:
        print(f"No classifier events ever recorded for `{args.slug}`. Clean ✅")
        return
    print(f"project `{args.slug}`: {len(events)} session(s) with events\n")
    inj = identify_known(discover_injectors(cwds_of(events[0][1])))

    flagged_blobs, clean_blobs = [], []
    for sid, rows, marks in events:
        for i, r in enumerate(rows):
            if r.get("type") != "api-request-blob":
                continue
            (flagged_blobs if i in marks else clean_blobs).append(r)

    # Injector share among flagged first-turns
    sh_flagged = inject_share(flagged_blobs, inj)
    sh_clean = inject_share(clean_blobs, inj)
    fl_dens = sum(sec_density(blob_text(r))[0] for r in flagged_blobs) / max(len(flagged_blobs), 1)
    cl_dens = sum(sec_density(blob_text(r))[0] for r in clean_blobs) / max(len(clean_blobs), 1)

    print(f"avg security-vocab density: flagged-requests {fl_dens:.0f} vs clean {cl_dens:.0f}\n")

    culprit = None
    if fl_dens >= 4 * cl_dens and fl_dens > 20:
        culprit = _provenance_analysis(events, inj)

    print("Injector involvement (marker-hit counts, flagged vs clean turns):")
    for name, cf in sorted(sh_flagged.items(), key=lambda x: -x[1]):
        cc = sh_clean.get(name, 0)
        star = " ⭐ known memory-manager" if any(
            i["name"] == name and i.get("sig") for i in inj) else ""
        print(f"  {name:38s} in {cf}/{len(flagged_blobs)} flagged vs {cc}/{len(clean_blobs)} clean{star}")

    if culprit:
        print("\n════════ VERDICT ════════")
        print(f"DETERMINISTIC CULPRIT: {culprit}")
        cfg = next((i for i in inj if culprit.lower() in i["name"].lower()), None)
        if cfg:
            print(f"  kind={cfg['kind']} · configured in {cfg['source']}")
        print("\nRecommended action:")
        print("  1. remove/disable that plugin & prune its stored digests (README §remediation)")
        print("  2. open a FRESH session and probe 'hi' → expect no fallback banner")
        print("  3. re-run this tool later; expect zero new events")
    else:
        print("\n════════ VERDICT ════════")
        print("INCONCLUSIVE — see content-provenance clues above.")
        print("Next step: invoke the `cyber-context-triage` skill (manual forensic")
        print("procedure): isolate chunks, replay headlessly, vote n-of-m.")


def _flagged_giant_blocks(events, top_n=3):
    """Largest text blocks from flagged turns across sessions."""
    out = []
    for sid, rows, marks in events:
        local = []
        for i, r in enumerate(rows):
            if r.get("type") == "api-request-blob" and i in marks:
                t = blob_text(r)
                local.append(t)
        if local:
            out.append(max(local, key=len))
    return sorted(out, key=len, reverse=True)[:top_n]


def _provenance_analysis(events, inj) -> str | None:
    """Find WHERE flagged requests' security vocabulary lives and WHICH
    registered injector that region belongs to (heading-based matching)."""
    print("\nContent provenance inside flagged mega-requests:")
    votes: dict[str, int] = collections.Counter()
    seen_any_heading = False
    for big in _flagged_giant_blocks(events):
        low = big.lower()
        # split into heading-delimited sections; weight secvocab per section
        heads = [(m.start(), m.group(1)) for m in re.finditer(r"^#{1,3} ([^\n]{3,70})$", big, re.M)]
        if not heads:
            continue
        seen_any_heading = True
        bounds = [o for o, _ in heads] + [len(big)]
        scored = []
        for k in range(len(heads)):
            seg = big[bounds[k]:bounds[k + 1]]
            d, _ = sec_density(seg)
            scored.append((d, heads[k][1]))
        scored.sort(reverse=True)
        for d, h in scored[:4]:
            if d < 5:
                continue
            match = None
            hl = h.lower()
            for kn, kv in KNOWN_INJECTORS.items():
                for mk in kv["markers"]:
                    if mk in hl or kn.split("-")[0] in hl:
                        match = kn
                        break
                if match:
                    break
            if not match:
                if MEM_NAME_RE.search(hl):
                    match = h.strip()[:40]
            tag = f" → Injector: {match}" if match else ""
            print(f"  [{d:>4} hits] “{h}”{tag}")
            if match:
                votes[match] += d
    if votes:
        best, sc = votes.most_common(1)[0]
        total = sum(votes.values())
        if sc / total >= 0.6:
            return best
    elif seen_any_heading:
        pass
    return None


def scope_all(args):
    stats = []
    for slug_dir in sorted(glob.glob(os.path.join(PROJ_ROOT, "*"))):
        if not os.path.isdir(slug_dir):
            continue
        n_ev = 0
        n_sess = 0
        latest = ""
        for f in glob.glob(os.path.join(slug_dir, "*.jsonl")):
            try:
                for line in open(f):
                    if '"model_refusal_fallback"' not in line and '"stop_reason":"refusal"' not in line:
                        continue
                    r = json.loads(line)
                    m = r.get("message") or {}
                    trip = (r.get("type") == "system" and r.get("subtype") == "model_refusal_fallback") \
                           or m.get("stop_reason") == "refusal" \
                           or ((m.get("stop_details") or {}).get("type") == "refusal")
                    if trip:
                        ts = str(r.get("timestamp"))
                        n_ev += 1
                        latest = max(latest, ts)
                        n_sess = 1
            except Exception:
                continue
        if n_ev:
            stats.append((n_ev, os.path.basename(slug_dir), latest))
    stats.sort(reverse=True)
    print(f"{'events':>7}  {'last seen':16s}  project")
    for n, s, ts in stats[:args.top]:
        print(f"{n:>7}  {ts[:16]:16s}  {s}")


# --------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", choices=["session", "project", "all"], required=True)
    ap.add_argument("--slug", help="project slug (-Users-... )")
    ap.add_argument("--session-id", help="8-char session id prefix (for --scope session)")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for d in sorted(os.listdir(PROJ_ROOT)):
            p = os.path.join(PROJ_ROOT, d)
            if os.path.isdir(p):
                print(d)
        return

    if args.scope == "all":
        scope_all(args)
        return
    if not args.slug:
        raise SystemExit("--slug required for this scope")
    if args.scope == "session":
        if not args.session_id:
            raise SystemExit("--session-id required (8-char prefix; see events listed by project scope)")
        scope_session(args)
    else:
        scope_project(args)


if __name__ == "__main__":
    main()
