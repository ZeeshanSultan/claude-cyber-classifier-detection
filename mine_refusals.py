#!/usr/bin/env python3
"""
mine_refusals.py — OFFLINE cyber-classifier attribution (zero API calls).

Scans a Claude Code project's transcript JSONLs, attributes every classifier
event (model_refusal_fallback system records + hard stop_reason:"refusal"
assistant rows) to the nearest PRECEDING api-request-blob row (the actual
assembled request), then ranks the lexical ingredients of "tripped" request
compositions against the "clean" baseline of the same project.

Evidence-driven design (validated 2026-11-19):
  * headless replay of MEMORY.md alone did NOT reproduce trips (stochastic,
    low base-rate) — but historical request blobs DO carry the offending mix.
  * tripped/clean token-lift surfaces what actually distinguishes flagged
    compositions — often in-session task attachments rather than memory text.

Usage:
  ./mine_refusals.py [--slug SLUG] [--list] [--min-count N] [--top K]

Output: results/attribution-<ts>.md (+ console summary).
"""

from __future__ import annotations
import argparse, collections, datetime as dt, glob, json, math, os, re

HOME = os.path.expanduser("~")
PROJECTS = os.path.join(HOME, ".claude", "projects")
WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,}")
STOP = set("""the and for with that this from you your are have has was were will
would can could our their they them what when where which these those into over
under than then must need needed should shall using used use file line error
failed failure please make made take came result results response about after
before between during through each other some more most only same such very just
also been being because while there here again once only own too very said says
stopped continue continuing""".split())


def blob_text(rec):
    """Flatten an api-request-blob row to plain text, skipping binary fields."""
    out = []
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("base64", "data") and isinstance(v, str) and len(v) > 400:
                    continue
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)
        elif isinstance(o, str):
            out.append(o)
    walk(rec.get("request", rec))
    return "\n".join(out)


def scan_slug(slug_dir: str):
    tripped, clean = collections.Counter(), collections.Counter()
    n_t = n_c = 0
    refs, first_seen_ctx = [], []
    for f in sorted(glob.glob(os.path.join(slug_dir, "*.jsonl"))):
        try:
            rows = [json.loads(l) for l in open(f) if l.strip()]
        except Exception:
            continue
        marks = {}
        for i, r in enumerate(rows):
            trip = False
            kind = None
            if r.get("type") == "system" and r.get("subtype") == "model_refusal_fallback":
                trip, kind = True, "fallback:" + str(r.get("apiRefusalCategory"))
            m = r.get("message") or {}
            sd = m.get("stop_details") or {}
            if sd.get("type") == "refusal" or m.get("stop_reason") == "refusal":
                trip, kind = True, "hard-refusal:" + str(sd.get("category"))
            if trip:
                for j in range(i - 1, -1, -1):
                    if rows[j].get("type") == "api-request-blob":
                        marks.setdefault(j, []).append((kind, str(r.get("timestamp"))))
                        break
        for i, r in enumerate(rows):
            if r.get("type") != "api-request-blob":
                continue
            txt = blob_text(r)
            toks = {w.lower() for w in WORD.findall(txt)} - STOP
            if i in marks:
                tripped.update(toks); n_t += 1
                refs.append((os.path.basename(f)[:8], i, marks[i]))
                for kind, ts in marks[i]:
                    first_seen_ctx.append((ts, kind, os.path.basename(f)[:8], i))
            else:
                clean.update(toks); n_c += 1
    return tripped, clean, n_t, n_c, refs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slug", default="-Users-zeeshan-Desktop-DevSecOps-Operating-Model-Deployment")
    ap.add_argument("--list", action="store_true", help="list project slugs & exit")
    ap.add_argument("--min-count", type=int, default=2,
                    help="min occurrences in tripped corpus (default 2)")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()

    if args.list:
        for d in sorted(os.listdir(PROJECTS)):
            p = os.path.join(PROJECTS, d)
            if os.path.isdir(p):
                n = len(glob.glob(p + "/*.jsonl"))
                print(f"{n:5d} sessions  {d}")
        return

    slug_dir = os.path.join(PROJECTS, args.slug)
    if not os.path.isdir(slug_dir):
        raise SystemExit(f"no such project dir: {slug_dir}")

    tripped, clean, n_t, n_c, refs = scan_slug(slug_dir)
    print(f"project: {args.slug}")
    print(f"turn-level request blobs: tripped={n_t} clean={n_c}\n")
    if n_t == 0:
        print("No classifier events found in this project. Nothing to attribute.")
        return
    print("event -> attributed turn (transcript, blob-row):")
    for t, i, kinds in refs[:15]:
        print(f"  {t} row{i:>4}: {kinds}")

    scored = []
    for w, c in tripped.items():
        cc = clean.get(w, 0)
        if c < args.min_count:
            continue
        pt, pc = c / max(n_t, 1), cc / max(n_c, 1)
        score = float("inf") if pc == 0 else math.log(pt / pc)
        # confidence: how consistently present among tripped turns
        scored.append((score, c / n_t, w, c, cc))
    scored.sort(reverse=True)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(outdir, exist_ok=True)
    md = os.path.join(outdir, f"attribution-{stamp}.md")

    with open(md, "w") as fh:
        fh.write(f"# Offline refusal attribution — {dt.datetime.now():%Y-%m-%d %H:%M}\n\n")
        fh.write(f"* slug `{args.slug}` · tripped turns {n_t} · clean turns {n_c}\n\n")
        fh.write("| lift | coverage | token | tripped/clean |\n|---|---|---|---|\n")
        for s, cov, w, a, b in scored[:args.top * 2]:
            fs = "+inf" if s == float("inf") else f"{s:+.2f}"
            fh.write(f"| {fs} | {cov:.0%} | `{w}` | {a}/{b} |\n")
        fh.write("\nInterpretation: high-coverage tokens are the recurring ingredients\n"
                 "of flagged request compositions. Check whether each belongs to\n"
                 "MEMORY.md, CLAUDE.md, plugin/MCP listings, or in-session task state.\n"
                 "Neutralize the sources you control (rewrite phrasing, prune plugins,\n"
                 "fresh sessions instead of resuming pinned ones).\n")

    print(f"\nTop discriminators (coverage>=50%, top {args.top}):")
    shown = 0
    for s, cov, w, a, b in scored:
        if cov < 0.5 or shown >= args.top:
            continue
        fs = "+inf" if s == float("inf") else f"{s:+.2f}"
        print(f"  {fs:>6} {cov:>4.0%}  {w:34s} ({a}/{b})")
        shown += 1
    print(f"\nFull report: {md}")


if __name__ == "__main__":
    main()
