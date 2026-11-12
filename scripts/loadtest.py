"""Load test (§15.5): a hostname sample through every stage separately.

    python scripts/loadtest.py                       # newest sample, example rulesets
    python scripts/loadtest.py --rules broad         # a broad demo set (amazon, microsoft, ...)
    python scripts/loadtest.py --sample data/samples/x.tsv --limit 50000

The sample: one line per certificate, names separated by tabs
(`scripts/record_stream.py`). Without a sample, `--synthetic N` makes names up. For
CI, not for statements about the real stream. Stages: parse (JSON plus the certificate
dedupe as in the ingest), normalise, prefilter, score (all tenants per candidate, as
`Pipeline.process` does), DB write.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
import tempfile
import time
from pathlib import Path

from ctwatchtower import db
from ctwatchtower.config import REPO_ROOT
from ctwatchtower.ingest.certstream import parse_message
from ctwatchtower.ingest.dedupe import TTLSet
from ctwatchtower.normalize.names import normalize
from ctwatchtower.normalize.prefilter import build_from_rulesets
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RULES_DIR, load_ruleset, load_rulesets
from ctwatchtower.scoring.engine import score_candidate

# Deliberately broad: big brands as anchors, every match kind on. It shows what a high
# pass ratio costs. Lives in the temp directory only, never under `rules/`.
BROAD = """
apiVersion: ctwatchtower/v2
kind: RuleSet
includes: [common/lures_en.yaml, common/tlds_highrisk.yaml]
tenant: {{ id: broad-demo-{i}, name: "Broad demo set {i}" }}
anchors:
  - terms: [paylio, kavano, stellax, vantabank, northvault, cardex, vendora, oria,
            korvex, orbex, payro, zelo, vexa, velton, veltondesk, zentara]
    weight: 30
    match:
      exact: true
      fuzzy: {{ enabled: true, max_distance: 2 }}
      homoglyph: true
      permutations: {{ enabled: true }}
"""


def load_sample(path: Path | None, limit: int, synthetic: int) -> list[list[str]]:
    if synthetic:
        rnd = random.Random(1)
        words = ["login", "secure", "shop", "mail", "api", "cdn", "app", "paypa1", "amazon"]
        out = []
        for _ in range(synthetic):
            label = "".join(rnd.choices(string.ascii_lowercase + string.digits, k=rnd.randint(4, 14)))
            if rnd.random() < 0.05:
                label = f"{rnd.choice(words)}-{label}"
            out.append([f"{label}.{rnd.choice(['com', 'de', 'top', 'xyz', 'co.uk', 'net'])}"])
        return out
    if path is None:
        samples = sorted((REPO_ROOT / "data" / "samples").glob("*.tsv"))
        if not samples:
            sys.exit("No sample under data/samples/ - run scripts/record_stream.py")
        path = samples[-1]
    certs, total = [], 0
    for line in path.read_text(encoding="utf-8").splitlines():
        names = [n for n in line.split("\t") if n]
        if names:
            certs.append(names)
            total += len(names)
            if limit and total >= limit:
                break
    return certs


def rulesets_for(kind: str, tmp: Path) -> list:
    if kind == "examples":
        return [load_ruleset(p, RULES_DIR) for p in sorted((RULES_DIR / "examples").glob("*.yaml"))]
    # The broad set: two tenants, so the per-tenant loop becomes visible.
    (tmp / "common").mkdir()
    for f in (RULES_DIR / "common").glob("*.yaml"):
        (tmp / "common" / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    for i in (1, 2):
        (tmp / f"broad-{i}.yaml").write_text(BROAD.format(i=i), encoding="utf-8")
    return load_rulesets(tmp)


class _Store:
    def __init__(self, rulesets: list) -> None:
        self.rulesets = rulesets


def run(certs: list[list[str]], rulesets: list, tmp: Path) -> dict:
    names = [n for c in certs for n in c]
    timings: dict[str, float] = {}

    messages = [json.dumps({"message_type": "dns_entries", "data": c}) for c in certs]
    seen = TTLSet(21_600)
    t = time.perf_counter()
    for m in messages:
        cert = parse_message(m)
        seen.add(cert.sha256)
    timings["parse+dedupe"] = time.perf_counter() - t

    t = time.perf_counter()
    cands = []
    for c in certs:  # as Pipeline.process does: the same candidate once per certificate
        uniq = {cand.name: cand for cand in map(normalize, c) if cand is not None}
        cands.extend(uniq.values())
    timings["normalize"] = time.perf_counter() - t

    pf = build_from_rulesets(rulesets)
    t = time.perf_counter()
    passed = [(c, pf.tenants_for(h)) for c in cands if (h := pf.hits(c))]
    timings["prefilter"] = time.perf_counter() - t

    t = time.perf_counter()
    scored = [
        (rs, c, score_candidate(rs, c, None))
        for c, wanted in passed
        for rs in rulesets
        if wanted is None or rs.tenant.id in wanted
    ]
    timings["score"] = time.perf_counter() - t
    hits = [(rs, c, r) for rs, c, r in scored if r.severity is not None]

    conn = db.connect(tmp / "load.sqlite3")
    db.sync_tenants(conn, rulesets)
    ctx = parse_message(messages[0])
    t = time.perf_counter()
    for rs, c, r in hits:
        db.upsert_finding(conn, rs.tenant.id, c, ctx, score=r.score, severity=r.severity,
                          explanation=r.to_dict(), related_names=[])
    timings["db-write"] = time.perf_counter() - t
    conn.close()

    # End to end along the same path as the worker thread, pipeline overhead included.
    pipe = Pipeline(db.connect(tmp / "e2e.sqlite3"), _Store(rulesets), url="ws://127.0.0.1:1")
    parsed = [parse_message(m) for m in messages]
    t = time.perf_counter()
    for cert in parsed:
        pipe.process(cert)
    e2e = time.perf_counter() - t
    pipe.conn.close()

    return {
        "certs": len(certs), "names": len(names), "valid": len(cands), "passed": len(passed),
        "pass_ratio": pf.pass_ratio, "scored": len(scored), "findings": len(hits),
        "timings": timings, "e2e": e2e,
    }


def report(label: str, r: dict) -> None:
    total = sum(r["timings"].values())
    print(f"\n## {label}: {r['certs']} certificates, {r['names']} names, {r['valid']} valid")
    print(f"prefilter pass {r['pass_ratio']:.2%} ({r['passed']}) · "
          f"scorings {r['scored']} · findings {r['findings']}")
    print(f"| {'stage':14s} | {'seconds':>8s} | {'names/s':>10s} | {'share':>6s} |")
    print(f"|{'-' * 16}|{'-' * 10}:|{'-' * 12}:|{'-' * 8}:|")
    for stage, sec in r["timings"].items():
        print(f"| {stage:14s} | {sec:8.2f} | {r['names'] / sec:10.0f} | {sec / total:6.1%} |")
    print(f"| {'total':14s} | {total:8.2f} | {r['names'] / total:10.0f} | {'100%':>6s} |")
    print(f"end to end (Pipeline.process): {r['e2e']:.2f} s -> "
          f"{r['names'] / r['e2e']:.0f} names/s, {r['certs'] / r['e2e']:.0f} certificates/s")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=Path)
    ap.add_argument("--limit", type=int, default=0, help="at most this many names")
    ap.add_argument("--synthetic", type=int, default=0)
    ap.add_argument("--rules", choices=["examples", "broad", "both"], default="both")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")  # the Windows console sits on cp1252

    certs = load_sample(args.sample, args.limit, args.synthetic)
    for kind in (["examples", "broad"] if args.rules == "both" else [args.rules]):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rulesets = rulesets_for(kind, tmp)
            report(f"rulesets: {kind} ({len(rulesets)} tenants)", run(certs, rulesets, tmp))


if __name__ == "__main__":
    main()
