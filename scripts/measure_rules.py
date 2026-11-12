"""Hold a ruleset against real names: what matches, what is a false alarm?

Without measuring, every claim about false alarms is a guess. This script takes a
file of names, scores them against a ruleset and says per name whether and why it
crosses the threshold.

    python scripts/measure_rules.py rules/examples/financial-products.yaml names.txt
    python scripts/measure_rules.py rules/examples/financial-products.yaml --db   # from the database

Never goes to the network: phase 1, without a certificate, without enrichment.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ctwatchtower.normalize.names import normalize  # noqa: E402
from ctwatchtower.rules.loader import RuleStore  # noqa: E402
from ctwatchtower.scoring.engine import score_candidate  # noqa: E402


def load_one(path: Path):
    store = RuleStore(path.parent)
    for rs in store.rulesets:
        if rs.tenant.id == path.stem:
            return rs
    raise SystemExit(f"No ruleset with the id {path.stem!r} in {path.parent}")


def names_from_db(db: Path) -> list[str]:
    conn = sqlite3.connect(db)
    try:
        return [r[0] for r in conn.execute("SELECT DISTINCT domain FROM findings")]
    finally:
        conn.close()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("ruleset", type=Path)
    p.add_argument("names", type=Path, nargs="?")
    p.add_argument("--db", type=Path, help="names from a database instead of a file")
    p.add_argument("--from", dest="from_", type=float, default=None,
                   help="threshold (default: the ruleset's info)")
    p.add_argument("--quiet", action="store_true", help="the summary only")
    args = p.parse_args()

    rs = load_one(args.ruleset)
    limit = args.from_ if args.from_ is not None else rs.thresholds.info

    if args.db:
        names = names_from_db(args.db)
    elif args.names:
        names = [n.strip() for n in args.names.read_text(encoding="utf-8").splitlines()
                 if n.strip() and not n.startswith("#")]
    else:
        names = [n.strip() for n in sys.stdin if n.strip()]

    hits = []
    for raw in names:
        cand = normalize(raw)
        if cand is None:
            continue
        r = score_candidate(rs, cand)
        if r.score >= limit:
            hits.append((r.score, r.severity, raw, [m for m in r.matched][:4]))

    hits.sort(key=lambda t: -t[0])
    if not args.quiet:
        for score, sev, name, why in hits:
            print(f"{score:6.1f} {sev:<8} {name[:62]:<62} {' '.join(why)[:70]}")

    print(f"\n{len(hits)} of {len(names)} names from {limit:g} "
          f"({len(hits) / max(len(names), 1):.1%}) - ruleset {rs.tenant.id}")


if __name__ == "__main__":
    main()
