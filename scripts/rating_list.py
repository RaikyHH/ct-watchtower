"""Build a list for rating by hand, out of hits and misses.

A ruleset cannot improve itself; somebody has to say what is an attack and what is
not. This script picks the names where a decision helps most:

  A  a high score. Is that right, or is it a false alarm?
  B  close to the threshold. This is where the line should be decided.
  C  missed. Should that have stood out?

What gets written is a TSV with an empty `verdict` column. Enter one of `attack`,
`benign`, `unclear`.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ctwatchtower.normalize.names import normalize  # noqa: E402


def family(name: str) -> str:
    """Names of the same registrable domain are one decision, not ten.

    `www.www.gls.lrit.us.cc` and `www.gls.lrit.us.cc` are no different for the
    rating. Whoever holds one of them to be benign holds the other one to be too.
    """
    cand = normalize(name)
    return cand.registrable if cand else name


def read(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hits", type=Path, default=Path("hits.tsv"))
    ap.add_argument("--missed", type=Path, default=Path("missed.tsv"))
    ap.add_argument("--out", type=Path, default=Path("rating.tsv"))
    ap.add_argument("--per-group", type=int, default=20)
    ap.add_argument("--seed", type=int, default=20261023)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    hits = read(args.hits)
    for t in hits:
        t["score"] = float(t["score"])

    # A: the highest per tenant. That is where a false alarm hurts most.
    per_tenant: dict[str, list[dict]] = defaultdict(list)
    for t in hits:
        per_tenant[t["tenant"]].append(t)
    high = []
    for _tenant, rows in sorted(per_tenant.items()):
        rows.sort(key=lambda r: -r["score"])
        high.extend(rows[: max(3, args.per_group // max(len(per_tenant), 1))])

    # B: the edge. Names within ±6 points of the ruleset's warning threshold.
    edge = [t for t in hits if 31 <= t["score"] <= 43]
    rng.shuffle(edge)
    edge = edge[: args.per_group]

    # C: the missed ones that scored highest, where the least is missing.
    missed = read(args.missed)
    missed.sort(key=lambda r: -float(r["best_score"]))
    gaps = missed[: args.per_group]

    seen: set[str] = set()
    families: set[str] = set()
    with args.out.open("w", encoding="utf-8", newline="") as f:
        s = csv.writer(f, delimiter="\t", lineterminator="\n")
        s.writerow(["group", "verdict", "name", "score", "tenant", "why_shown"])
        for group, rows, why in (
            ("A scored high", high, "Is the high score right?"),
            ("B at the threshold", edge, "Does this belong above or below the line?"),
            ("C missed", gaps, "Should this have stood out?"),
        ):
            for r in rows:
                name = r.get("name", "")
                if not name or name in seen:
                    continue
                fam = family(name)
                if fam in families:
                    continue
                seen.add(name)
                families.add(fam)
                s.writerow([group, "", name,
                            r.get("score", r.get("best_score", "")),
                            r.get("tenant", "-"), why])
    print(f"{len(seen)} names -> {args.out}")


if __name__ == "__main__":
    main()
