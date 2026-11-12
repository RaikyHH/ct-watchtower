"""What the rules miss: brand-like names that stayed below the threshold.

The other direction from `analyse_stream.py`. That one shows what was hit, this one
what looks like phishing but set nothing off. You need both: a ruleset without false
alarms that finds nothing is not a good ruleset.

The search is coarse and deliberately generous: brand names and lures in any
spelling. The hits are suggestions to look at, not a verdict.

    python scripts/stream_missed.py /data/sample.tsv --rules rules --examples

Never goes to the network.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ctwatchtower.normalize.names import normalize  # noqa: E402
from ctwatchtower.rules.loader import load_ruleset  # noqa: E402
from ctwatchtower.scoring.engine import score_candidate  # noqa: E402

# Lures that smell of an attack on their own, whatever the brand. The German words
# are detection patterns, not prose: German phishing is written in German. Anchored
# at a word boundary on purpose: `login` in `bloggin` is not one.
LURES = re.compile(
    r"(^|[.\-_])(login|signin|secure|security|verify|verification|confirm|"
    r"account|wallet|seed|recovery|airdrop|release|suspended|unlock|otp|"
    r"payment|refund|billing|clientportal|support|helpdesk|"
    r"parcel|delivery|surcharge|reminder|penalty|customs)([.\-_]|$)")

# Endings with a high amount of abuse. The same as `tlds_highrisk`, here only as a
# quick preselection.
CHEAP = {"top", "xyz", "cfd", "sbs", "icu", "rest", "click", "live", "quest",
         "bond", "cyou", "lol", "mom", "zip", "mov", "buzz", "work", "fit",
         "shop", "online", "site", "store", "tk", "ml", "ga", "cf", "gq"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("recording", type=Path)
    ap.add_argument("--rules", type=Path, default=Path("rules"))
    ap.add_argument("--examples", action="store_true")
    ap.add_argument("--out", type=Path, default=Path("missed.tsv"))
    args = ap.parse_args()

    root = args.rules
    folder = root / "examples" if args.examples else root
    rulesets = [load_ruleset(p, root=root) for p in sorted(folder.glob("*.yaml"))]

    seen: set[str] = set()
    hits = []
    for row in args.recording.open(encoding="utf-8", errors="replace"):
        for raw in row.rstrip("\n").split("\t"):
            if not raw or raw in seen:
                continue
            seen.add(raw)
            if not LURES.search(raw.lower()):
                continue
            cand = normalize(raw)
            if cand is None:
                continue
            # Two grounds for suspicion have to come together, otherwise the list is
            # as long as the stream: a lure plus a cheap ending or many labels.
            if cand.tld not in CHEAP and raw.count(".") < 3:
                continue
            best = max((score_candidate(rs, cand).score for rs in rulesets), default=0.0)
            lowest_info = min(rs.thresholds.info for rs in rulesets)
            if best < lowest_info:
                hits.append((best, raw, cand.tld))

    hits.sort(key=lambda f: (-f[0], f[1]))
    with args.out.open("w", encoding="utf-8") as f:
        f.write("best_score\tname\ttld\n")
        for s, n, t in hits:
            f.write(f"{s:g}\t{n}\t{t}\n")
    print(f"{len(hits)} suspicious names below every threshold -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
