"""Run a stream recording against rulesets. Like the pipeline, only offline.

The Aho-Corasick prefilter over everything first, then the scoring only for what
gets through. Exactly the order of the real pipeline; anything else would not be
computable at millions of names.

    python scripts/analyse_stream.py /data/sample.tsv --rules rules --examples

Writes a TSV with one line per hit: tenant, score, severity, name, reasons. Never
goes to the network. Phase 1, without certificate context, without enrichment.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ctwatchtower.normalize.names import normalize  # noqa: E402
from ctwatchtower.normalize.prefilter import build_from_rulesets  # noqa: E402
from ctwatchtower.rules.loader import load_ruleset  # noqa: E402
from ctwatchtower.scoring.engine import score_candidate  # noqa: E402


class _Private:
    """Wraps the extractor and switches the private PSL section on."""

    def __init__(self, real):
        self._real = real

    def __call__(self, name, **kw):
        kw.setdefault("include_psl_private_domains", True)
        return self._real(name, **kw)


def load_rulesets(root: Path, examples: bool) -> list:
    folder = root / "examples" if examples else root
    return [load_ruleset(p, root=root) for p in sorted(folder.glob("*.yaml"))]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("recording", type=Path)
    ap.add_argument("--rules", type=Path, default=Path("rules"))
    ap.add_argument("--examples", action="store_true", help="rules/examples instead of rules/")
    ap.add_argument("--out", type=Path, default=Path("hits.tsv"))
    ap.add_argument("--from", dest="from_", default="persist",
                    choices=["persist", "info", "warning", "alert"])
    ap.add_argument("--psl-private", action="store_true",
                    help="determine the registrable domain with the private PSL section")
    args = ap.parse_args()

    if args.psl_private:
        # For measuring, not as a switch for the product: under a private suffix
        # (`pages.dev`) the label to its left is what the attacker registered
        # themselves, and not a subdomain of somebody else's platform.
        import ctwatchtower.normalize.names as _n
        _real = _n._extractor()
        _n._extractor = lambda: _Private(_real)

    rulesets = load_rulesets(args.rules, args.examples)
    print(f"{len(rulesets)} rulesets: {', '.join(rs.tenant.id for rs in rulesets)}",
          file=sys.stderr)

    prefilter = build_from_rulesets(rulesets)
    certs = names = unique = passed = 0
    seen: set[str] = set()
    counts: Counter[str] = Counter()
    # Which prefilter term pulls how much through? A term that matches often and never
    # leads to a finding is exactly what clogs the automaton.
    term_passed: Counter[str] = Counter()
    term_hit: Counter[str] = Counter()
    rows = []

    with args.recording.open(encoding="utf-8", errors="replace") as f:
        for row in f:
            certs += 1
            for raw in row.rstrip("\n").split("\t"):
                if not raw:
                    continue
                names += 1
                # Dedupe across the whole run: a name that appears in 500
                # certificates is one observation, not 500.
                if raw in seen:
                    continue
                seen.add(raw)
                unique += 1

                cand = normalize(raw)
                if cand is None:
                    continue
                hits = prefilter.hits(cand)
                if not hits:
                    continue
                passed += 1
                for t in hits:
                    term_passed[t] += 1
                # Score only the tenants whose terms actually matched, exactly as the
                # pipeline does.
                wanted = prefilter.tenants_for(hits)
                for rs in rulesets:
                    if wanted is not None and rs.tenant.id not in wanted:
                        continue
                    r = score_candidate(rs, cand)
                    limit = getattr(rs.thresholds, args.from_)
                    if r.score < limit:
                        continue
                    counts[rs.tenant.id] += 1
                    for t in hits:
                        term_hit[t] += 1
                    rows.append((rs.tenant.id, r.score, r.severity, raw,
                                 " ".join(r.matched[:6])))

    rows.sort(key=lambda r: -r[1])
    with args.out.open("w", encoding="utf-8") as f:
        f.write("tenant\tscore\tseverity\tname\treasons\n")
        for tenant, score, sev, name, why in rows:
            f.write(f"{tenant}\t{score:g}\t{sev}\t{name}\t{why}\n")

    print(f"\n{certs} certificates · {names} names · {unique} unique", file=sys.stderr)
    print(f"{passed} through the prefilter ({passed / max(unique, 1):.2%})", file=sys.stderr)
    for tenant, n in counts.most_common():
        print(f"  {tenant:<22} {n:>6} hits from {args.from_}", file=sys.stderr)

    print("\nPrefilter terms with the worst yield:", file=sys.stderr)
    print(f"  {'term':<22}{'let through':>14}{'of those hits':>15}", file=sys.stderr)
    for t, n in term_passed.most_common(25):
        print(f"  {t:<22}{n:>14}{term_hit.get(t, 0):>15}", file=sys.stderr)

    with args.out.with_suffix(".terms.tsv").open("w", encoding="utf-8") as f:
        f.write("term\tlet_through\tof_those_hits\n")
        for t, n in term_passed.most_common():
            f.write(f"{t}\t{n}\t{term_hit.get(t, 0)}\n")
    print(f"-> {args.out} and {args.out.with_suffix('.terms.tsv')}", file=sys.stderr)


if __name__ == "__main__":
    main()
