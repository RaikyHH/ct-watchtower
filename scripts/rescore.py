"""Rescore stored findings with today's rules.

The pipeline scores what comes in. Older findings stay as they were. So after a rule
change or a corrected detector, the list holds findings that would come out
differently today, or would not come about at all.

    python scripts/rescore.py <tenant> [--write] [--db PATH]

Without `--write` it only shows what would change. Anything that falls below the
`persist` threshold is deleted when writing: the finding would not have been created
at all today.

What gets touched is `score`, `severity` and `explanation`. `status` stays as it is,
because no machine overwrites a judgement made by hand. `score_enriched` and
`enrich_note` are dropped, because they belonged to the old scoring.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from ctwatchtower.config import settings  # noqa: E402
from ctwatchtower.normalize.names import CertContext, normalize  # noqa: E402
from ctwatchtower.rules.loader import RULES_DIR, load_ruleset  # noqa: E402
from ctwatchtower.scoring.engine import score_candidate  # noqa: E402


def _cert(row: sqlite3.Row) -> CertContext | None:
    """The certificate context out of the stored columns.

    If something is missing, nothing is invented: the certificate-related detectors
    simply do not fire instead of insisting on a guessed value.
    """
    if not row["cert_sha256"]:
        return None
    # Only part of the certificate is stored (§9.1). What is missing: the issuer CN,
    # the serial number, the remaining SANs. Left empty rather than guessed; the
    # detectors concerned then simply do not fire.
    related = json.loads(row["related_names"] or "[]")
    return CertContext(
        log_id=row["ct_log_id"] or "",
        idx=row["ct_log_index"] or 0,
        seen_at=datetime.now(UTC),
        not_before=row["cert_not_before"],
        not_after=row["cert_not_after"],
        issuer_cn="",
        issuer_o=row["issuer_o"] or "",
        serial="",
        sha256=row["cert_sha256"],
        is_precert=False,
        names=[row["domain"], *related],
    )


def _best(rs, row: sqlite3.Row):
    """The score of the strongest name in this row.

    A certificate often carries several names. The dedupe (§4.4) creates one row per
    `registrable` and raises its score when a sibling name comes out stronger;
    `domain` stays the one seen first. Rescoring only `domain` would therefore talk
    such findings down: `datasport.ag` on its own gives 40, while the name
    `secure.datasport.ag` from the same certificate gives 84.
    """
    cert = _cert(row)
    names = [row["domain"], *json.loads(row["related_names"] or "[]")]
    results = [
        score_candidate(rs, cand, cert) for n in names if (cand := normalize(n)) is not None
    ]
    return max(results, key=lambda e: e.score, default=None)


def rescore(conn: sqlite3.Connection, rs, *, write: bool) -> dict[str, int]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM findings WHERE tenant_id=? ORDER BY first_seen", (rs.tenant.id,)
    ).fetchall()
    numbers = dict.fromkeys(("same", "changed", "dropped", "kept", "unscorable"), 0)

    for row in rows:
        result = _best(rs, row)
        if result is None:
            numbers["unscorable"] += 1
            print(f"  ?  {row['domain']}  - no scorable name left")
            continue
        old, fresh = row["score"], result.score
        if result.severity is None and row["status"] in ("confirmed", "reported"):
            # Confirmed by hand or already reported: the finding stays, even when
            # today's rules would not find it any more. The retention keeps it for the
            # same reason (§9.3).
            numbers["kept"] += 1
            print(f"  !  {row['domain']}  {old} -> {fresh}, but {row['status']}: stays")
            continue
        if result.severity is None:
            numbers["dropped"] += 1
            print(f"  -  {row['domain']}  {old} -> {fresh}, below the threshold: dropped")
            if write:
                conn.execute("DELETE FROM findings WHERE id=?", (row["id"],))
            continue
        if old == fresh and row["severity"] == result.severity:
            numbers["same"] += 1
            # Clear the result of the second scoring here too: it came about before
            # the rule change. Two numbers from different times next to each other are
            # worse than one number less. The enrichment itself (registrar,
            # nameservers, age) stays, it cost queries and does not change with a rule.
            if write and row["score_enriched"] is not None:
                conn.execute(
                    "UPDATE findings SET score_enriched=NULL, enrich_note=NULL WHERE id=?",
                    (row["id"],),
                )
            continue
        numbers["changed"] += 1
        print(f"  ~  {row['domain']}  {old} -> {fresh}  ({row['severity']} -> {result.severity})")
        if write:
            conn.execute(
                "UPDATE findings SET score=?, score_phase1=?, severity=?, explanation=?,"
                " score_enriched=NULL, enrich_note=NULL WHERE id=?",
                (fresh, fresh, result.severity, json.dumps(result.to_dict()), row["id"]),
            )
    if write:
        conn.commit()
    return numbers


def main() -> int:
    # Windows consoles often sit on cp1252; an arrow in the text used to end the
    # script mid-run.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("tenant")
    p.add_argument("--write", action="store_true", help="really store the changes")
    p.add_argument("--db", default=str(settings.database_path))
    p.add_argument("--rules", default=str(RULES_DIR))
    args = p.parse_args()

    rules = Path(args.rules)
    rs = load_ruleset(rules / f"{args.tenant}.yaml", root=rules)
    conn = sqlite3.connect(args.db)
    print(f"{args.tenant}: ruleset {rs.ruleset_hash}, database {args.db}")
    numbers = rescore(conn, rs, write=args.write)
    print(
        f"\n{numbers['same']} unchanged · {numbers['changed']} rescored · "
        f"{numbers['dropped']} below the threshold · "
        f"{numbers['kept']} kept despite the threshold · {numbers['unscorable']} unscorable"
    )
    if not args.write:
        print("A dry run. With `--write` it really gets written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
