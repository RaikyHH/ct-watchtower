"""Check every YAML under `rules/` against the schema (§14.2, point 5).

Runs in CI. A ruleset that does not load would be skipped silently in production
(§5.1: on an error the old version stays active); here it should stand out.

    python scripts/validate_rules.py [directory]
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from ctwatchtower.rules.loader import RuleLoadError, load_ruleset  # noqa: E402


def main(root: Path) -> int:
    files = sorted(root.rglob("*.y*ml"))
    if not files:
        print(f"No rule files under {root}")
        return 1

    broken = 0
    for path in files:
        # The `common/` building blocks are fragments without a `tenant`; they are
        # checked through the files that include them, not on their own.
        if path.parent.name == "common":
            continue
        try:
            rs = load_ruleset(path, root=root)
        except RuleLoadError as exc:
            print(f"ERROR   {path.relative_to(REPO)}: {exc}")
            broken += 1
            continue
        anchors = sum(len(g.terms) for g in rs.anchors)
        print(f"ok      {path.relative_to(REPO)}  ({rs.tenant.id}, {anchors} anchor terms)")

    print(f"\n{len(files)} files checked, {broken} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    # `.resolve()`: without it the output breaks at `relative_to(REPO)` as soon as
    # somebody passes a relative path (`scripts/validate_rules.py rules`).
    target = (Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "rules").resolve()
    raise SystemExit(main(target))
