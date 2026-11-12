"""Tenants that are not tenants.

The tenant picker holds two entries with no ruleset behind them:

    all-tenants       sums up the findings of every tenant
    revoked-watcher   shows the certificates of revoked issuers

In the picker they look like tenants so they are found where people look for them.
That is why their ids have to be **taken**: if there were a real tenant called
`all-tenants`, the same entry would be there twice and nobody would know which one
is meant. The block applies in two places, when creating a tenant through the UI
and in the rule schema itself, so a hand-written YAML file is refused too.
"""

from __future__ import annotations

ALL_TENANTS = "all-tenants"
REVOKED = "revoked-watcher"

# The order is the display order: the overall view first, then the special watch,
# then the real tenants.
PSEUDO: dict[str, str] = {
    ALL_TENANTS: "All tenants",
    REVOKED: "Revoked watcher",
}


def is_pseudo(ident: str | None) -> bool:
    return ident in PSEUDO


def name(ident: str | None) -> str | None:
    return PSEUDO.get(ident or "")


def query_filter(ident: str | None) -> str | None:
    """What belongs in a query as the tenant filter.

    `all-tenants` becomes `None`. The queries then leave the filter out and sum up
    over everything. That was always how it worked, only nobody had a way to pick
    it.
    """
    if ident == ALL_TENANTS:
        return None
    return ident
