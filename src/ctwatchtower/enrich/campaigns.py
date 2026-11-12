"""Campaign clustering (§17.1, addendum §4): union-find over registrar + nameserver
set + IP /24.

Every enriched finding gets one key per IPv4 /24 it is reachable under:
`registrar - nameserver set - network`. Findings sharing a key end up in one
component; a finding with IPs in two networks joins two groups.

The campaign is a stable row in `campaigns`: when a cluster grows or merges it keeps
the oldest existing row, so "active since" stays right across restarts. A
`campaign_id` only exists from two findings upwards.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from collections import defaultdict


def _keys(row: sqlite3.Row) -> list[str]:
    registrar = (row["registrar"] or "").strip().lower()
    ns = ",".join(sorted(json.loads(row["nameservers"] or "[]")))
    nets = set()
    for ip in json.loads(row["a_records"] or "[]"):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4:
            nets.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
    if not (registrar or ns or nets):
        return []  # nothing known, and "nothing" joins no findings
    return [f"{registrar or '-'} / {ns or '-'} / {net}" for net in sorted(nets) or ["-"]]


def cluster(conn: sqlite3.Connection) -> int:
    """Assigns `findings.campaign_id` afresh. Returns the number of campaigns.

    The caller holds the DB lock. Suppressed findings and those marked as false
    positives do not count.
    """
    rows = conn.execute(
        "SELECT id, tenant_id, registrar, nameservers, a_records, first_seen, last_seen, campaign_id"
        " FROM findings WHERE enrich_state='done' AND status NOT IN ('suppressed','false_positive')"
    ).fetchall()

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[tuple[str, str], str] = {}
    keys: dict[str, list[str]] = {}
    for row in rows:
        fid = row["id"]
        keys[fid] = _keys(row)
        parent[fid] = fid
        for key in keys[fid]:
            other = owner.setdefault((row["tenant_id"], key), fid)
            parent[find(fid)] = find(other)

    groups: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        if keys[row["id"]]:
            groups[find(row["id"])].append(row)

    assigned: dict[str, str] = {}
    for members in groups.values():
        if len(members) < 2:
            continue
        tenant = members[0]["tenant_id"]
        first = min(m["first_seen"] for m in members)
        last = max(m["last_seen"] for m in members)
        ids = {m["campaign_id"] for m in members if m["campaign_id"]}
        existing = (
            conn.execute(
                f"SELECT id FROM campaigns WHERE id IN ({','.join('?' * len(ids))}) AND tenant_id=?"
                " ORDER BY first_seen LIMIT 1",
                (*ids, tenant),
            ).fetchone()
            if ids
            else None
        )
        key = min(k for m in members for k in keys[m["id"]])
        if existing is None:
            existing = conn.execute(
                "SELECT id FROM campaigns WHERE tenant_id=? AND cluster_key=?", (tenant, key)
            ).fetchone()
        if existing is None:
            cid = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO campaigns (id, tenant_id, cluster_key, first_seen, last_seen)"
                " VALUES (?,?,?,?,?)",
                (cid, tenant, key, first, last),
            )
        else:
            cid = existing["id"]
            conn.execute(
                "UPDATE campaigns SET first_seen=MIN(first_seen, ?), last_seen=MAX(last_seen, ?) WHERE id=?",
                (first, last, cid),
            )
        for m in members:
            assigned[m["id"]] = cid

    current = conn.execute("SELECT id, campaign_id FROM findings WHERE campaign_id IS NOT NULL").fetchall()
    for row in current:
        if row["id"] not in assigned:
            conn.execute("UPDATE findings SET campaign_id=NULL WHERE id=?", (row["id"],))
    for fid, cid in assigned.items():
        conn.execute("UPDATE findings SET campaign_id=? WHERE id=?", (cid, fid))
    conn.execute(
        "DELETE FROM campaigns WHERE id NOT IN"
        " (SELECT campaign_id FROM findings WHERE campaign_id IS NOT NULL)"
    )
    conn.commit()
    return len(set(assigned.values()))
