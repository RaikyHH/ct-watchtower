"""Find certificates of revoked issuers in the CT stream.

A different kind of monitoring from the rest of the application: this is not about a
brand but about the web PKI itself. When a fresh certificate turns up whose chain
runs through a revoked intermediate, that is remarkable whatever the domain is.

Why it becomes visible at all: Chrome demands SCTs from public CT logs for every
certificate. Whoever wants to issue a certificate that works in a browser, even with
a stolen intermediate key, has to have it logged. Then it is in this stream.

The revocation list comes from the database: maintained in the UI under Settings,
topped up from Mozilla's OneCRL. This file decides nothing about the content, it only
holds it up against the stream.

    python scripts/ca_watch.py --db /data/ctwatchtower.sqlite3

Deliberately runs as a **process of its own**: the pipeline reads `/domains-only` and
never sees the chain at all, and a second consumer in the same process would push its
throughput down as well.

Never goes to the network itself. It reads the local certstream service, which
fetches the CT logs anyway.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import websocket

from ctwatchtower.db import connect
from ctwatchtower.revocation import store

log = logging.getLogger("ca-watch")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://certstream:8080/full-stream",
                    help="`/full-stream` carries the whole chain with a SHA-256 each. "
                         "Only that allows hitting an intermediate exactly; "
                         "`/domains-only` does not even carry the issuer.")
    ap.add_argument("--db", type=Path, default=Path("/data/ctwatchtower.sqlite3"))
    ap.add_argument("--reload-after", type=float, default=300.0,
                    help="seconds after which the list is read fresh from the database")
    ap.add_argument("--seconds", type=float, default=0.0, help="0 = forever")
    ap.add_argument("--out", type=Path, default=None, help="also write hits as JSONL")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    conn = connect(args.db)
    checker = store.load_checker(conn)
    if not len(checker):
        log.warning("The revocation list is empty, nothing will match. "
                    "Sync it under Settings or add entries.")
    log.info("%d revocations loaded", len(checker))

    next_reload = time.monotonic() + args.reload_after
    end = time.time() + args.seconds if args.seconds else None
    writer = args.out.open("a", encoding="utf-8") if args.out else None
    seen = hits = 0
    ws = None

    try:
        while end is None or time.time() < end:
            if time.monotonic() >= next_reload:
                store.load_checker(conn, checker)
                next_reload = time.monotonic() + args.reload_after

            if ws is None:
                ws = websocket.create_connection(args.url, timeout=60)
                log.info("connected: %s", args.url)
            try:
                raw = ws.recv()
            except Exception as exc:  # noqa: BLE001 - every drop means: reconnect
                log.warning("connection lost (%s), retrying", exc)
                ws = None
                time.sleep(2)
                continue
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            if data.get("message_type") == "heartbeat":
                continue
            block = data.get("data") or {}
            chain = block.get("chain") or []
            if not chain:
                continue
            seen += 1

            # The checker remembers its verdict per chain link. There are only a few
            # hundred intermediates, so after a short while this is a dict lookup.
            # Measured: 135 distinct links in 3,000 chains.
            verdict = checker.check_chain(chain)
            if verdict is None:
                continue

            entry, link = verdict
            hits += 1
            leaf = block.get("leaf_cert") or {}
            names = leaf.get("all_domains") or []
            record = {
                "seen_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "revoked_issuer": entry.get("name") or str(entry.get("value", ""))[:60],
                "kind": entry.get("kind"),
                "source": entry.get("source"),
                "reason": entry.get("reason", ""),
                "reference": entry.get("reference", ""),
                "link_sha256": link.get("sha256", ""),
                "link_subject": (link.get("subject") or {}).get("CN") or "",
                "chain": [(g.get("subject") or {}).get("CN") for g in chain],
                "leaf_sha256": leaf.get("sha256", ""),
                "names": names[:20],
                "names_total": len(names),
            }
            # Into the database, so the hit survives the process and shows up in the
            # UI. The same certificate arrives several times, and `report_hit` counts
            # it and only answers `True` the first time.
            try:
                is_new = store.report_hit(conn, record)
            except Exception:  # noqa: BLE001 - a write error does not stop the watch
                log.exception("hit not stored")
                is_new = True
            if is_new:
                log.warning("REVOKED %s via %s -> %s",
                            record["revoked_issuer"], record["link_subject"],
                            ", ".join(names[:3]) or "(no names)")
            if writer:
                writer.write(json.dumps(record, ensure_ascii=False) + "\n")
                writer.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if ws is not None:
            ws.close()
        if writer:
            writer.close()
        conn.close()

    print(f"{seen} chains checked, {hits} through a revoked certificate",
          file=sys.stderr)


if __name__ == "__main__":
    main()
