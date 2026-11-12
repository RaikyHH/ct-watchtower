"""Record a slice of the CT stream, to recompute things on real data.

Taps the **running** certstream service instead of starting a second one: that one
would fetch all the CT logs again, which is load on somebody else's servers for data
we already have.

    python scripts/record_stream.py --seconds 600 --out /data/sample.tsv

One line per certificate gets written, names separated by tabs. No scoring, no
filtering, this is raw material.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import websocket


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="ws://certstream:8080/domains-only")
    ap.add_argument("--seconds", type=float, default=600.0)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    ws = websocket.create_connection(args.url, timeout=30)
    end = time.monotonic() + args.seconds
    certificates = names = 0
    last_report = time.monotonic()

    with args.out.open("w", encoding="utf-8") as f:
        while time.monotonic() < end:
            try:
                raw = ws.recv()
            except Exception as exc:  # noqa: BLE001 - a drop is no drama here
                print(f"connection gone after {certificates} certificates: {exc}",
                      file=sys.stderr)
                break
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            entries = data.get("data") if isinstance(data, dict) else data
            if isinstance(entries, dict):
                entries = entries.get("leaf_cert", {}).get("all_domains") or []
            if not isinstance(entries, list) or not entries:
                continue
            f.write("\t".join(str(n) for n in entries) + "\n")
            certificates += 1
            names += len(entries)
            if time.monotonic() - last_report >= 60:
                last_report = time.monotonic()
                left = int(end - time.monotonic())
                print(f"{certificates} certificates · {names} names · {left}s to go", flush=True)

    ws.close()
    print(f"done: {certificates} certificates, {names} names -> {args.out}")


if __name__ == "__main__":
    main()
