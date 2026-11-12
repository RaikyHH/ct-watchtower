"""Deeplinks to analysis services from `config/deeplinks.yaml` (§7.8).

Plain links, no server-side call. The UI still wires its links up itself
(`web/views.py::analysis_links`); this function is the replacement for that.
"""

from __future__ import annotations

import functools
import logging
import string
from pathlib import Path
from urllib.parse import quote

from ruamel.yaml import YAML

from ctwatchtower.config import settings

log = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("https://",)


@functools.lru_cache(maxsize=4)
def _load(path: str, mtime: float) -> tuple[tuple[str, str], ...]:
    doc = YAML(typ="safe").load(Path(path).read_text(encoding="utf-8")) or {}
    out = []
    for entry in doc.get("links") or []:
        name, url = str(entry.get("name", "")).strip(), str(entry.get("url", "")).strip()
        # https targets with a fixed host only: a placeholder before the first `/`
        # could otherwise produce a link to the suspicious domain itself.
        host = url.removeprefix("https://").split("/", 1)[0]
        if name and url.startswith(ALLOWED_SCHEMES) and "{" not in host:
            out.append((name, url))
        else:
            log.warning("deeplink %r skipped: https targets with a fixed host only", name or url)
    return tuple(out)


def load_deeplinks(path: Path | None = None) -> tuple[tuple[str, str], ...]:
    """`(name, url pattern)` per entry. Without the file there are no links."""
    path = path or settings.deeplinks_path
    try:
        return _load(str(path), path.stat().st_mtime)
    except OSError:
        log.warning("deeplink file %s is missing", path)
        return ()


def deeplinks(
    domain: str, registrable: str = "", ip: str = "", path: Path | None = None
) -> list[tuple[str, str]]:
    """Finished links for a finding. Links whose placeholders stayed empty are dropped."""
    values = {"domain": domain, "registrable": registrable or domain, "ip": ip}
    out = []
    for name, pattern in load_deeplinks(path):
        fields = {f for _, f, _, _ in string.Formatter().parse(pattern) if f}
        if all(values.get(f) for f in fields):
            out.append((name, pattern.format(**{k: quote(v, safe="") for k, v in values.items()})))
    return out
