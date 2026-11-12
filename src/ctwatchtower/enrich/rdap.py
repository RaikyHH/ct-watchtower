"""Registration data over RDAP (§7.2), WHOIS as a fallback (§7.3).

**Data protection (§16.2), not negotiable.** Only what is listed in
`REGISTRATION_FIELDS` is taken out of an answer: registrar name and IANA id,
registration, change and expiry date, EPP status, nameservers. That is an allowlist
over field names: `allow()` is the only place a result leaves this module through.
Cache and database never see anything else. Registrant and contact data is not even
read; the raw answer (JSON or WHOIS text) lives only as a local variable and is
never stored.
"""

from __future__ import annotations

import re
import socket
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from ctwatchtower.config import settings
from ctwatchtower.enrich.net import Cache, Quota, ServerLimits, Transient, client, daily_limits

REGISTRATION_FIELDS = frozenset(
    {
        "registrar", "registrar_iana_id", "created", "changed", "expires",
        "epp_status", "nameservers",
        # The abuse contact **of the registrar** (`abuse@registrar.example`), an
        # organisational address, nothing personal. §17.2 provides for it explicitly
        # for the abuse report. Only the `abuse` role INSIDE the registrar entry is
        # read; registrant, admin and tech are never touched.
        "registrar_abuse_email",
    }
)

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL = 86_400  # §7.2: refreshed daily
TTL_YOUNG, TTL_OLD, OLD_DAYS = 86_400, 7 * 86_400, 90  # §7.2
WHOIS_SERVER_TTL = 30 * 86_400
WHOIS_MAX_BYTES = 256 * 1024


def allow(data: dict[str, Any]) -> dict[str, Any]:
    """The allowlist (§16.2). Anything not allowed by name is dropped."""
    return {k: v for k, v in data.items() if k in REGISTRATION_FIELDS and v not in (None, "", [])}


def _date(value: Any) -> str | None:
    """ISO-8601 in UTC, or `None` if the date is unreadable (§7.3: no abort)."""
    text = str(value or "").strip()
    for parse in (
        lambda t: datetime.fromisoformat(t.replace("Z", "+00:00")),
        lambda t: datetime.strptime(t, "%d-%b-%Y"),  # 12-Nov-2002
        lambda t: datetime.strptime(t, "%d.%m.%Y"),
    ):
        try:
            dt = parse(text)
        except ValueError:
            continue
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).isoformat()
    return None


def _epp(status: str) -> str:
    """RDAP "client transfer prohibited" -> EPP "clientTransferProhibited"."""
    words = status.strip().split()
    return words[0].lower() + "".join(w.capitalize() for w in words[1:]) if words else ""


def _abuse_email(registrar_entity: dict[str, Any]) -> str | None:
    """The registrar's abuse address. Only from the `abuse` role below the registrar.

    Not from the domain object itself: the registrant with their contact details
    would be in there too. That restriction is why extending the allowlist (§16.2)
    is defensible.
    """
    for sub in registrar_entity.get("entities") or []:
        if "abuse" not in (sub.get("roles") or []):
            continue
        vcard = (sub.get("vcardArray") or [None, []])[1] or []
        for entry in vcard:
            if entry and entry[0] == "email" and str(entry[3]).strip():
                return str(entry[3]).strip().lower()
    return None


def _ns(names: list[str]) -> list[str]:
    return sorted({n.strip().lower().rstrip(".") for n in names if n and n.strip()})


def parse_rdap(doc: dict[str, Any]) -> dict[str, Any]:
    """RDAP domain object -> allowed fields. Reads deliberately, never copies the object."""
    out: dict[str, Any] = {}
    for entity in doc.get("entities") or []:
        if "registrar" not in (entity.get("roles") or []):
            continue  # registrant, administrative, technical, abuse: never touched
        vcard = (entity.get("vcardArray") or [None, []])[1] or []
        out["registrar"] = next((str(p[3]) for p in vcard if p and p[0] == "fn"), None)
        out["registrar_abuse_email"] = _abuse_email(entity)
        for pid in entity.get("publicIds") or []:
            if pid.get("type") == "IANA Registrar ID" and str(pid.get("identifier", "")).isdigit():
                out["registrar_iana_id"] = int(pid["identifier"])
        break
    events = {e.get("eventAction"): e.get("eventDate") for e in doc.get("events") or []}
    out["created"] = _date(events.get("registration"))
    out["changed"] = _date(events.get("last changed"))
    out["expires"] = _date(events.get("expiration"))
    out["epp_status"] = [_epp(s) for s in doc.get("status") or [] if _epp(s)]
    out["nameservers"] = _ns([n.get("ldhName", "") for n in doc.get("nameservers") or []])
    return allow(out)


# Key of a WHOIS line -> allowed field. Whatever is missing here is ignored.
WHOIS_KEYS = {
    "registrar": "registrar",
    "sponsoring registrar": "registrar",
    "registrar name": "registrar",
    "registrar iana id": "registrar_iana_id",
    "registrar abuse contact email": "registrar_abuse_email",
    "abuse contact email": "registrar_abuse_email",
    "creation date": "created",
    "created": "created",
    "created on": "created",
    "registered on": "created",
    "registration time": "created",
    "updated date": "changed",
    "last updated": "changed",
    "last modified": "changed",
    "changed": "changed",
    "registry expiry date": "expires",
    "registrar registration expiration date": "expires",
    "expiration date": "expires",
    "expiration time": "expires",
    "expiry date": "expires",
    "paid-till": "expires",
    "domain status": "epp_status",
    "status": "epp_status",
    "name server": "nameservers",
    "nserver": "nameservers",
}


def parse_whois(text: str) -> dict[str, Any]:
    """WHOIS text -> allowed fields (§7.3). A generic `key: value` parser.

    Sections (`Registrant:` with indented lines below it, as with `.eu`) are
    skipped, with two exceptions: `Name` under `Registrar:` and the list under
    `Name servers:`. That way a `Name:` under `Registrant:` never ends up in the
    registrar field.
    """
    out: dict[str, Any] = {"epp_status": [], "nameservers": []}
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            section = None
            continue
        if line.startswith(("%", "#", ">>>")):
            continue
        key, sep, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if sep and not value:
            section = key
            continue
        if raw[:1] in " \t" and section:
            if section == "registrar" and key == "name" and sep:
                out["registrar"] = value
            elif section in ("name servers", "nameservers"):
                out["nameservers"].append(line.split()[0])
            continue
        field = WHOIS_KEYS.get(key) if sep else None
        if field in ("epp_status", "nameservers"):
            out[field].append(value.split()[0])
        elif field == "registrar_iana_id":
            out[field] = int(value) if value.isdigit() else None
        elif field in ("created", "changed", "expires"):
            if not out.get(field):
                out[field] = _date(value)
        elif field:
            out.setdefault(field, value)
    out["epp_status"] = sorted(set(out["epp_status"]))
    out["nameservers"] = _ns(out["nameservers"])
    return allow(out)


def domain_age_days(data: dict[str, Any], now: datetime | None = None) -> int | None:
    created = data.get("created")
    if not created:
        return None
    return max(0, ((now or datetime.now(UTC)) - datetime.fromisoformat(created)).days)


class Registration:
    """RDAP with bootstrap, a rate limit per server and a cache; WHOIS where RDAP is missing."""

    def __init__(self, cache: Cache, http: httpx.Client | None = None, whois=None) -> None:
        self.cache = cache
        self._http = http
        self.limits = ServerLimits(settings.enrich_rdap_rps)
        self.quota = Quota(cache.conn, cache.lock)
        self.whois_query = whois or _whois_query

    @property
    def http(self) -> httpx.Client:
        # Only on the first call: an httpx client loads the CA store when created.
        if self._http is None:
            self._http = client("application/rdap+json")
        return self._http

    def bootstrap(self) -> dict[str, str]:
        """TLD -> RDAP base URL from the IANA file, cached locally (§7.2)."""
        data = self.cache.get("bootstrap", "dns.json")
        if data is None:
            try:
                resp = self.http.get(BOOTSTRAP_URL)
                resp.raise_for_status()
                services = resp.json()["services"]
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                raise Transient(f"RDAP bootstrap: {exc}") from exc
            data = {tld.lower(): urls[0] for tlds, urls in services for tld in tlds if urls}
            self.cache.put("bootstrap", "dns.json", data, BOOTSTRAP_TTL)
        return data

    def lookup(self, registrable: str) -> dict[str, Any]:
        """The domain's allowed registration fields; `{}` if there are none.

        Raises `Defer` (server throttled, try later) or `Transient` (failed
        attempt). The cache key is the registrable domain (§7.1).
        """
        cached = self.cache.get("rdap", registrable)
        if cached is not None:
            return cached
        base = self.bootstrap().get(registrable.rsplit(".", 1)[-1])
        if base:
            data = self._rdap(base, registrable)
        elif settings.enrich_whois_fallback:
            data = self._whois(registrable)
        else:
            data = {}
        age = domain_age_days(data)
        self.cache.put("rdap", registrable, data, TTL_OLD if age and age > OLD_DAYS else TTL_YOUNG)
        return data

    def _rdap(self, base: str, registrable: str) -> dict[str, Any]:
        server = urlsplit(base).netloc
        self.limits.check(server)
        self.quota.take(daily_limits("rdap", server))
        try:
            resp = self.http.get(f"{base.rstrip('/')}/domain/{registrable}")
        except httpx.HTTPError as exc:
            raise Transient(f"{server}: {exc}") from exc
        if resp.status_code == 429:
            self.limits.block(server)
            raise Transient(f"{server}: 429, resting for 10 min")
        if resp.status_code >= 500:
            raise Transient(f"{server}: HTTP {resp.status_code}")
        if resp.status_code != 200:
            return {}  # 404 and friends: the registry does not know the domain, a result, not an error
        try:
            return parse_rdap(resp.json())
        except (ValueError, TypeError, AttributeError, IndexError):
            return {}  # §7.3 in spirit: unreadable -> fields stay empty, no abort

    def _whois(self, registrable: str) -> dict[str, Any]:
        tld = registrable.rsplit(".", 1)[-1]
        server = self.cache.get("whois-server", tld)
        if server is None:
            self.limits.check("whois.iana.org")
            self.quota.take(daily_limits("whois", "whois.iana.org"))
            answer = self.whois_query("whois.iana.org", tld)
            # `[ \t]`, not `\s`: for TLDs without a server (`.lk`) the line is empty,
            # and `\s` would run over the newline to the next word ("status:").
            server = next(iter(re.findall(r"(?im)^whois:[ \t]*(\S+)", answer)), "")
            self.cache.put("whois-server", tld, server, WHOIS_SERVER_TTL)
        if not server:
            return {}
        self.limits.check(server)
        self.quota.take(daily_limits("whois", server))
        return parse_whois(self.whois_query(server, registrable))


def _whois_query(server: str, query: str) -> str:  # pragma: no cover - real network
    """Port 43, 10 s timeout (§7.3). The answer leaves this function only as text."""
    try:
        with socket.create_connection((server, 43), timeout=settings.enrich_timeout) as sock:
            sock.sendall(f"{query}\r\n".encode())
            chunks, size = [], 0
            while size < WHOIS_MAX_BYTES and (chunk := sock.recv(4096)):
                chunks.append(chunk)
                size += len(chunk)
    except OSError as exc:
        raise Transient(f"WHOIS {server}: {exc}") from exc
    return b"".join(chunks).decode("utf-8", errors="replace")
