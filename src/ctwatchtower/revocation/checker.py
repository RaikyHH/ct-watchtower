"""Hold a certificate against the revocation list.

The list addresses certificates by values that first have to be computed from the
DER bytes: SHA-256 over the SubjectPublicKeyInfo, or issuer plus serial number.
Doing that for every chain link at 2000 certificates a second would be too dear.

The structure of the web PKI helps, though: there are only a few hundred
intermediate certificates, and the same ones over and over. The R series of Let's
Encrypt sits in half of all chains. So compute once per chain link and remember
the result under its SHA-256, which certstream hands over anyway. After a few
minutes every check is a dict lookup.
"""

from __future__ import annotations

import base64
import hashlib
import logging

from ctwatchtower.revocation.der import DerError, fields

log = logging.getLogger(__name__)


class Checker:
    """Holds the revocation list and answers: is this certificate revoked?

    Not thread-safe for writes; `load` swaps the sets in one go, so a concurrent
    reader never sees half a list.
    """

    def __init__(self) -> None:
        self._spki: dict[str, dict] = {}
        self._issuer_serial: dict[str, dict] = {}
        self._sha256: dict[str, dict] = {}
        self._verdict: dict[str, dict | None] = {}

    def load(self, entries: list[dict]) -> int:
        """Replace the list. Returns the number of entries taken."""
        spki, iss_ser, sha = {}, {}, {}
        for e in entries:
            kind, value = e.get("kind"), e.get("value")
            if not kind or not value:
                continue
            if kind == "spki":
                spki[value] = e
            elif kind == "issuer_serial":
                iss_ser[value] = e
            elif kind == "sha256":
                sha[value.replace(":", "").lower()] = e
        self._spki, self._issuer_serial, self._sha256 = spki, iss_ser, sha
        # Old verdicts no longer hold, the list is a different one.
        self._verdict = {}
        return len(spki) + len(iss_ser) + len(sha)

    def __len__(self) -> int:
        return len(self._spki) + len(self._issuer_serial) + len(self._sha256)

    def check(self, der: bytes, sha256_hex: str | None = None) -> dict | None:
        """The entry that matches this certificate, or `None`.

        `sha256_hex` is the cache key. If it is missing it gets computed; handed
        over it is free.
        """
        key = (sha256_hex or hashlib.sha256(der).hexdigest()).replace(":", "").lower()
        if key in self._verdict:
            return self._verdict[key]
        verdict = self._compute(der, key)
        # Memory stays bounded: there are not endlessly many intermediates, but
        # leaf certificates are endless. A hard cap is cheaper than a clever
        # eviction scheme.
        if len(self._verdict) < 50_000:
            self._verdict[key] = verdict
        return verdict

    def _compute(self, der: bytes, key: str) -> dict | None:
        if hits := self._sha256.get(key):
            return hits
        if not self._spki and not self._issuer_serial:
            return None
        try:
            f = fields(der)
        except DerError as exc:
            log.debug("certificate not readable: %s", exc)
            return None

        if self._spki:
            key_hash = base64.b64encode(hashlib.sha256(f["spki"]).digest()).decode()
            subject = base64.b64encode(f["subject"]).decode()
            if hits := self._spki.get(f"{subject}|{key_hash}"):
                return hits

        if self._issuer_serial:
            issuer = base64.b64encode(f["issuer"]).decode()
            serial = base64.b64encode(f["serial"]).decode()
            if hits := self._issuer_serial.get(f"{issuer}|{serial}"):
                return hits
        return None

    def check_chain(self, links: list[dict]) -> tuple[dict, dict] | None:
        """Check a whole chain. Returns (entry, chain link) of the first hit.

        Checked from the back: a revoked intermediate is what counts. A revoked
        leaf is a single case, a revoked intermediate affects everything below it.
        """
        for link in reversed(links):
            raw = link.get("as_der")
            if not raw:
                continue
            try:
                der = base64.b64decode(raw)
            except (ValueError, TypeError):
                continue
            if hits := self.check(der, link.get("sha256")):
                return hits, link
        return None
