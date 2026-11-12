"""Name handling (§4.1) and the pipeline's data contracts (§2.3).

`CandidateName` is `cert.candidate`, `CertContext` the compact certificate
context from `cert.raw`. The raw certificate is never passed on.
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

import idna
import tldextract

from ctwatchtower.config import settings
from ctwatchtower.normalize.homoglyph import skeleton


@dataclass(slots=True)
class CandidateName:
    name: str  # canonical form (A-label, no `*.`, no trailing dot)
    unicode: str
    ascii: str
    is_idn: bool
    wildcard: bool
    labels: list[str]
    registrable: str  # eTLD+1
    subdomain: str
    tld: str
    skeleton: str
    prefilter_hits: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CertContext:
    """Certificate context of a CT entry (§2.3 `cert.raw`)."""

    log_id: str
    idx: int
    seen_at: datetime
    not_before: datetime | None
    not_after: datetime | None
    issuer_cn: str
    issuer_o: str
    serial: str
    sha256: str
    is_precert: bool
    names: list[str]


@lru_cache(maxsize=1)
def _extractor() -> tldextract.TLDExtract:
    # §3.5: the PSL ships with the repo, never fetched at runtime.
    return tldextract.TLDExtract(
        suffix_list_urls=(settings.psl_path.resolve().as_uri(),),
        cache_dir=None,
        fallback_to_snapshot=False,
    )


def _to_ascii(name: str) -> str | None:
    if name.isascii():
        return name
    try:
        return idna.encode(name, uts46=True, transitional=False).decode()
    except idna.IDNAError:
        return None


def _to_unicode(ascii_name: str) -> str:
    out = []
    for label in ascii_name.split("."):
        if label.startswith("xn--"):
            try:
                label = idna.decode(label)
            except idna.IDNAError:
                pass  # broken A-label: keep the A form
        out.append(label)
    return ".".join(out)


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        return False
    return True


def normalize(raw: str) -> CandidateName | None:
    """One SAN/CN -> candidate. `None` if the name cannot be scored."""
    name = raw.strip().lower()
    wildcard = False
    while name.startswith("*."):  # `*.*.example.com` does happen
        wildcard = True
        name = name[2:]
    name = name.rstrip(".")

    if not name or name == "localhost" or "." not in name or _is_ip(name):
        return None

    ascii_form = _to_ascii(name)
    if ascii_form is None:
        return None
    unicode_form = _to_unicode(ascii_form)
    is_idn = not name.isascii() or any(lb.startswith("xn--") for lb in ascii_form.split("."))

    ext = _extractor()(ascii_form)
    if not ext.suffix or not ext.domain:
        return None  # no valid TLD, or a bare public suffix

    return CandidateName(
        name=ascii_form,
        unicode=unicode_form,
        ascii=ascii_form,
        is_idn=is_idn,
        wildcard=wildcard,
        labels=ascii_form.split("."),
        registrable=f"{ext.domain}.{ext.suffix}",
        subdomain=ext.subdomain,
        tld=ext.suffix,
        skeleton=skeleton(unicode_form),
    )


if __name__ == "__main__":
    c = normalize("*.PayLi0-Secure.TOP.")
    assert c and c.wildcard and c.registrable == "payli0-secure.top" and c.skeleton == "paylio-secure.top"
    assert normalize("10.0.0.1") is None and normalize("co.uk") is None
    print("ok", c)
