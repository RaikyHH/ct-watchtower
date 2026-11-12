"""A test helper: candidates and a certificate context for the scoring tests.

Both factories reach through to the **production code** (`normalize/names.py`). A
second, shortened normalisation in the tests would have checked the golden set
against a different semantics than the pipeline - `tld` as the last label instead
of as the complete public suffix, say.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ctwatchtower.normalize.names import CandidateName, CertContext, normalize


def make_candidate(domain: str) -> CandidateName:
    """A normalised candidate out of a raw hostname (§4.1)."""
    cand = normalize(domain)
    if cand is None:
        raise ValueError(f"not scorable: {domain!r}")
    return cand


def make_cert(names: list[str] | None = None, **overrides) -> CertContext:
    """A certificate context per §2.3."""
    cert = CertContext(
        log_id="oak2026h1",
        idx=918273645,
        seen_at=datetime(2026, 9, 15, 10, 22, 31, tzinfo=UTC),
        not_before=datetime(2026, 9, 15, 10, 20, tzinfo=UTC),
        not_after=datetime(2026, 9, 21, 10, 20, tzinfo=UTC),
        issuer_cn="E7",
        issuer_o="Let's Encrypt",
        serial="03a1",
        sha256="9f2c",
        is_precert=True,
        names=names or [],
    )
    for key, value in overrides.items():
        setattr(cert, key, value)
    return cert


def test_the_helpers_use_the_production_code() -> None:
    cand = make_candidate("*.PayLi0-Secure.Login.TOP.")
    assert cand.wildcard and cand.name == "payli0-secure.login.top"
    assert cand.registrable == "login.top" and cand.subdomain == "payli0-secure"
    assert cand.skeleton == "paylio-secure.login.top"

    idn = make_candidate("xn--pylio-4ve.com")
    assert idn.is_idn and idn.ascii.startswith("xn--")
    assert idn.skeleton == "paylio.com"

    # The complete public suffix, not just the last label (§4.1.6).
    assert make_candidate("shop.co.uk").tld == "co.uk"
