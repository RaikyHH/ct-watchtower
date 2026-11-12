"""Deeplinks out of `config/deeplinks.yaml` (§7.8)."""

from ctwatchtower.enrich.deeplinks import deeplinks, load_deeplinks


def test_repo_file_carries_the_spec_services() -> None:
    names = [n for n, _ in load_deeplinks()]
    for wanted in (
        "crt.sh",
        "VirusTotal",
        "urlscan.io",
        "Shodan",
        "SecurityTrails",
        "AbuseIPDB",
        "Google Safe Browsing",
        "Wayback Machine",
        "RDAP raw",
        "DNS (dnsviz)",
    ):
        assert wanted in names


def test_links_are_encoded_and_skip_missing_placeholders() -> None:
    links = dict(deeplinks("a b.example.com", "example.com"))
    assert links["crt.sh"] == "https://crt.sh/?q=a%20b.example.com"
    assert links["RDAP raw"] == "https://rdap.org/domain/example.com"
    assert "AbuseIPDB" not in links  # no IP known
    assert dict(deeplinks("x.com", ip="192.0.2.1"))["AbuseIPDB"].endswith("/check/192.0.2.1")


def test_only_https_links_with_a_fixed_host(tmp_path, caplog) -> None:
    f = tmp_path / "links.yaml"
    f.write_text(
        "links:\n"
        "  - {name: gut, url: 'https://example.org/{domain}'}\n"
        "  - {name: selbst, url: 'https://{domain}/'}\n"
        "  - {name: http, url: 'http://example.org/{domain}'}\n",
        encoding="utf-8",
    )
    assert [n for n, _ in deeplinks("x.com", path=f)] == ["gut"]
    assert "selbst" in caplog.text
    assert deeplinks("x.com", path=tmp_path / "fehlt.yaml") == []
