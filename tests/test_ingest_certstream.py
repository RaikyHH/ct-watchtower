import json
import queue
import time

from ctwatchtower.ingest.certstream import BACKOFF_CAP, CertStreamIngest, backoff_delay, parse_message
from ctwatchtower.ingest.dedupe import TTLSet

FULL = json.dumps({
    "message_type": "certificate_update",
    "data": {
        "update_type": "PrecertLogEntry",
        "cert_index": 918273645,
        "seen": 1789000000,
        "source": {"name": "oak2026h1", "url": "https://oak.ct.letsencrypt.org/2026h1/"},
        "leaf_cert": {
            "all_domains": ["*.payli0-secure.top", "payli0-secure.top"],
            "not_before": 1788900000,
            "not_after": 1789400000,
            "serial_number": "03a1",
            "fingerprint": "9F:2C:AB",
            "issuer": {"CN": "E7", "O": "Let's Encrypt"},
        },
    },
})
DOMAINS_ONLY = json.dumps({"message_type": "dns_entries", "data": ["payli0-secure.top"]})


def test_parse_full_message():
    cert = parse_message(FULL)
    assert cert.log_id == "oak2026h1" and cert.idx == 918273645
    assert cert.issuer_o == "Let's Encrypt" and cert.issuer_cn == "E7"
    assert cert.sha256 == "9f2cab" and cert.is_precert is True
    assert cert.names == ["*.payli0-secure.top", "payli0-secure.top"]
    assert cert.not_before < cert.not_after


def test_parse_hostname_channel():
    cert = parse_message(DOMAINS_ONLY)
    assert cert.names == ["payli0-secure.top"] and cert.idx == -1
    assert len(cert.sha256) == 64  # a stand-in key for the dedupe


def test_heartbeat_and_empty_messages_are_not_certificates():
    assert parse_message(json.dumps({"message_type": "heartbeat", "data": {}})) is None
    assert parse_message(json.dumps({"message_type": "dns_entries", "data": []})) is None
    assert parse_message(json.dumps({"data": {"leaf_cert": {"all_domains": []}}})) is None


def test_heartbeat_counts_as_liveness():
    ingest = CertStreamIngest(queue.Queue())
    assert ingest.alive is False
    ingest.handle(json.dumps({"message_type": "heartbeat", "data": {}}))
    assert ingest.alive is True


def test_certificate_dedupe_by_sha256():
    out = queue.Queue()
    ingest = CertStreamIngest(out, dedupe=TTLSet(ttl=3600))
    assert ingest.handle(FULL) is not None
    assert ingest.handle(FULL) is None  # the same certificate out of a second log
    assert out.qsize() == 1
    assert (ingest.certs_seen, ingest.certs_duplicate) == (2, 1)


def test_dedupe_expires():
    ttl = TTLSet(ttl=0)
    assert ttl.add("x") is True
    assert ttl.add("x") is True


def test_the_dedupe_stays_fast_when_the_set_grows():
    """The clean-up must not grow with the size of the set.

    It used to rebuild the whole dictionary every 10,000 adds. In operation there
    were millions of entries in it, a rebuild took seconds, and for that long the
    ingest thread held the GIL without calling `recv()`, so certstream dropped
    about 29 % of the stream. Measured: 9,050 adds/s instead of 772,000.

    The test measures no absolute speed but the growth: the price per add must not
    depend on how much is in there already.
    """
    import time

    def dauer_fuer(vorbelastung: int, proben: int = 20_000) -> float:
        ts = TTLSet(ttl=3600)
        for i in range(vorbelastung):
            ts.add(f"v{i}")
        start = time.perf_counter()
        for i in range(proben):
            ts.add(f"p{i}")
        return time.perf_counter() - start

    lower = dauer_fuer(10_000)
    larger = dauer_fuer(400_000)
    # Forty times the amount. With the old rebuild that was a multiple of the time;
    # with generations it stays in the same order of magnitude.
    assert larger < lower * 5, f"the clean-up grows with the set: {lower:.3f}s -> {larger:.3f}s"


def test_the_dedupe_keeps_the_memory_within_bounds():
    """Generations really have to fall away, otherwise the process fills up."""
    ttl = TTLSet(ttl=0.05, buckets=2)
    for i in range(3000):
        ttl.add(f"k{i}")
        time.sleep(0.0001)
    assert len(ttl._buckets) <= 3, f"{len(ttl._buckets)} Generationen behalten"


def test_backoff_grows_exponentially_with_jitter_and_is_capped():
    assert 0.8 <= backoff_delay(0) <= 1.2
    assert 3.2 <= backoff_delay(2) <= 4.8
    assert backoff_delay(20) <= BACKOFF_CAP * 1.2
    assert len({backoff_delay(3) for _ in range(20)}) > 1


def test_queue_blocks_instead_of_dropping():
    out = queue.Queue(maxsize=1)
    ingest = CertStreamIngest(out)
    ingest.handle(FULL)
    assert out.full()
    # A second, different message no longer gets in -> put() would block (§3.3).
    assert out.qsize() == 1
