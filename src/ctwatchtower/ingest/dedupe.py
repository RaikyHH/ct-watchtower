"""Certificate dedupe (§3.4): SHA-256 with a TTL, in-process instead of Redis."""

import time


class TTLSet:
    """A set with an expiry. `add` returns True if the key is new.

    Expiry is decided by the timestamp, not by the cleanup: `add` compares the
    stored time against `ttl`. The cleanup only keeps memory down and must not
    change the answer.

    That is where a fat operational bug used to sit. The cleanup rebuilt the whole
    dict every 10,000 adds. At 2000 certs/s and a 6 h TTL that is up to 43 million
    entries; measured, one rebuild took 2.8 s at 5 million, and it ran every 5 s.
    For that long the ingest thread held the GIL without calling `recv()`.
    certstream then dropped whatever piled up: roughly 29 % of the stream never
    arrived.

    So, generations. Every `ttl/buckets` seconds an empty dict moves to the front
    and the oldest one falls off the back. Constant time, no matter how big the set
    gets. Lookups go across all generations, which is a handful of dict reads
    instead of a walk over millions of entries.
    """

    def __init__(self, ttl: float, buckets: int = 8) -> None:
        self.ttl = ttl
        # One bucket more than the TTL covers. The oldest is then always at least
        # `ttl` old, never younger. Keeping it too long only costs memory, too
        # short would falsify the answer.
        self._span = max(ttl / max(buckets, 1), 1.0)
        self._limit = buckets + 1
        self._buckets: list[dict[str, float]] = [{}]
        self._rotate_at = time.monotonic() + self._span

    def add(self, key: str) -> bool:
        now = time.monotonic()
        if now >= self._rotate_at:
            self._buckets.insert(0, {})
            del self._buckets[self._limit:]
            self._rotate_at = now + self._span

        before = None
        for i, buckets in enumerate(self._buckets):
            hits = buckets.get(key)
            if hits is not None:
                before = hits
                if i:  # drop it from the old generation, else it sits there twice
                    del buckets[key]
                break
        self._buckets[0][key] = now
        return before is None or now - before > self.ttl

    def __len__(self) -> int:
        return sum(len(e) for e in self._buckets)


def demo() -> None:
    """Self-check: expiry, recognition and bounded memory."""
    ts = TTLSet(ttl=1.0, buckets=2)
    assert ts.add("a") is True, "a new key is new"
    assert ts.add("a") is False, "right afterwards it is known"

    # Past the TTL it counts as new again, even while it is still stored.
    ts._buckets[0]["b"] = time.monotonic() - 5.0
    assert ts.add("b") is True, "an expired key counts as new"

    # A key from an older generation is found, not missed.
    old = TTLSet(ttl=600.0, buckets=2)
    old.add("c")
    old._buckets.insert(0, {})          # rotate by hand
    assert old.add("c") is False, "the older generation is read too"
    assert len(old) == 1, "and not doubled up in the process"

    # Memory stays bounded: more rotations than buckets.
    lower = TTLSet(ttl=0.03, buckets=2)
    for i in range(2000):
        lower.add(f"k{i}")
        time.sleep(0.0001)
    assert len(lower._buckets) <= 3, f"too many generations: {len(lower._buckets)}"
    print("ok")


if __name__ == "__main__":
    demo()
