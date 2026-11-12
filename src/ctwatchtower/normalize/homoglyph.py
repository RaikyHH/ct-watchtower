"""Homoglyph skeleton (§4.3): Unicode confusables plus an ASCII table."""

import re
import unicodedata
from functools import lru_cache

from ctwatchtower.config import settings

# §4.3. The usual mix-ups the Unicode table does not cover.
_ASCII_MULTI = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"), ("nn", "m")]
_ASCII_SINGLE = str.maketrans({"0": "o", "1": "l", "5": "s", "3": "e", "4": "a", "7": "t", "8": "b"})

_LINE = re.compile(r"^([0-9A-F ]+?)\s*;\s*([0-9A-F ]+?)\s*;\s*MA", re.MULTILINE)


@lru_cache(maxsize=1)
def confusables() -> dict[str, str]:
    """Source code point -> prototype, from the bundled Unicode table.

    Only entries with a single source character; multi-character sources do not
    appear in the table, the check is pure caution.
    """
    text = settings.confusables_path.read_text(encoding="utf-8-sig")
    table: dict[str, str] = {}
    for src, dst in _LINE.findall(text):
        src_cps = src.split()
        if len(src_cps) != 1:
            continue
        source = chr(int(src_cps[0], 16))
        target = "".join(chr(int(cp, 16)) for cp in dst.split())
        if source != target:
            table[source] = target
    return table


def skeleton(name: str) -> str:
    """Homoglyph-normalised form. Order: Unicode first, then the ASCII table."""
    table = confusables()
    mapped = "".join(table.get(ch, ch) for ch in unicodedata.normalize("NFD", name))
    out = unicodedata.normalize("NFD", mapped).casefold()
    # Drop combining marks: they do not tell two skeletons apart in any useful way.
    out = "".join(ch for ch in out if not unicodedata.combining(ch))
    for a, b in _ASCII_MULTI:
        out = out.replace(a, b)
    return out.translate(_ASCII_SINGLE)


if __name__ == "__main__":
    assert skeleton("pаyli0.com") == "paylio.com", skeleton("pаyli0.com")
    assert skeleton("rnodel.de") == "model.de"
    assert skeleton("VantaBank.COM") == "vantabank.com"
    print("ok", len(confusables()), "entries")
