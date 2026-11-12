"""Typo permutations of an anchor term (dnstwist style, §5.2).

Runs once when a ruleset is loaded; the results end up in the prefilter automaton
(§4.2 stage 1) and in the anchor detector (strength 0.9).
"""

from __future__ import annotations

from collections.abc import Iterable

from ctwatchtower.rules.schema import MIN_TERM_LENGTH

# Deliberately simple: one keyboard layout is enough. QWERTZ and QWERTY differ only
# in y/z, and both neighbourhoods are in here.
KEYBOARD = {
    "a": "qwsyz",
    "b": "vghn",
    "c": "xdfv",
    "d": "serfcx",
    "e": "wsdr",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gzujnb",
    "i": "ujko",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedyx",
    "t": "rfgz",
    "u": "zhji",
    "v": "cfgb",
    "w": "qase",
    "x": "ysdc",
    "y": "asxt",
    "z": "tghu",
    "0": "o9",
    "1": "l2",
    "3": "e4",
    "4": "a5",
    "5": "s6",
    "7": "t8",
    "8": "b9",
}

VOWELS = "aeiou"

# Digit/letter mix-ups attackers actually use (§4.3).
LOOKALIKE = {"o": "0", "l": "1", "i": "1", "s": "5", "e": "3", "a": "4", "t": "7", "b": "8", "g": "9"}

COMMON_TLDS = (
    "com", "net", "org", "de", "eu", "info", "biz", "shop", "online", "site",
    "top", "xyz", "cc", "co", "app", "io",
)


def _omission(t: str) -> set[str]:
    return {t[:i] + t[i + 1 :] for i in range(len(t))}


def _insertion(t: str) -> set[str]:
    return {
        t[:i] + c + t[i:]
        for i in range(len(t) + 1)
        for c in KEYBOARD.get(t[i - 1] if i else t[0], "")
    }


def _transposition(t: str) -> set[str]:
    return {t[:i] + t[i + 1] + t[i] + t[i + 2 :] for i in range(len(t) - 1) if t[i] != t[i + 1]}


def _replacement(t: str) -> set[str]:
    out = {t[:i] + c + t[i + 1 :] for i, ch in enumerate(t) for c in KEYBOARD.get(ch, "")}
    # Digit substitution belongs to practically the same class (paypa1, sparkass3)
    out |= {t[:i] + LOOKALIKE[ch] + t[i + 1 :] for i, ch in enumerate(t) if ch in LOOKALIKE}
    return out


def _hyphenation(t: str) -> set[str]:
    return {t[:i] + "-" + t[i:] for i in range(1, len(t)) if "-" not in (t[i - 1], t[i])}


def _bitsquatting(t: str) -> set[str]:
    out = set()
    for i, ch in enumerate(t):
        for bit in range(8):
            c = chr(ord(ch) ^ (1 << bit))
            if c.isalnum() and c.isascii() and c != ch:
                out.add(t[:i] + c.lower() + t[i + 1 :])
    return out


def _vowel_swap(t: str) -> set[str]:
    return {t[:i] + v + t[i + 1 :] for i, ch in enumerate(t) if ch in VOWELS for v in VOWELS if v != ch}


def _repetition(t: str) -> set[str]:
    return {t[:i] + ch + t[i:] for i, ch in enumerate(t) if ch.isalnum()}


def _double_char(t: str) -> set[str]:
    """Fold a doubled character back into one (`payllio` -> `paylio`)."""
    return {t[:i] + t[i + 1 :] for i in range(len(t) - 1) if t[i] == t[i + 1]}


def _tld_swap(t: str) -> set[str]:
    if "." not in t:
        return set()
    stem, _, tld = t.rpartition(".")
    return {f"{stem}.{other}" for other in COMMON_TLDS if other != tld}


_GENERATORS = {
    "omission": _omission,
    "insertion": _insertion,
    "transposition": _transposition,
    "replacement": _replacement,
    "hyphenation": _hyphenation,
    "bitsquatting": _bitsquatting,
    "vowel_swap": _vowel_swap,
    "repetition": _repetition,
    "double_char": _double_char,
    "tld_swap": _tld_swap,
}


def permutations_for(term: str, kinds: Iterable[str], min_length: int = MIN_TERM_LENGTH) -> set[str]:
    """All variants of `term` for the requested classes, without the term itself.

    Terms below `min_length` get no variants, and variants below `min_length` are
    dropped: `ali`, `ald`, `tem` sit as a substring in every tenth hostname and
    would flood the prefilter through `all_prefilter_terms`.
    """
    term = term.strip().lower()
    if len(term) < min_length:
        return set()
    out: set[str] = set()
    for kind in kinds:
        gen = _GENERATORS.get(kind)
        if gen is not None:
            out |= gen(term)
    out.discard(term)
    return {v for v in out if len(v) >= min_length}
