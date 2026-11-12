"""Read the four fields out of an X.509 certificate that revocation lists address.

OneCRL names a revoked certificate in two ways:

    issuerName + serialNumber   the issuer name (DER) and the serial number
    subject    + pubKeyHash     the subject name (DER) and SHA-256 over the
                                SubjectPublicKeyInfo

Both sit in the certificate, and both can be had without a crypto library: it is a
walk over the DER structure, no maths. `cryptography` would be a heavy dependency
for that. Rust toolchain, big wheel, upkeep of its own, for something that is sixty
lines here.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    TBSCertificate ::= SEQUENCE {
        version         [0] EXPLICIT  -- optional
        serialNumber    INTEGER
        signature       AlgorithmIdentifier
        issuer          Name
        validity        SEQUENCE
        subject         Name
        subjectPublicKeyInfo SEQUENCE
        ... }

Reading only. Nothing here interprets OIDs, checks signatures or makes a trust
decision. This file is the wrong place for that.
"""

from __future__ import annotations

import hashlib


class DerError(ValueError):
    """The bytes are not a usable certificate."""


def _header(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read one TLV at `pos`. Returns (tag, start of the content, end)."""
    if pos + 2 > len(data):
        raise DerError("ends early")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise DerError(f"unusable length ({count} bytes)")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise DerError("length points past the end")
    return tag, pos, end


def _elements(data: bytes, start: int, stop: int):
    """The TLVs of a sequence in order, each as (tag, raw, content)."""
    pos = start
    while pos < stop:
        tag, content, end = _header(data, pos)
        yield tag, data[pos:end], data[content:end]
        pos = end


SEQUENCE = 0x30
INTEGER = 0x02
VERSION = 0xA0  # [0] EXPLICIT, context-specific constructed


def fields(der: bytes) -> dict[str, bytes]:
    """`serial`, `issuer`, `subject` and `spki` as raw DER bytes.

    `issuer` and `subject` come back **including** their SEQUENCE header, exactly
    the way OneCRL base64-encodes them. The same goes for `spki`.
    """
    tag, content, end = _header(der, 0)
    if tag != SEQUENCE:
        raise DerError("not a Certificate (outer SEQUENCE missing)")
    tag, tbs_content, tbs_end = _header(der, content)
    if tag != SEQUENCE:
        raise DerError("not a TBSCertificate")

    parts = list(_elements(der, tbs_content, tbs_end))
    if not parts:
        raise DerError("empty TBSCertificate")

    # The version is optional. Without it everything shifts one place forward.
    i = 1 if parts[0][0] == VERSION else 0
    needed = i + 6  # serial, sigAlg, issuer, validity, subject, spki
    if len(parts) < needed:
        raise DerError(f"too few fields in the TBSCertificate ({len(parts)})")

    if parts[i][0] != INTEGER:
        raise DerError("serial number is not an INTEGER")
    return {
        "serial": parts[i][2],          # content without header: that is how OneCRL counts
        "issuer": parts[i + 2][1],      # with header
        "subject": parts[i + 4][1],     # with header
        "spki": parts[i + 5][1],        # with header
    }


def spki_hash(der: bytes) -> bytes:
    """SHA-256 over the SubjectPublicKeyInfo, what OneCRL calls `pubKeyHash`."""
    return hashlib.sha256(fields(der)["spki"]).digest()


def demo() -> None:
    """Self-check against a minimal certificate built by hand.

    The real proof was run against real certificates from the CT stream: there it
    was cross-checked that SHA-256 over the bytes we read gives the same thing
    certstream itself reports.
    """
    def tlv(tag: int, content: bytes) -> bytes:
        if len(content) < 0x80:
            return bytes([tag, len(content)]) + content
        length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(length)]) + length + content

    issuer = tlv(SEQUENCE, b"ISSUER")
    subject = tlv(SEQUENCE, b"SUBJECT")
    spki = tlv(SEQUENCE, b"PUBLICKEY")
    tbs = tlv(SEQUENCE,
              tlv(VERSION, tlv(INTEGER, b"\x02"))     # version v3
              + tlv(INTEGER, b"\x12\x34")             # serial
              + tlv(SEQUENCE, b"ALG")                  # signature
              + issuer
              + tlv(SEQUENCE, b"VALID")                # validity
              + subject
              + spki)
    cert = tlv(SEQUENCE, tbs + tlv(SEQUENCE, b"ALG") + tlv(0x03, b"\x00SIG"))

    f = fields(cert)
    assert f["serial"] == b"\x12\x34", f["serial"]
    assert f["issuer"] == issuer, "issuer with header"
    assert f["subject"] == subject, "subject with header"
    assert f["spki"] == spki, "SubjectPublicKeyInfo with header"
    assert spki_hash(cert) == hashlib.sha256(spki).digest()

    # Without a version everything shifts forward, the more common v1 case.
    tbs1 = tlv(SEQUENCE, tlv(INTEGER, b"\x07") + tlv(SEQUENCE, b"ALG")
               + issuer + tlv(SEQUENCE, b"VALID") + subject + spki)
    assert fields(tlv(SEQUENCE, tbs1 + tlv(SEQUENCE, b"ALG")))["serial"] == b"\x07"

    # Multi-byte lengths (real certificates are always over 127 bytes).
    big = tlv(SEQUENCE, b"X" * 300)
    tag, start, stop = _header(big, 0)
    assert stop - start == 300, (start, stop)

    for broken in (b"", b"\x30", b"\x30\x05ab", b"\x02\x01\x00"):
        try:
            fields(broken)
        except DerError:
            pass
        else:
            raise AssertionError(f"{broken!r} should have been caught")
    print("ok")


if __name__ == "__main__":
    demo()


# The text types in a Name: PrintableString, UTF8String, IA5String, T61String,
# BMPString. Nothing more is needed. This reads, it does not validate.
_TEXT_TAGS = {0x13, 0x0C, 0x16, 0x14, 0x1E}


def readable(name_der: bytes) -> str:
    """An issuer or subject name as text, for the display.

    Without an OID table: the text parts are collected in the order they appear.
    The DER of `/C=NL/O=eMudhra BV/CN=EM DV TLS CA - G3B` becomes
    `NL, eMudhra BV, EM DV TLS CA - G3B`. Good enough for one line in the UI;
    whoever needs the exact DN has the bytes next to it.
    """
    parts: list[str] = []

    def walk(data: bytes, start: int, stop: int, depth: int = 0) -> None:
        if depth > 6:
            return
        pos = start
        while pos < stop:
            try:
                tag, content, end = _header(data, pos)
            except DerError:
                return
            if tag in _TEXT_TAGS:
                raw = data[content:end]
                encoding = "utf-16-be" if tag == 0x1E else "utf-8"
                text = raw.decode(encoding, errors="replace").strip()
                if text:
                    parts.append(text)
            elif tag & 0x20:  # constructed: go in
                walk(data, content, end, depth + 1)
            pos = end

    try:
        tag, content, end = _header(name_der, 0)
    except DerError:
        return ""
    walk(name_der, content, end)
    return ", ".join(parts)
