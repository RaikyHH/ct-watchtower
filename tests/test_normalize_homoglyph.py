from ctwatchtower.normalize.homoglyph import skeleton


def test_cyrillic_and_digit_lookalikes_collapse_to_the_brand():
    assert skeleton("pаyli0.com") == "paylio.com"
    assert skeleton("VANTABANK.COM") == "vantabank.com"


def test_ascii_multigraphs():
    assert skeleton("rnodel.de") == "model.de"
    assert skeleton("vvallet.io") == "wallet.io"
    assert skeleton("clns.net") == "dns.net"


def test_digit_table():
    assert skeleton("v4nt4b4nk.de") == "vantabank.de"
    # §4.3 maps `1` onto `l`, not onto `i`. Both forms collapse onto the same skeleton.
    assert skeleton("1og1n.de") == skeleton("logln.de") == "logln.de"
    assert skeleton("v4nta-8ank.de") == "vanta-bank.de"


def test_idempotent_on_plain_ascii():
    assert skeleton("example.com") == "example.com"
