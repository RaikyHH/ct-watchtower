from ctwatchtower.normalize.names import normalize


def test_wildcard_trailing_dot_and_case():
    c = normalize("  *.Shop.Example.COM.  ")
    assert c is not None
    assert c.wildcard is True
    assert c.name == "shop.example.com"
    assert c.labels == ["shop", "example", "com"]
    assert (c.registrable, c.subdomain, c.tld) == ("example.com", "shop", "com")


def test_multi_level_wildcard():
    c = normalize("*.*.example.de")
    assert c is not None and c.wildcard is True and c.name == "example.de"


def test_psl_two_label_suffix():
    c = normalize("login.bank.co.uk")
    assert c is not None
    assert (c.registrable, c.subdomain, c.tld) == ("bank.co.uk", "login", "co.uk")


def test_psl_icann_only_for_cloud_hosts():
    c = normalize("s3.vendoraaws.com")
    assert c is not None
    assert (c.registrable, c.subdomain) == ("vendoraaws.com", "s3")


def test_idn_a_label_input_keeps_both_forms():
    c = normalize("xn--pylio-4ve.com")  # pаylio with a Cyrillic a
    assert c is not None
    assert c.is_idn is True
    assert c.ascii == "xn--pylio-4ve.com"
    assert c.unicode == "pаylio.com"
    assert c.skeleton == "paylio.com"


def test_idn_u_label_input_is_encoded():
    c = normalize("pаylio.com")
    assert c is not None
    assert c.is_idn is True
    assert c.ascii.startswith("xn--")
    assert c.unicode == "pаylio.com"


def test_invalid_names_are_discarded():
    for bad in ["", "   ", "localhost", "intern", "10.0.0.1", "[2001:db8::1]", "co.uk", "foo.invalidtld"]:
        assert normalize(bad) is None, bad


def test_prefilter_hits_start_empty():
    c = normalize("example.com")
    assert c is not None and c.prefilter_hits == []
