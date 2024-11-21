import pytest

from utils.utils import refang_text, is_really_ipv6, identify_observable_type, extract_observables

def test_refang_text():
    text = "hxxps://example[.]com"
    expected = "https://example.com"
    result = refang_text(text)
    assert result == expected

    text = "example[.]com"
    expected = "example.com"
    result = refang_text(text)
    assert result == expected

    text = "toto[@]toto[.]com"
    expected = "toto@toto.com"
    result = refang_text(text)
    assert result == expected

def test_is_really_ipv6():
    ipv6_address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert is_really_ipv6(ipv6_address)

    ipv4_address = "192.168.0.1"
    assert not is_really_ipv6(ipv4_address)

    invalid_ipv6_address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    assert not is_really_ipv6(invalid_ipv6_address)

def test_identify_observable_type():
    # sample URL
    observable = "http://example.com"
    expected = "URL"
    result = identify_observable_type(observable)
    assert result == expected

    # sample IPv6
    observable = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    expected = "IPv6"
    result = identify_observable_type(observable)
    assert result == expected

    # sample IPv4
    observable = "8.8.8.8"
    expected = "IPv4"
    result = identify_observable_type(observable)
    assert result == expected

    # sample FQDN
    observable = "example.com"
    expected = "FQDN"
    result = identify_observable_type(observable)
    assert result == expected

    # sample hash md5
    observable = "d41d8cd98f00b204e9800998ecf8427e"
    expected = "MD5"
    result = identify_observable_type(observable)
    assert result == expected

    # sample hash sha1
    observable = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    expected = "SHA1"
    result = identify_observable_type(observable)
    assert result == expected

    # sample hash sha256
    observable = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    expected = "SHA256"
    result = identify_observable_type(observable)
    assert result == expected

def test_extract_observables():
    text = "http://example.com oui non pas vraiment 1.1.1.1"
    expected = [{'value': 'http://example.com', 'type': 'URL'}, {'value': '1.1.1.1', 'type': 'IPv4'}]
    result = extract_observables(text)
    assert all(any(item == expected_item for item in result) for expected_item in expected)