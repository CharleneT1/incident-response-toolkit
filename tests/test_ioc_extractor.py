"""Tests for ioc_extractor."""

import ioc_extractor


def test_extracts_public_ipv4_excludes_private():
    iocs = ioc_extractor.extract_iocs("attacker 203.0.113.42 internal 10.0.0.5")
    assert "203.0.113.42" in iocs["ipv4"]
    assert "10.0.0.5" not in iocs.get("ipv4", [])


def test_include_private_when_requested():
    iocs = ioc_extractor.extract_iocs("internal 10.0.0.5", exclude_private=False)
    assert "10.0.0.5" in iocs["ipv4"]


def test_hash_lengths_not_confused():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = ioc_extractor.extract_iocs(f"{md5} {sha256}")
    assert md5 in iocs["md5"]
    assert sha256 in iocs["sha256"]
    # The SHA256 must not be mis-split into an MD5.
    assert md5 != sha256
    assert sha256 not in iocs.get("md5", [])


def test_url_and_domain():
    iocs = ioc_extractor.extract_iocs("visit https://c2.evil.xyz/login now")
    assert any("c2.evil.xyz" in u for u in iocs["url"])


def test_misp_event_envelope():
    iocs = ioc_extractor.extract_iocs("203.0.113.42")
    event = ioc_extractor.to_misp_event(iocs, source="unit-test")
    assert event["Event"]["Attribute"]
    assert event["Event"]["Attribute"][0]["type"] == "ip-dst"
