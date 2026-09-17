from pathlib import Path


def test_torrc_has_transparent_and_dns_ports():
    text = Path("config/torrc").read_text()
    assert "TransPort 0.0.0.0:9040" in text
    assert "DNSPort 0.0.0.0:5353" in text
    assert "SocksPort 127.0.0.1:9050" in text


def test_socks_listener_stays_host_local():
    text = Path("config/torrc").read_text()
    assert "0.0.0.0:9050" not in text


def test_transparent_listeners_are_not_loopback_only():
    text = Path("config/torrc").read_text()
    assert "TransPort 127.0.0.1:9040" not in text
    assert "DNSPort 127.0.0.1:5353" not in text
