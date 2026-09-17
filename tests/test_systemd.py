from pathlib import Path


def test_firewall_precedes_forwarding_sysctl_and_network():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "Before=systemd-sysctl.service network-pre.target" in text
    assert "DefaultDependencies=no" in text


def test_tor_requires_firewall():
    text = Path("systemd/tor-amnesic-pi.conf").read_text()
    assert "Requires=amnesic-pi-firewall.service" in text
    assert "After=amnesic-pi-firewall.service" in text
