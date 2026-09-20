from pathlib import Path


def test_firewall_precedes_sysctl_and_network():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "Before=systemd-sysctl.service network-pre.target NetworkManager.service" in text
    assert "DefaultDependencies=no" in text


def test_enabling_firewall_makes_network_manager_require_it():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "RequiredBy=NetworkManager.service" in text


def test_tor_requires_firewall():
    text = Path("systemd/tor-amnesic-pi.conf").read_text()
    assert "Requires=amnesic-pi-firewall.service" in text
    assert "After=amnesic-pi-firewall.service" in text


def test_stage1_keeps_ipv4_forwarding_disabled():
    text = Path("config/99-amnesic-pi.conf").read_text()
    assert "net.ipv4.ip_forward = 0" in text
    assert "net.ipv4.ip_forward = 1" not in text
