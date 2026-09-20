from pathlib import Path


def test_firewall_precedes_forwarding_sysctl_and_network():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "Before=systemd-sysctl.service network-pre.target" in text
    assert "DefaultDependencies=no" in text


def test_tor_requires_firewall():
    text = Path("systemd/tor-amnesic-pi.conf").read_text()
    assert "Requires=amnesic-pi-firewall.service" in text
    assert "After=amnesic-pi-firewall.service" in text


def test_network_manager_is_bound_to_firewall():
    # BindsTo, not Requires: a later firewall stop/crash must also stop
    # NetworkManager, not just block it from starting in the first place.
    text = Path("systemd/network-manager-amnesic-pi.conf").read_text()
    assert "BindsTo=amnesic-pi-firewall.service" in text
    assert "After=amnesic-pi-firewall.service" in text


def test_systemd_networkd_is_bound_to_firewall():
    text = Path("systemd/systemd-networkd-amnesic-pi.conf").read_text()
    assert "BindsTo=amnesic-pi-firewall.service" in text
    assert "After=amnesic-pi-firewall.service" in text


def test_provision_installs_both_network_manager_drop_ins():
    # Both are shipped unconditionally: a drop-in for a unit that is not
    # installed on a given image is simply never loaded by systemd, so this
    # does not require guessing which network stack the target OS uses.
    text = Path("image/provision.sh").read_text()
    assert "NetworkManager.service.d/10-amnesic-pi.conf" in text
    assert "systemd-networkd.service.d/10-amnesic-pi.conf" in text
