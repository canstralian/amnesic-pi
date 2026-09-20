from pathlib import Path


def test_firewall_precedes_sysctl_and_network():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "Before=systemd-sysctl.service network-pre.target NetworkManager.service" in text
    assert "DefaultDependencies=no" in text
    assert "Wants=network-pre.target" in text


def test_enabling_firewall_makes_network_manager_require_it():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "RequiredBy=NetworkManager.service" in text


def test_firewall_is_verified_before_ordered_dependents_start():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "ExecStartPost=/usr/local/bin/amnesic-pi verify-firewall" in text


def test_firewall_failure_is_console_visible_and_manual_stop_is_refused():
    firewall = Path("systemd/amnesic-pi-firewall.service").read_text()
    failure = Path("systemd/amnesic-pi-firewall-failure.service").read_text()
    assert "OnFailure=amnesic-pi-firewall-failure.service" in firewall
    assert "RefuseManualStop=yes" in firewall
    assert "StandardOutput=journal+console" in failure


def test_firewall_unit_has_no_condition_skip():
    text = Path("systemd/amnesic-pi-firewall.service").read_text()
    assert "Condition" not in text


def test_tor_requires_firewall():
    text = Path("systemd/tor-amnesic-pi.conf").read_text()
    assert "Requires=amnesic-pi-firewall.service" in text
    assert "After=amnesic-pi-firewall.service" in text


def test_stage1_forwarding_policy_is_explicit():
    text = Path("config/99-amnesic-pi.conf").read_text()
    assert "net.ipv4.ip_forward = 1" in text
    assert "net.ipv6.conf.all.forwarding = 0" in text


def test_provisioner_installs_failure_reporter():
    text = Path("image/provision.sh").read_text()
    assert "amnesic-pi-firewall-failure.service" in text
