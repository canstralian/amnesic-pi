from pathlib import Path

import pytest

from amnesic_pi.config import Config, ConfigError, load_env


def test_valid_config():
    cfg = Config("eth0", "eth1")
    cfg.validate()


def test_interfaces_must_be_distinct():
    with pytest.raises(ConfigError):
        Config("eth0", "eth0").validate()


def test_reject_shell_metacharacters_in_interface():
    with pytest.raises(ConfigError):
        Config("eth0;reboot", "eth1").validate()


def test_load_rejects_unknown_key(tmp_path: Path):
    p = tmp_path / "network.env"
    p.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\nSURPRISE=yes\n")
    with pytest.raises(ConfigError):
        load_env(p)


def test_sysctl_file_does_not_set_ip_forward_unconditionally():
    # ip_forward must only ever be enabled by amnesic-pi apply-firewall after
    # its nftables transaction succeeds, never unconditionally by
    # systemd-sysctl.service at boot regardless of firewall outcome.
    text = Path("config/99-amnesic-pi.conf").read_text()
    assert "net.ipv4.ip_forward =" not in text


def test_sysctl_file_still_disables_ipv6():
    text = Path("config/99-amnesic-pi.conf").read_text()
    assert "net.ipv6.conf.all.disable_ipv6 = 1" in text
    assert "net.ipv6.conf.default.disable_ipv6 = 1" in text
