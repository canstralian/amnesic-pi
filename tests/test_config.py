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


def test_mac_ifaces_default_to_both_role_interfaces():
    """Randomizing nothing would silently weaken the anonymity gate."""
    assert Config("eth0", "eth1").resolved_mac_ifaces() == ("eth0", "eth1")


def test_mac_ifaces_can_be_named_explicitly(tmp_path: Path):
    p = tmp_path / "network.env"
    p.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\nMAC_IFACES=eth0, eth1\n")
    assert load_env(p).resolved_mac_ifaces() == ("eth0", "eth1")


def test_mac_ifaces_reject_invalid_names(tmp_path: Path):
    p = tmp_path / "network.env"
    p.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\nMAC_IFACES=eth0;reboot\n")
    with pytest.raises(ConfigError):
        load_env(p)


def test_interface_wait_is_bounded(tmp_path: Path):
    """The enumeration retry is a budget, not an unbounded wait."""
    for value in ("0", "-1", "600"):
        p = tmp_path / f"wait-{value}.env"
        p.write_text(f"UPLINK_IF=eth0\nCLIENT_IF=eth1\nIFACE_WAIT_SECONDS={value}\n")
        with pytest.raises(ConfigError):
            load_env(p)


def test_probe_hostnames_are_validated(tmp_path: Path):
    """Probe targets reach a resolver and a SOCKS request; they are never shell."""
    p = tmp_path / "network.env"
    p.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\nTOR_PROBE_HOST=evil host; rm -rf /\n")
    with pytest.raises(ConfigError):
        load_env(p)


def test_egress_telemetry_is_off_unless_configured():
    assert Config("eth0", "eth1").egress_echo_host == ""
