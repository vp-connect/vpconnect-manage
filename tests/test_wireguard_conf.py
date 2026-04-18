"""Разбор и запись wg0.conf (wireguard_conf)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from manage_site import wireguard_conf


def test_logical_config_line_strips_comment_prefix():
    assert wireguard_conf.logical_config_line("#  PublicKey = abc") == "PublicKey = abc"
    assert wireguard_conf.logical_config_line("  # # Address = 1.2.3.4/24") == "Address = 1.2.3.4/24"


def test_peer_enabled_respects_comments():
    assert wireguard_conf.peer_enabled(["# foo", ""]) is False
    assert wireguard_conf.peer_enabled(["# foo", "PublicKey = x"]) is True


def test_parse_peer_public_key_and_tunnel_ip():
    body = [
        "PublicKey = AbCdEf==",
        "# note: PublicKey = would-be-ignored-if-first",
        "AllowedIPs = 10.8.0.5/32",
    ]
    assert wireguard_conf.parse_peer_public_key(body) == "AbCdEf=="
    assert wireguard_conf.parse_peer_tunnel_ip(body) == "10.8.0.5"


def test_parse_wg_conf_no_file(tmp_path: Path):
    missing = tmp_path / "missing.conf"
    assert wireguard_conf.parse_wg_conf(missing) == ([], [])


def test_parse_wg_conf_no_markers(tmp_path: Path):
    p = tmp_path / "wg.conf"
    p.write_text("[Interface]\nPrivateKey = x\n", encoding="utf-8")
    preamble, peers = wireguard_conf.parse_wg_conf(p)
    assert peers == []
    assert "[Interface]" in "".join(preamble)


def test_parse_wg_conf_with_peers(tmp_path: Path):
    p = tmp_path / "wg.conf"
    p.write_text(
        "[Interface]\nAddress = 10.8.0.1/24\n\n"
        "# Client: c1\n"
        "[Peer]\nPublicKey = pk1\nAllowedIPs = 10.8.0.2/32\n\n"
        "# Client: c2\n"
        "[Peer]\nPublicKey = pk2\nAllowedIPs = 10.8.0.3/32\n",
        encoding="utf-8",
    )
    preamble, peers = wireguard_conf.parse_wg_conf(p)
    assert len(peers) == 2
    assert peers[0].name == "c1"
    assert wireguard_conf.parse_peer_tunnel_ip(peers[0].body_lines) == "10.8.0.2"


def test_server_subnet_prefix_from_conf(tmp_path: Path):
    p = tmp_path / "wg.conf"
    p.write_text(
        "[Interface]\nAddress = 10.8.0.1/24\n\n# Client: x\n[Peer]\n",
        encoding="utf-8",
    )
    assert wireguard_conf.server_subnet_prefix_from_conf(p) == "10.8.0."


def test_server_subnet_prefix_from_conf_raises(tmp_path: Path):
    p = tmp_path / "wg.conf"
    p.write_text("[Interface]\nListenPort = 51820\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        wireguard_conf.server_subnet_prefix_from_conf(p)


@pytest.mark.parametrize(
    "cidr,expected",
    [
        ("10.8.0.1/24", "10.8.0."),
        ("10.8.0.0/24", "10.8.0."),
    ],
)
def test_subnet_prefix_from_network_cidr_ok(cidr: str, expected: str):
    assert wireguard_conf.subnet_prefix_from_network_cidr(cidr) == expected


@pytest.mark.parametrize(
    "cidr",
    ["", "not-a-cidr", "10.8.0.1/25", "10.8/24"],
)
def test_subnet_prefix_from_network_cidr_bad(cidr: str):
    with pytest.raises(ValueError):
        wireguard_conf.subnet_prefix_from_network_cidr(cidr)


def test_format_wg_conf_roundtrip(tmp_path: Path):
    p = tmp_path / "wg.conf"
    text = (
        "[Interface]\nAddress = 10.8.0.1/24\n\n"
        "# Client: a\n[Peer]\nPublicKey = k\nAllowedIPs = 10.8.0.2/32\n"
    )
    p.write_text(text, encoding="utf-8")
    preamble, peers = wireguard_conf.parse_wg_conf(p)
    out = wireguard_conf.format_wg_conf(preamble, peers)
    p2 = tmp_path / "out.conf"
    p2.write_text(out, encoding="utf-8")
    preamble2, peers2 = wireguard_conf.parse_wg_conf(p2)
    assert len(peers2) == len(peers)


def test_append_remove_peer(tmp_path: Path):
    p = tmp_path / "wg.conf"
    p.write_text("[Interface]\nAddress = 10.8.0.1/24\n", encoding="utf-8")
    wireguard_conf.append_peer(p, "u1", "PUBKEY1", "10.8.0.2")
    peers = wireguard_conf.list_peers_from_conf(p)
    assert len(peers) == 1
    assert wireguard_conf.remove_peer(p, "u1") is True
    assert wireguard_conf.remove_peer(p, "u1") is False


def test_set_peer_block_enabled_toggle(tmp_path: Path):
    p = tmp_path / "wg.conf"
    p.write_text("[Interface]\nAddress = 10.8.0.1/24\n", encoding="utf-8")
    wireguard_conf.append_peer(p, "u1", "PUBKEY1", "10.8.0.2")
    assert wireguard_conf.set_peer_block_enabled(p, "u1", False) is True
    peers = wireguard_conf.list_peers_from_conf(p)
    assert wireguard_conf.peer_enabled(peers[0].body_lines) is False
    assert wireguard_conf.set_peer_block_enabled(p, "u1", True) is True
    peers = wireguard_conf.list_peers_from_conf(p)
    assert wireguard_conf.peer_enabled(peers[0].body_lines) is True
    assert wireguard_conf.set_peer_block_enabled(p, "missing", True) is False


def test_collect_used_tunnel_ips_and_pick_free():
    p1 = wireguard_conf.WgPeerBlock(
        name="a",
        body_lines=["[Peer]", "PublicKey = x", "AllowedIPs = 10.8.0.2/32"],
    )
    p2 = wireguard_conf.WgPeerBlock(
        name="b",
        body_lines=["AllowedIPs = 10.8.0.3/32"],
    )
    used = wireguard_conf.collect_used_tunnel_ips([p1, p2])
    assert used == {"10.8.0.2", "10.8.0.3"}
    free = wireguard_conf.pick_free_tunnel_ip([p1, p2], "10.8.0.")
    assert free == "10.8.0.4"


def test_pick_free_tunnel_ip_exhausted():
    peers = [
        wireguard_conf.WgPeerBlock(
            name=f"n{i}",
            body_lines=[f"AllowedIPs = 10.8.0.{i}/32"],
        )
        for i in range(2, 255)
    ]
    with pytest.raises(RuntimeError):
        wireguard_conf.pick_free_tunnel_ip(peers, "10.8.0.")


def test_set_peer_enabled_lines():
    body = ["Foo", "# Bar"]
    disabled = wireguard_conf.set_peer_enabled(body, False)
    assert all(line.startswith("#") for line in disabled)
    enabled = wireguard_conf.set_peer_enabled(disabled, True)
    assert enabled[0] == "Foo"


def test_try_run_wg_syncconf_skips_nonstandard_path(tmp_path: Path):
    warnings: list[str] = []

    def logw(msg: str) -> None:
        warnings.append(msg)

    conf = tmp_path / "wg0.conf"
    conf.write_text("x", encoding="utf-8")
    wireguard_conf.try_run_wg_syncconf("wg0", conf, logw)
    assert warnings and "пропущен" in warnings[0]


@patch("manage_site.wireguard_conf.subprocess.run")
def test_try_run_wg_syncconf_invokes_subprocess_when_resolved_paths_match(mock_run: MagicMock):
    """Оба ``resolve()`` должны совпасть с ожидаемым путём wg-quick (заглушка)."""
    unified = Path("/etc/wireguard/wg0.conf")
    with patch.object(Path, "resolve", lambda self: unified):
        wireguard_conf.try_run_wg_syncconf("wg0", Path("/any/wg0.conf"), None)
    mock_run.assert_called_once()
