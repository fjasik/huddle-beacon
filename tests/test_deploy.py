import importlib.util
from pathlib import Path

from beacon.__main__ import keygen
from beacon.config import Config, ports, render
from beacon.trust.certs import read_key

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def load_tool(name: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_keygen_makes_the_key_once(tmp_path: Path) -> None:
    path = tmp_path / "etc" / "beacon.key"
    pub = keygen(path)
    assert keygen(path) == pub == read_key(path).pub.hex()


def test_rendered_config_loads_back(tmp_path: Path) -> None:
    path = tmp_path / "node.toml"
    path.write_text(
        render(
            {
                "beacon_id": 2,
                "venue_id": 3,
                **ports(2),
                "data_dir": "d",
                "key_file": "k",
                "cert_file": "c",
                "compact_cert_file": "cc",
                "ca_file": "ca",
                "venue_pub_file": "v",
                "peers": ["https://a:1"],
                "mdns": True,
                "gossip_interval_s": 0.5,
            }
        ),
        encoding="utf-8",
    )
    config = Config.load(path)
    assert (config.port, config.dev_port, config.phone_port) == (8442, 8542, 8642)
    assert config.peers == ["https://a:1"] and config.mdns and config.gossip_interval_s == 0.5
    assert config.data_dir == tmp_path / "d"


def test_pi_config_listens_on_the_network_and_uses_absolute_paths(tmp_path: Path) -> None:
    provision = load_tool("provision")
    values = provision.beacon_config(3, 1, "192.168.0.69", ["https://192.168.0.100:8441"], False)
    path = tmp_path / "beacon.toml"
    path.write_text(render(values), encoding="utf-8")
    config = Config.load(path)
    assert config.advertise_url == "https://192.168.0.69:8443"
    assert (config.host, config.phone_host, config.phone_port) == ("0.0.0.0", "0.0.0.0", 8643)
    assert config.key_file.as_posix().endswith("/etc/huddle-beacon/beacon.key")
    assert config.data_dir.as_posix().endswith("/var/lib/huddle-beacon")
