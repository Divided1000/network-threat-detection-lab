"""Shared pytest fixtures: build the dataset once in memory for all tests."""
import sys
from pathlib import Path

import pytest

# make src/ importable without installing the package
SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from nethunt.generate import build_world, write_logs  # noqa: E402
from nethunt.ingest import load_all  # noqa: E402
from nethunt.baseline import build_host_baseline  # noqa: E402
from nethunt.intel import load_intel  # noqa: E402

# Ground-truth attacker hosts, matched to the injectors in generate.py.
GROUND_TRUTH = {
    "beaconing": "10.10.0.22",
    "dns_tunnel": "10.10.0.31",
    "exfil_volume": "10.10.0.18",
    "port_scan": "10.10.0.27",
    "lateral_movement": "10.10.0.14",
    "ioc_contact": "10.10.0.19",
}


@pytest.fixture(scope="session")
def dataset(tmp_path_factory):
    """Generate the seeded dataset to a temp dir and load normalized frames."""
    out = tmp_path_factory.mktemp("data")
    world, attackers = build_world(seed=1337)
    write_logs(world, out)
    data = load_all(out)
    feed = load_intel(Path(__file__).resolve().parents[1] / "data" / "intel_feed.json")
    baseline = build_host_baseline(data["conn"], data["dns"])
    return {
        "data": data,
        "baseline": baseline,
        "feed": feed,
        "attackers": attackers,
    }


@pytest.fixture(scope="session")
def conn(dataset):
    return dataset["data"]["conn"]


@pytest.fixture(scope="session")
def dns(dataset):
    return dataset["data"]["dns"]


@pytest.fixture(scope="session")
def baseline(dataset):
    return dataset["baseline"]


@pytest.fixture(scope="session")
def feed(dataset):
    return dataset["feed"]
