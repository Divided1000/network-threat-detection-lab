"""Synthetic Zeek-style network log generator.

Produces two Zeek-style TSV logs:
  - conn.log : connection summaries (one row per flow)
  - dns.log  : DNS queries

The data is split into:
  - BENIGN baseline traffic: a realistic mix of web browsing, SaaS, internal
    file share, and DNS lookups across a fleet of workstations. This is what the
    baseline engine learns "normal" from.
  - INJECTED attacks: six scenarios mapped to the detection catalog (D001-D006).

Everything is seeded, so regenerating produces identical data. That makes the
detections testable and the hunt notebook reproducible.

Usage:
    python -m nethunt.generate --out data/ [--seed 1337]
"""
from __future__ import annotations

import argparse
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Environment model
# ---------------------------------------------------------------------------

INTERNAL_SUBNET = "10.10.0."
WORKSTATIONS = [f"{INTERNAL_SUBNET}{i}" for i in range(10, 40)]  # 30 hosts
INTERNAL_SERVERS = {
    "10.10.0.5": "fileshare",
    "10.10.0.6": "intranet",
    "10.10.0.7": "dns",
}

# Common benign external destinations (web, SaaS, CDNs).
BENIGN_EXTERNAL = [
    ("140.82.112.3", "github.com"),
    ("142.250.80.46", "google.com"),
    ("13.107.42.14", "office.com"),
    ("151.101.1.69", "slack.com"),
    ("104.16.123.96", "cloudflare.com"),
    ("52.84.150.10", "aws.amazon.com"),
    ("31.13.66.35", "meta.com"),
]

BENIGN_TLDS = ["com", "net", "org", "io"]
BENIGN_WORDS = [
    "mail", "docs", "drive", "calendar", "cdn", "api", "static", "assets",
    "login", "portal", "update", "status", "img", "video", "chat",
]

SIM_START = datetime(2026, 10, 12, 0, 0, 0, tzinfo=timezone.utc)
SIM_HOURS = 24


@dataclass
class ConnRow:
    ts: float
    uid: str
    orig_h: str
    orig_p: int
    resp_h: str
    resp_p: int
    proto: str
    service: str
    duration: float
    orig_bytes: int
    resp_bytes: int
    conn_state: str

    def to_tsv(self) -> str:
        return "\t".join(
            str(x)
            for x in [
                f"{self.ts:.6f}",
                self.uid,
                self.orig_h,
                self.orig_p,
                self.resp_h,
                self.resp_p,
                self.proto,
                self.service,
                f"{self.duration:.3f}",
                self.orig_bytes,
                self.resp_bytes,
                self.conn_state,
            ]
        )


@dataclass
class DnsRow:
    ts: float
    uid: str
    orig_h: str
    resp_h: str
    query: str
    qtype: str
    answers: str

    def to_tsv(self) -> str:
        return "\t".join(
            str(x)
            for x in [
                f"{self.ts:.6f}",
                self.uid,
                self.orig_h,
                self.resp_h,
                self.query,
                self.qtype,
                self.answers,
            ]
        )


@dataclass
class World:
    rng: random.Random
    conns: list[ConnRow] = field(default_factory=list)
    dns: list[DnsRow] = field(default_factory=list)
    _uid: int = 0

    def uid(self) -> str:
        self._uid += 1
        return f"C{self._uid:08d}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(hour_offset: float) -> float:
    return (SIM_START + timedelta(hours=hour_offset)).timestamp()


def _rand_domain(rng: random.Random) -> str:
    word = rng.choice(BENIGN_WORDS)
    base = rng.choice([d for _, d in BENIGN_EXTERNAL])
    return f"{word}.{base}"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Benign baseline traffic
# ---------------------------------------------------------------------------

def gen_benign(world: World) -> None:
    """Realistic baseline: web, SaaS, internal file share, DNS.

    Each workstation makes a human-plausible number of connections spread
    across the day with jittered timing and lognormal-ish byte volumes.
    """
    rng = world.rng
    for host in WORKSTATIONS:
        n_conns = rng.randint(180, 320)
        for _ in range(n_conns):
            hour = rng.random() * SIM_HOURS
            # business hours get more traffic
            if not (8 <= (hour % 24) <= 19) and rng.random() < 0.7:
                continue
            ip, domain = rng.choice(BENIGN_EXTERNAL)
            orig_bytes = int(abs(rng.lognormvariate(6.5, 1.0)))  # ~ hundreds-KB
            resp_bytes = int(abs(rng.lognormvariate(8.0, 1.2)))  # downloads larger
            world.conns.append(
                ConnRow(
                    ts=_ts(hour),
                    uid=world.uid(),
                    orig_h=host,
                    orig_p=rng.randint(49152, 65535),
                    resp_h=ip,
                    resp_p=rng.choice([443, 443, 443, 80]),
                    proto="tcp",
                    service=rng.choice(["ssl", "ssl", "http"]),
                    duration=round(abs(rng.gauss(2.0, 1.5)) + 0.05, 3),
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    conn_state="SF",
                )
            )
            # a matching benign DNS lookup sometimes
            if rng.random() < 0.4:
                world.dns.append(
                    DnsRow(
                        ts=_ts(hour) - 0.05,
                        uid=world.uid(),
                        orig_h=host,
                        resp_h="10.10.0.7",
                        query=domain if rng.random() < 0.5 else _rand_domain(rng),
                        qtype="A",
                        answers=ip,
                    )
                )

        # normal internal file-share access (a few hosts, modest volume)
        if rng.random() < 0.5:
            for _ in range(rng.randint(3, 12)):
                hour = rng.uniform(8, 19)
                world.conns.append(
                    ConnRow(
                        ts=_ts(hour),
                        uid=world.uid(),
                        orig_h=host,
                        orig_p=rng.randint(49152, 65535),
                        resp_h="10.10.0.5",
                        resp_p=445,
                        proto="tcp",
                        service="smb",
                        duration=round(abs(rng.gauss(1.0, 0.5)) + 0.05, 3),
                        orig_bytes=int(abs(rng.lognormvariate(6.0, 0.8))),
                        resp_bytes=int(abs(rng.lognormvariate(7.0, 1.0))),
                        conn_state="SF",
                    )
                )


# ---------------------------------------------------------------------------
# Injected attacks  (each returns the attacker host so tests can assert)
# ---------------------------------------------------------------------------

def inject_beaconing(world: World) -> str:
    """D001: C2 beaconing. Highly regular inter-arrival to a single external IP."""
    rng = world.rng
    host = "10.10.0.22"
    c2_ip = "185.220.101.45"
    interval_s = 60.0  # beacon every 60s
    jitter = 1.5       # very low jitter => regular
    start = 9.0
    t = _ts(start)
    end = _ts(start + 6)  # 6 hours of beaconing
    while t < end:
        world.conns.append(
            ConnRow(
                ts=t,
                uid=world.uid(),
                orig_h=host,
                orig_p=rng.randint(49152, 65535),
                resp_h=c2_ip,
                resp_p=443,
                proto="tcp",
                service="ssl",
                duration=round(abs(rng.gauss(0.4, 0.1)), 3),
                orig_bytes=rng.randint(280, 420),   # small, consistent
                resp_bytes=rng.randint(280, 420),
                conn_state="SF",
            )
        )
        t += interval_s + rng.uniform(-jitter, jitter)
    return host


def inject_dns_tunnel(world: World) -> str:
    """D002: DNS tunneling/exfil. Long, high-entropy subdomains to one domain."""
    rng = world.rng
    host = "10.10.0.31"
    tunnel_domain = "exfil-cdn.net"
    start = 11.0
    for i in range(400):
        payload = "".join(
            rng.choice("abcdef0123456789qwxyzjkv") for _ in range(rng.randint(40, 55))
        )
        q = f"{payload}.{tunnel_domain}"
        world.dns.append(
            DnsRow(
                ts=_ts(start + i * 0.01),
                uid=world.uid(),
                orig_h=host,
                resp_h="10.10.0.7",
                query=q,
                qtype="TXT",
                answers="-",
            )
        )
    return host


def inject_exfil_volume(world: World) -> str:
    """D003: Data exfiltration volume spike. Huge orig_bytes to an external host."""
    rng = world.rng
    host = "10.10.0.18"
    dest = "45.133.1.77"
    start = 2.0  # off-hours
    for _ in range(8):
        world.conns.append(
            ConnRow(
                ts=_ts(start + rng.uniform(0, 1)),
                uid=world.uid(),
                orig_h=host,
                orig_p=rng.randint(49152, 65535),
                resp_h=dest,
                resp_p=443,
                proto="tcp",
                service="ssl",
                duration=round(abs(rng.gauss(120, 20)), 3),
                orig_bytes=int(abs(rng.gauss(500_000_000, 50_000_000))),  # ~500MB up
                resp_bytes=rng.randint(2000, 8000),
                conn_state="SF",
            )
        )
    return host


def inject_port_scan(world: World) -> str:
    """D004: Port/host scan fan-out. One host hits many dest ports/hosts fast."""
    rng = world.rng
    host = "10.10.0.27"
    start = 14.0
    # fan out across internal hosts and ports
    for i in range(600):
        target = f"{INTERNAL_SUBNET}{rng.randint(5, 254)}"
        port = rng.choice([22, 23, 80, 135, 139, 443, 445, 1433, 3389, 5985, 8080])
        world.conns.append(
            ConnRow(
                ts=_ts(start + i * 0.002),
                uid=world.uid(),
                orig_h=host,
                orig_p=rng.randint(49152, 65535),
                resp_h=target,
                resp_p=port,
                proto="tcp",
                service="-",
                duration=0.01,
                orig_bytes=0,
                resp_bytes=0,
                conn_state=rng.choice(["REJ", "S0", "RSTO"]),  # failed = scan signal
            )
        )
    return host


def inject_lateral_movement(world: World) -> str:
    """D005: Lateral movement. Workstation using admin protocols to many peers."""
    rng = world.rng
    host = "10.10.0.14"
    start = 16.0
    targets = rng.sample(WORKSTATIONS, 10)
    for i, target in enumerate(targets):
        if target == host:
            continue
        for port in (445, 5985, 3389):
            world.conns.append(
                ConnRow(
                    ts=_ts(start + i * 0.1),
                    uid=world.uid(),
                    orig_h=host,
                    orig_p=rng.randint(49152, 65535),
                    resp_h=target,
                    resp_p=port,
                    proto="tcp",
                    service=rng.choice(["smb", "-", "-"]),
                    duration=round(abs(rng.gauss(3.0, 1.0)), 3),
                    orig_bytes=rng.randint(2000, 20000),
                    resp_bytes=rng.randint(2000, 50000),
                    conn_state="SF",
                )
            )
    return host


def inject_ioc_contact(world: World) -> str:
    """D006: Contact with a known-bad IOC (matches intel feed)."""
    rng = world.rng
    host = "10.10.0.19"
    bad_ip = "193.201.9.7"       # present in intel_feed.json
    bad_domain = "malicious-c2.example"
    start = 13.0
    for i in range(5):
        world.conns.append(
            ConnRow(
                ts=_ts(start + i * 0.5),
                uid=world.uid(),
                orig_h=host,
                orig_p=rng.randint(49152, 65535),
                resp_h=bad_ip,
                resp_p=443,
                proto="tcp",
                service="ssl",
                duration=round(abs(rng.gauss(5, 2)), 3),
                orig_bytes=rng.randint(1000, 5000),
                resp_bytes=rng.randint(1000, 5000),
                conn_state="SF",
            )
        )
    world.dns.append(
        DnsRow(
            ts=_ts(start),
            uid=world.uid(),
            orig_h=host,
            resp_h="10.10.0.7",
            query=bad_domain,
            qtype="A",
            answers=bad_ip,
        )
    )
    return host


INJECTORS = [
    inject_beaconing,
    inject_dns_tunnel,
    inject_exfil_volume,
    inject_port_scan,
    inject_lateral_movement,
    inject_ioc_contact,
]


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

CONN_HEADER = [
    "#fields", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
]
DNS_HEADER = [
    "#fields", "ts", "uid", "id.orig_h", "id.resp_h", "query", "qtype", "answers",
]


def write_logs(world: World, out: Path) -> dict[str, str]:
    out.mkdir(parents=True, exist_ok=True)
    world.conns.sort(key=lambda r: r.ts)
    world.dns.sort(key=lambda r: r.ts)

    conn_path = out / "conn.log"
    with conn_path.open("w") as f:
        f.write("\t".join(CONN_HEADER) + "\n")
        for row in world.conns:
            f.write(row.to_tsv() + "\n")

    dns_path = out / "dns.log"
    with dns_path.open("w") as f:
        f.write("\t".join(DNS_HEADER) + "\n")
        for row in world.dns:
            f.write(row.to_tsv() + "\n")

    return {"conn": str(conn_path), "dns": str(dns_path)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_world(seed: int = 1337) -> tuple[World, dict[str, str]]:
    """Build the full dataset in memory and return (world, attacker_map)."""
    world = World(rng=random.Random(seed))
    gen_benign(world)
    attackers = {fn.__name__.replace("inject_", ""): fn(world) for fn in INJECTORS}
    return world, attackers


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic Zeek logs.")
    parser.add_argument("--out", default="data", help="output directory")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    world, attackers = build_world(args.seed)
    paths = write_logs(world, Path(args.out))

    print(f"Wrote {len(world.conns)} conn rows -> {paths['conn']}")
    print(f"Wrote {len(world.dns)} dns rows  -> {paths['dns']}")
    print("Injected attackers (ground truth):")
    for scenario, host in attackers.items():
        print(f"  {scenario:18s} -> {host}")


if __name__ == "__main__":
    main()
