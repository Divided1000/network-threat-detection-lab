"""Threat-intel IOC feed loading and enrichment.

Intel-driven hunting means pivoting from "what looks anomalous" to "who/what do
we already know is bad". This module loads a simple IOC feed (IPs + domains) and
exposes lookups the detections and the hunt notebook use to corroborate
behavioral findings. In production the loader would point at MISP, a commercial
feed, or an internal threat-cluster tracking system instead of a JSON file.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class IntelFeed:
    name: str
    ip_index: dict[str, dict[str, Any]]
    domain_index: dict[str, dict[str, Any]]

    def match_ip(self, ip: str) -> dict[str, Any] | None:
        return self.ip_index.get(ip)

    def match_domain(self, domain: str) -> dict[str, Any] | None:
        if domain in self.domain_index:
            return self.domain_index[domain]
        # also match a parent domain (e.g. sub.bad.example -> bad.example)
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.domain_index:
                return self.domain_index[candidate]
        return None

    def all_ips(self) -> set[str]:
        return set(self.ip_index)

    def all_domains(self) -> set[str]:
        return set(self.domain_index)


def load_intel(path: str | Path) -> IntelFeed:
    data = json.loads(Path(path).read_text())
    ip_index: dict[str, dict[str, Any]] = {}
    domain_index: dict[str, dict[str, Any]] = {}
    for ind in data.get("indicators", []):
        itype = ind.get("type")
        value = ind.get("value", "")
        if itype == "ipv4":
            ip_index[value] = ind
        elif itype == "domain":
            domain_index[value] = ind
    return IntelFeed(
        name=data.get("feed_name", "intel"),
        ip_index=ip_index,
        domain_index=domain_index,
    )
