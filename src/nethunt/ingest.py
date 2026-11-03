"""Ingest + normalize Zeek-style logs into a common event schema.

Zeek writes several log types with different columns. The detections should not
care about per-log quirks, so we normalize both conn.log and dns.log into tidy
pandas DataFrames with stable column names. A small derived-feature pass adds
the fields the baseline/anomaly engine relies on (hour-of-day, DNS query
entropy, query length).
"""
from __future__ import annotations

import math
from pathlib import Path

import pandas as pd

CONN_COLUMNS = [
    "ts", "uid", "orig_h", "orig_p", "resp_h", "resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
]
DNS_COLUMNS = ["ts", "uid", "orig_h", "resp_h", "query", "qtype", "answers"]


def _read_zeek_tsv(path: Path, columns: list[str]) -> pd.DataFrame:
    """Read a Zeek TSV, skipping the '#fields' header line."""
    df = pd.read_csv(
        path,
        sep="\t",
        comment=None,
        skiprows=1,          # the single '#fields ...' header row
        names=columns,
        header=None,
        dtype=str,
    )
    return df


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits/char). High for random/encoded data."""
    if not isinstance(s, str) or not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def load_conn(path: str | Path) -> pd.DataFrame:
    df = _read_zeek_tsv(Path(path), CONN_COLUMNS)
    df["ts"] = df["ts"].astype(float)
    for col in ("orig_p", "resp_p", "orig_bytes", "resp_bytes"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", utc=True)
    df["hour"] = df["datetime"].dt.hour
    df["total_bytes"] = df["orig_bytes"] + df["resp_bytes"]
    return df


def load_dns(path: str | Path) -> pd.DataFrame:
    df = _read_zeek_tsv(Path(path), DNS_COLUMNS)
    df["ts"] = df["ts"].astype(float)
    df["datetime"] = pd.to_datetime(df["ts"], unit="s", utc=True)
    df["query"] = df["query"].fillna("")
    # label (leftmost) + registered-ish domain split
    df["qname_len"] = df["query"].str.len()
    df["leftmost"] = df["query"].str.split(".").str[0].fillna("")
    df["entropy"] = df["leftmost"].map(shannon_entropy)
    df["parent_domain"] = df["query"].apply(_parent_domain)
    return df


def _parent_domain(q: str) -> str:
    """Best-effort registered domain (last two labels). Good enough for grouping."""
    if not isinstance(q, str):
        return ""
    parts = q.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else q


def load_all(data_dir: str | Path) -> dict[str, pd.DataFrame]:
    data_dir = Path(data_dir)
    return {
        "conn": load_conn(data_dir / "conn.log"),
        "dns": load_dns(data_dir / "dns.log"),
    }
