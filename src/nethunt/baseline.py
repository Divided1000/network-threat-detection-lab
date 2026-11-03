"""Per-host behavioral baselining.

This is the core idea that separates NetHunt from signature-only detection:
instead of asking "does this one connection match a bad pattern", we learn what
each host normally does over the observation window and score how far current
behavior deviates. That is the behavioral/UEBA foundation used for insider-threat
and low-and-slow C2 detection, where any single event looks legitimate.

The baseline is intentionally simple and explainable (robust stats, not a black
box) so an analyst can reason about *why* a host was flagged:

  - fleet-level distribution of a metric (median + MAD) -> robust z-score
  - per-host rollups (bytes sent, distinct destinations, distinct ports, etc.)

Robust statistics (median / MAD) are used instead of mean / std because a single
large attack value would otherwise poison the very baseline meant to catch it.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# 1.4826 scales MAD to be a consistent estimator of std for normal data.
_MAD_SCALE = 1.4826


def robust_z(values: pd.Series) -> pd.Series:
    """Robust z-score using median and MAD. Resistant to the outliers we hunt."""
    med = values.median()
    mad = (values - med).abs().median()
    if mad == 0:
        # fall back to std if MAD collapses (e.g. many identical values)
        std = values.std(ddof=0)
        if std == 0:
            return pd.Series(0.0, index=values.index)
        return (values - values.mean()) / std
    return (values - med) / (_MAD_SCALE * mad)


@dataclass
class HostBaseline:
    """Per-host behavioral rollup over the observation window."""

    table: pd.DataFrame  # indexed by orig_h

    def hosts(self) -> list[str]:
        return list(self.table.index)

    def metric(self, name: str) -> pd.Series:
        return self.table[name]

    def zscores(self, name: str) -> pd.Series:
        return robust_z(self.table[name])


def build_host_baseline(conn: pd.DataFrame, dns: pd.DataFrame) -> HostBaseline:
    """Aggregate raw events into per-host behavioral features.

    Features chosen to surface the injected TTPs while staying interpretable:
      bytes_out_total      -> data exfiltration volume
      distinct_ext_dests   -> scanning / unusual breadth
      distinct_resp_ports  -> port scanning / lateral movement
      failed_conn_ratio    -> scan/probe behavior (REJ/S0/RSTO)
      internal_admin_fanout-> lateral movement over admin ports
      dns_txt_count        -> DNS tunneling channel
      max_dns_entropy      -> encoded DNS payloads
    """
    conn = conn.copy()
    conn["is_external"] = ~conn["resp_h"].str.startswith("10.10.0.")
    conn["is_failed"] = conn["conn_state"].isin(["REJ", "S0", "RSTO", "RSTR"])
    admin_ports = {445, 3389, 5985, 5986, 22, 135, 139}
    conn["is_admin_port"] = conn["resp_p"].isin(admin_ports)
    conn["is_internal_dest"] = conn["resp_h"].str.startswith("10.10.0.")

    grp = conn.groupby("orig_h")
    feats = pd.DataFrame(index=grp.size().index)
    feats["conn_count"] = grp.size()
    feats["bytes_out_total"] = grp["orig_bytes"].sum()
    feats["bytes_out_max"] = grp["orig_bytes"].max()
    feats["distinct_ext_dests"] = (
        conn[conn["is_external"]].groupby("orig_h")["resp_h"].nunique()
    )
    feats["distinct_resp_ports"] = grp["resp_p"].nunique()
    feats["failed_conn_ratio"] = (
        grp["is_failed"].sum() / grp.size()
    )
    # lateral movement: distinct *internal* hosts reached over admin ports
    admin = conn[conn["is_admin_port"] & conn["is_internal_dest"]]
    feats["internal_admin_fanout"] = (
        admin.groupby("orig_h")["resp_h"].nunique()
    )

    # DNS-derived features
    if not dns.empty:
        dgrp = dns.groupby("orig_h")
        feats["dns_query_count"] = dgrp.size()
        feats["dns_txt_count"] = (
            dns[dns["qtype"] == "TXT"].groupby("orig_h").size()
        )
        feats["max_dns_entropy"] = dgrp["entropy"].max()
        feats["mean_qname_len"] = dgrp["qname_len"].mean()

    feats = feats.fillna(0)
    return HostBaseline(table=feats)


# ---------------------------------------------------------------------------
# Beaconing: regularity of inter-arrival times to a single destination
# ---------------------------------------------------------------------------

def beacon_scores(conn: pd.DataFrame, min_events: int = 20) -> pd.DataFrame:
    """Score (orig_h, resp_h) pairs for beacon-like timing regularity.

    C2 beacons phone home on a timer, so their inter-arrival times cluster
    tightly around a period. We measure that with the coefficient of variation
    (CV = std/mean) of inter-arrival gaps: low CV = highly regular = beacon-like.
    Human/browser traffic is bursty and irregular, so CV is high.

    Returns one row per (orig_h, resp_h) pair with enough events, sorted by
    regularity (most regular first).
    """
    ext = conn[~conn["resp_h"].str.startswith("10.10.0.")]
    rows = []
    for (src, dst), g in ext.sort_values("ts").groupby(["orig_h", "resp_h"]):
        if len(g) < min_events:
            continue
        gaps = np.diff(g["ts"].to_numpy())
        gaps = gaps[gaps > 0]
        if len(gaps) < min_events - 1:
            continue
        mean_gap = float(np.mean(gaps))
        std_gap = float(np.std(gaps))
        cv = std_gap / mean_gap if mean_gap > 0 else np.inf
        rows.append(
            {
                "orig_h": src,
                "resp_h": dst,
                "events": len(g),
                "mean_interval_s": round(mean_gap, 2),
                "cv": round(cv, 4),
                "regularity": round(1.0 / (1.0 + cv), 4),  # 1.0 = perfectly regular
            }
        )
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values("cv").reset_index(drop=True)
