"""Detections: anomaly + rule logic that emits ATT&CK/Diamond-mapped findings.

Each detection is a small function that takes the normalized data (and, where
useful, the host baseline and intel feed) and returns a list of Finding objects.
Detections lean on the baseline for behavioral scoring rather than hard-coding
thresholds against single events, so they generalize beyond the seeded dataset.

Catalog:
  D001  C2 beaconing            anomaly  T1071.001 / T1573
  D002  DNS tunneling / exfil   anomaly  T1071.004 / T1048
  D003  Data exfil volume spike anomaly  T1030 / T1048
  D004  Port / host scan        anomaly  T1046
  D005  Lateral movement        rule     T1021
  D006  Known-bad IOC contact   rule     T1071 (+intel)
"""
from __future__ import annotations

import pandas as pd

from .baseline import HostBaseline, beacon_scores
from .findings import DiamondModel, Finding
from .intel import IntelFeed

INTERNAL_PREFIX = "10.10.0."


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _intel_for(feed: IntelFeed | None, ips=(), domains=()) -> list[dict]:
    hits = []
    if feed is None:
        return hits
    for ip in ips:
        m = feed.match_ip(ip)
        if m:
            hits.append(m)
    for d in domains:
        m = feed.match_domain(d)
        if m:
            hits.append(m)
    return hits


# ---------------------------------------------------------------------------
# D001 — C2 beaconing
# ---------------------------------------------------------------------------

def detect_beaconing(
    conn: pd.DataFrame,
    feed: IntelFeed | None = None,
    cv_max: float = 0.1,
    min_events: int = 20,
) -> list[Finding]:
    """Flag external destinations contacted on a near-fixed timer.

    Low coefficient-of-variation of inter-arrival times = beacon-like. Benign
    browsing is bursty (high CV), so this keys on *regularity*, not volume,
    which is what catches low-and-slow C2 that each look like one HTTPS call.
    """
    scores = beacon_scores(conn, min_events=min_events)
    findings: list[Finding] = []
    if scores.empty:
        return findings
    for _, r in scores[scores["cv"] <= cv_max].iterrows():
        intel = _intel_for(feed, ips=[r["resp_h"]])
        findings.append(
            Finding(
                detection_id="D001",
                title="Periodic C2 beaconing to external host",
                severity="high",
                confidence=min(0.99, float(r["regularity"])),
                src_host=r["orig_h"],
                attack_tactic="Command and Control",
                attack_technique="T1071.001",
                attack_technique_name="Application Layer Protocol: Web Protocols",
                rationale=(
                    f"{int(r['events'])} connections to {r['resp_h']} at a near-fixed "
                    f"{r['mean_interval_s']}s interval (CV={r['cv']}, "
                    f"regularity={r['regularity']}). Human traffic is bursty; this "
                    f"timing regularity is characteristic of automated C2 beaconing."
                ),
                evidence={
                    "dest": r["resp_h"],
                    "events": int(r["events"]),
                    "mean_interval_s": float(r["mean_interval_s"]),
                    "cv": float(r["cv"]),
                },
                diamond=DiamondModel(
                    adversary=(intel[0]["diamond_adversary"] if intel else "unknown"),
                    capability="Timed C2 beacon over TLS",
                    infrastructure=r["resp_h"],
                    victim=r["orig_h"],
                ),
                intel=intel,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D002 — DNS tunneling / exfil
# ---------------------------------------------------------------------------

def detect_dns_tunneling(
    dns: pd.DataFrame,
    feed: IntelFeed | None = None,
    entropy_min: float = 3.5,
    len_min: int = 40,
    min_queries: int = 20,
) -> list[Finding]:
    """Flag hosts emitting many long, high-entropy DNS labels to one domain.

    Encoded data smuggled in DNS labels looks random (high Shannon entropy) and
    is longer than normal hostnames. A volume of such queries to a single parent
    domain is the tunneling signal.
    """
    findings: list[Finding] = []
    if dns.empty:
        return findings
    suspicious = dns[(dns["entropy"] >= entropy_min) & (dns["qname_len"] >= len_min)]
    if suspicious.empty:
        return findings
    grouped = suspicious.groupby(["orig_h", "parent_domain"])
    for (src, parent), g in grouped:
        if len(g) < min_queries:
            continue
        intel = _intel_for(feed, domains=[parent])
        findings.append(
            Finding(
                detection_id="D002",
                title="DNS tunneling / exfiltration over DNS",
                severity="high",
                confidence=0.9,
                src_host=src,
                attack_tactic="Exfiltration",
                attack_technique="T1048.001",
                attack_technique_name="Exfiltration Over Alternative Protocol",
                rationale=(
                    f"{len(g)} DNS queries to {parent} with high label entropy "
                    f"(max {g['entropy'].max():.2f} bits/char) and long names "
                    f"(max {int(g['qname_len'].max())} chars). Consistent with "
                    f"encoded data tunneled through DNS."
                ),
                evidence={
                    "parent_domain": parent,
                    "queries": len(g),
                    "max_entropy": float(g["entropy"].max()),
                    "max_qname_len": int(g["qname_len"].max()),
                    "qtypes": sorted(g["qtype"].unique().tolist()),
                },
                diamond=DiamondModel(
                    adversary=(intel[0]["diamond_adversary"] if intel else "unknown"),
                    capability="Data exfiltration via DNS tunneling",
                    infrastructure=parent,
                    victim=src,
                ),
                intel=intel,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D003 — Data exfiltration volume spike
# ---------------------------------------------------------------------------

def detect_exfil_volume(
    conn: pd.DataFrame,
    baseline: HostBaseline,
    feed: IntelFeed | None = None,
    z_min: float = 8.0,
) -> list[Finding]:
    """Flag hosts whose outbound byte volume is a massive outlier vs the fleet.

    Uses the robust (median/MAD) z-score so one giant upload cannot hide inside
    its own baseline. Also surfaces the single external destination that
    received the bulk of the data.
    """
    findings: list[Finding] = []
    z = baseline.zscores("bytes_out_total")
    for host, zval in z[z >= z_min].items():
        ext = conn[
            (conn["orig_h"] == host)
            & (~conn["resp_h"].str.startswith(INTERNAL_PREFIX))
        ]
        if ext.empty:
            continue
        top = ext.groupby("resp_h")["orig_bytes"].sum().sort_values(ascending=False)
        dest = top.index[0]
        mb = top.iloc[0] / 1e6
        intel = _intel_for(feed, ips=[dest])
        findings.append(
            Finding(
                detection_id="D003",
                title="Outbound data volume anomaly (possible exfiltration)",
                severity="critical" if mb > 100 else "high",
                confidence=0.85,
                src_host=host,
                attack_tactic="Exfiltration",
                attack_technique="T1030",
                attack_technique_name="Data Transfer Size Limits",
                rationale=(
                    f"Host sent {mb:,.0f} MB to {dest}, a robust z-score of "
                    f"{zval:,.1f} above fleet-normal outbound volume. "
                    f"Volume and single-destination concentration are consistent "
                    f"with bulk data exfiltration."
                ),
                evidence={
                    "dest": dest,
                    "mb_out": round(mb, 1),
                    "bytes_out_zscore": round(float(zval), 1),
                },
                diamond=DiamondModel(
                    adversary=(intel[0]["diamond_adversary"] if intel else "unknown"),
                    capability="Bulk data exfiltration over TLS",
                    infrastructure=dest,
                    victim=host,
                ),
                intel=intel,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D004 — Port / host scan
# ---------------------------------------------------------------------------

def detect_scan(
    conn: pd.DataFrame,
    baseline: HostBaseline,
    feed: IntelFeed | None = None,
    port_z_min: float = 3.0,
    failed_ratio_min: float = 0.3,
) -> list[Finding]:
    """Flag hosts with anomalous port fan-out and a high failed-connection ratio.

    Scanning touches many ports/hosts and most attempts fail (REJ/S0/RSTO).
    Requiring both an anomalous distinct-port z-score and a high failure ratio
    separates scans from a busy-but-legitimate host.
    """
    findings: list[Finding] = []
    z = baseline.zscores("distinct_resp_ports")
    fail = baseline.metric("failed_conn_ratio")
    for host in baseline.hosts():
        if z.get(host, 0) < port_z_min or fail.get(host, 0) < failed_ratio_min:
            continue
        hconn = conn[conn["orig_h"] == host]
        n_ports = int(hconn["resp_p"].nunique())
        n_hosts = int(hconn["resp_h"].nunique())
        findings.append(
            Finding(
                detection_id="D004",
                title="Network scanning / host discovery",
                severity="medium",
                confidence=0.8,
                src_host=host,
                attack_tactic="Discovery",
                attack_technique="T1046",
                attack_technique_name="Network Service Discovery",
                rationale=(
                    f"Host touched {n_ports} distinct ports across {n_hosts} hosts "
                    f"with a {fail.get(host, 0):.0%} failed-connection ratio "
                    f"(port z-score {z.get(host, 0):.1f}). Broad fan-out with mostly "
                    f"failed connections is characteristic of scanning."
                ),
                evidence={
                    "distinct_ports": n_ports,
                    "distinct_hosts": n_hosts,
                    "failed_ratio": round(float(fail.get(host, 0)), 2),
                    "port_zscore": round(float(z.get(host, 0)), 1),
                },
                diamond=DiamondModel(
                    adversary="unknown",
                    capability="Active network scanning",
                    infrastructure=host,
                    victim="internal /24 subnet",
                ),
                intel=[],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D005 — Lateral movement
# ---------------------------------------------------------------------------

def detect_lateral_movement(
    conn: pd.DataFrame,
    feed: IntelFeed | None = None,
    min_targets: int = 3,
) -> list[Finding]:
    """Flag a workstation opening SUCCESSFUL admin-protocol sessions to many peers.

    Key discriminator vs scanning: we require conn_state == 'SF' (established) and
    real data transfer. A scanner produces failed, zero-byte probes; lateral
    movement produces completed SMB/WinRM/RDP sessions that move data. This keeps
    the port-scan host out of this detection.
    """
    admin_ports = {445, 3389, 5985, 5986, 135, 139}
    internal = conn[
        conn["resp_h"].str.startswith(INTERNAL_PREFIX)
        & conn["resp_p"].isin(admin_ports)
        & (conn["conn_state"] == "SF")
        & (conn["total_bytes"] > 1000)        # established + real transfer
    ]
    findings: list[Finding] = []
    if internal.empty:
        return findings
    for host, g in internal.groupby("orig_h"):
        targets = g["resp_h"].nunique()
        if targets < min_targets:
            continue
        ports = sorted(g["resp_p"].unique().tolist())
        findings.append(
            Finding(
                detection_id="D005",
                title="Internal lateral movement over admin protocols",
                severity="high",
                confidence=0.82,
                src_host=host,
                attack_tactic="Lateral Movement",
                attack_technique="T1021",
                attack_technique_name="Remote Services",
                rationale=(
                    f"Workstation opened established sessions to {targets} internal "
                    f"hosts over admin ports {ports} with real data transfer. "
                    f"A workstation fanning out over SMB/WinRM/RDP to many peers is "
                    f"atypical and consistent with lateral movement."
                ),
                evidence={
                    "target_count": int(targets),
                    "admin_ports": ports,
                    "targets": sorted(g["resp_h"].unique().tolist())[:10],
                },
                diamond=DiamondModel(
                    adversary="unknown",
                    capability="Remote service abuse (SMB/WinRM/RDP)",
                    infrastructure=host,
                    victim=f"{targets} internal hosts",
                ),
                intel=[],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# D006 — Known-bad IOC contact (intel-driven)
# ---------------------------------------------------------------------------

def detect_ioc_contact(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    feed: IntelFeed,
) -> list[Finding]:
    """Flag any contact with an IP/domain present in the threat-intel feed."""
    findings: list[Finding] = []
    if feed is None:
        return findings

    bad_ips = feed.all_ips()
    hits = conn[conn["resp_h"].isin(bad_ips)]
    for (host, dest), g in hits.groupby(["orig_h", "resp_h"]):
        ind = feed.match_ip(dest)
        findings.append(
            Finding(
                detection_id="D006",
                title="Connection to known-bad infrastructure (intel match)",
                severity="critical" if ind.get("confidence") == "high" else "high",
                confidence=0.95,
                src_host=host,
                attack_tactic="Command and Control",
                attack_technique="T1071",
                attack_technique_name="Application Layer Protocol",
                rationale=(
                    f"Host contacted {dest} ({g.shape[0]} connections), which matches "
                    f"intel indicator '{ind.get('threat')}' "
                    f"(confidence={ind.get('confidence')}). {ind.get('note', '')}"
                ),
                evidence={
                    "dest": dest,
                    "connections": int(g.shape[0]),
                    "threat": ind.get("threat"),
                },
                diamond=DiamondModel(
                    adversary=ind.get("diamond_adversary", "unknown"),
                    capability="Known C2 / malicious infrastructure",
                    infrastructure=dest,
                    victim=host,
                ),
                intel=[ind],
            )
        )

    # DNS resolutions of known-bad domains
    if not dns.empty:
        for _, row in dns.iterrows():
            ind = feed.match_domain(row["query"])
            if not ind:
                continue
            findings.append(
                Finding(
                    detection_id="D006",
                    title="DNS resolution of known-bad domain (intel match)",
                    severity="high",
                    confidence=0.9,
                    src_host=row["orig_h"],
                    attack_tactic="Command and Control",
                    attack_technique="T1071.004",
                    attack_technique_name="Application Layer Protocol: DNS",
                    rationale=(
                        f"Host resolved {row['query']}, matching intel indicator "
                        f"'{ind.get('threat')}' (confidence={ind.get('confidence')})."
                    ),
                    evidence={"query": row["query"], "threat": ind.get("threat")},
                    diamond=DiamondModel(
                        adversary=ind.get("diamond_adversary", "unknown"),
                        capability="C2 domain resolution",
                        infrastructure=row["query"],
                        victim=row["orig_h"],
                    ),
                    intel=[ind],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def run_all(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    baseline: HostBaseline,
    feed: IntelFeed | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings += detect_beaconing(conn, feed)
    findings += detect_dns_tunneling(dns, feed)
    findings += detect_exfil_volume(conn, baseline, feed)
    findings += detect_scan(conn, baseline, feed)
    findings += detect_lateral_movement(conn, feed)
    if feed is not None:
        findings += detect_ioc_contact(conn, dns, feed)
    return findings
