"""Builds notebooks/threat_hunt.ipynb programmatically.

Keeping the notebook as code-generated JSON means it is reviewable in git and
reproducible. Run:  python notebooks/_build_notebook.py
Then execute/verify:  jupyter nbconvert --to notebook --execute ...
"""
import json
from pathlib import Path

NB = Path(__file__).parent / "threat_hunt.ipynb"


def md(*lines):
    return {"cell_type": "markdown", "metadata": {}, "source": _src(lines)}


def code(*lines):
    return {
        "cell_type": "code",
        "metadata": {},
        "execution_count": None,
        "outputs": [],
        "source": _src(lines),
    }


def _src(lines):
    text = "\n".join(lines)
    out = text.splitlines(keepends=True)
    return out


cells = []

cells.append(md(
    "# NetHunt — Network Threat Hunt",
    "",
    "**Hunt hypothesis:** an insider or external actor is using the network in a way",
    "that each single connection looks legitimate, but whose *behavior over time*",
    "deviates from how the host normally acts — low-and-slow C2 beaconing, DNS",
    "tunneling, bulk data exfiltration, scanning, or lateral movement.",
    "",
    "**Method:** baseline each host from Zeek `conn.log` + `dns.log`, score deviations",
    "with robust statistics, corroborate against a threat-intel feed, and map every",
    "finding to **MITRE ATT&CK** and the **Diamond Model**.",
    "",
    "This notebook is the investigative, narrative companion to the batch pipeline in",
    "`python -m nethunt.cli`.",
))

cells.append(md("## 0. Setup"))
cells.append(code(
    "import sys; sys.path.insert(0, '../src')",
    "import pandas as pd, numpy as np",
    "import matplotlib.pyplot as plt",
    "pd.set_option('display.width', 120); pd.set_option('display.max_columns', 20)",
    "",
    "from nethunt.ingest import load_all",
    "from nethunt.baseline import build_host_baseline, beacon_scores",
    "from nethunt.intel import load_intel",
    "from nethunt.detections import run_all",
    "from nethunt.findings import dedup",
))

cells.append(md(
    "## 1. Load and normalize the telemetry",
    "",
    "Both Zeek logs are normalized into one tidy schema so the hunt logic never has",
    "to care which log a field came from.",
))
cells.append(code(
    "data = load_all('../data')",
    "conn, dns = data['conn'], data['dns']",
    "print(f'conn flows: {len(conn):,}   dns queries: {len(dns):,}')",
    "print(f'hosts: {conn.orig_h.nunique()}   window: "
    "{conn.datetime.min()} -> {conn.datetime.max()}')",
    "conn[['datetime','orig_h','resp_h','resp_p','service','orig_bytes','resp_bytes',"
    "'conn_state']].head()",
))

cells.append(md(
    "## 2. Baseline normal behavior per host",
    "",
    "We roll each host up into behavioral features and score deviations with a",
    "**robust** (median/MAD) z-score, so a single massive attack value can't poison",
    "the baseline meant to catch it.",
))
cells.append(code(
    "baseline = build_host_baseline(conn, dns)",
    "baseline.table[['conn_count','bytes_out_total','distinct_resp_ports',",
    "                'failed_conn_ratio','internal_admin_fanout',",
    "                'dns_txt_count','max_dns_entropy']].describe().round(2)",
))

cells.append(md(
    "### 2a. Where do the outliers live?",
    "Rank hosts by outbound-volume z-score. One host should stand far off the fleet.",
))
cells.append(code(
    "z_bytes = baseline.zscores('bytes_out_total').sort_values(ascending=False)",
    "z_bytes.head(5).round(1)",
))

cells.append(md(
    "## 3. Hunt 1 — C2 beaconing (behavioral)",
    "",
    "C2 implants phone home on a timer. We measure the **coefficient of variation**",
    "(CV = std/mean) of inter-arrival gaps per (src, dst) pair. Low CV = metronome =",
    "automation. Human browsing is bursty (high CV).",
))
cells.append(code(
    "beacons = beacon_scores(conn)",
    "beacons.head(5)",
))
cells.append(code(
    "# visualize: the top beacon's gaps are tight; a benign pair's are scattered",
    "top = beacons.iloc[0]",
    "pair = conn[(conn.orig_h==top.orig_h) & (conn.resp_h==top.resp_h)].sort_values('ts')",
    "gaps = np.diff(pair.ts.to_numpy())",
    "",
    "benign = beacons.iloc[-1]",
    "bpair = conn[(conn.orig_h==benign.orig_h)&(conn.resp_h==benign.resp_h)].sort_values('ts')",
    "bgaps = np.diff(bpair.ts.to_numpy())",
    "",
    "fig, ax = plt.subplots(1, 2, figsize=(11, 3.2))",
    "ax[0].hist(gaps, bins=30); ax[0].set_title(f'C2 {top.orig_h}->{top.resp_h}\\nCV={top.cv}')",
    "ax[0].set_xlabel('inter-arrival gap (s)')",
    "ax[1].hist(bgaps, bins=30, color='green')",
    "ax[1].set_title(f'benign {benign.orig_h}->{benign.resp_h}\\nCV={benign.cv}')",
    "ax[1].set_xlabel('inter-arrival gap (s)'); plt.tight_layout(); plt.show()",
))
cells.append(md(
    "The C2 gaps collapse onto a single ~60s spike; benign gaps are spread out.",
    "That regularity is the detection signal, independent of payload or volume.",
))

cells.append(md(
    "## 4. Hunt 2 — Exfiltration (volume + DNS tunneling)",
))
cells.append(code(
    "# 4a. outbound volume per host (log scale) — the exfil host dwarfs the fleet",
    "bo = baseline.table['bytes_out_total'].sort_values()",
    "plt.figure(figsize=(10,3))",
    "plt.bar(range(len(bo)), bo.values)",
    "plt.yscale('log'); plt.ylabel('bytes out (log)'); plt.xlabel('host rank')",
    "plt.title('Outbound volume per host'); plt.tight_layout(); plt.show()",
    "print('top talker:', bo.index[-1], f'{bo.iloc[-1]/1e6:,.0f} MB')",
))
cells.append(code(
    "# 4b. DNS tunneling: long, high-entropy labels cluster on one parent domain",
    "susp = dns[(dns.entropy>=3.5) & (dns.qname_len>=40)]",
    "susp.groupby(['orig_h','parent_domain']).agg("
    "queries=('query','size'), max_entropy=('entropy','max'),"
    " max_len=('qname_len','max')).sort_values('queries', ascending=False).head()",
))

cells.append(md(
    "## 5. Intel-driven corroboration",
    "",
    "Pivot from \"what looks anomalous\" to \"what do we already know is bad\". Matching",
    "behavioral findings against the IOC feed raises confidence and attributes a",
    "Diamond-Model adversary.",
))
cells.append(code(
    "feed = load_intel('../data/intel_feed.json')",
    "ext = conn[~conn.resp_h.str.startswith('10.10.0.')]",
    "ext_bad = sorted(set(ext.resp_h) & feed.all_ips())",
    "print('known-bad external IPs contacted:', ext_bad)",
    "for ip in ext_bad:",
    "    ind = feed.match_ip(ip)",
    "    who = conn[conn.resp_h==ip].orig_h.unique()",
    "    print(f'  {ip}  threat={ind[\"threat\"]:18s} conf={ind[\"confidence\"]:6s} hosts={list(who)}')",
))

cells.append(md(
    "## 6. Run the full detection suite",
    "",
    "Everything above is the manual hunt. The same logic is codified in the detection",
    "modules so it runs automatically and emits prioritized, analyst-ready findings.",
))
cells.append(code(
    "findings = dedup(run_all(conn, dns, baseline, feed))",
    "print(f'{len(findings)} findings\\n')",
    "for f in findings:",
    "    print(f.summary_line())",
))

cells.append(md("### 6a. Top finding, fully contextualized (ATT&CK + Diamond + intel)"))
cells.append(code(
    "f = findings[0]",
    "print(f'{f.detection_id}  {f.title}')",
    "print('host     :', f.src_host)",
    "print('severity :', f.severity, 'score', f.score)",
    "print('ATT&CK   :', f.attack_technique, f.attack_technique_name, f'({f.attack_tactic})')",
    "print('rationale:', f.rationale)",
    "d = f.diamond",
    "print('Diamond  : adversary=%s | capability=%s | infra=%s | victim=%s' %",
    "      (d.adversary, d.capability, d.infrastructure, d.victim))",
    "print('intel    :', f.intel[0]['threat'] if f.intel else 'none')",
))

cells.append(md(
    "## 7. ATT&CK coverage of this hunt",
))
cells.append(code(
    "cov = pd.DataFrame([{",
    "  'detection': f.detection_id, 'technique': f.attack_technique,",
    "  'tactic': f.attack_tactic, 'host': f.src_host, 'score': f.score,",
    "} for f in findings]).sort_values('score', ascending=False)",
    "cov",
))

cells.append(md(
    "## 8. Hunt conclusion",
    "",
    "Starting from a behavioral hypothesis and zero prior IOCs, the hunt surfaced five",
    "distinct TTPs and corroborated three of them against threat intel:",
    "",
    "| Host | Behavior | ATT&CK | Intel |",
    "|------|----------|--------|-------|",
    "| .18 | 4 GB outbound to one sink | T1030 Exfiltration | EXFIL-SINK |",
    "| .19 | contact with known C2 | T1071 C2 | APT-DEMO (high) |",
    "| .22 | 60s beacon to external host | T1071.001 C2 | COMMODITY-BEACON |",
    "| .31 | high-entropy DNS tunneling | T1048 Exfiltration | DNS-TUNNEL |",
    "| .27 | port/host scan fan-out | T1046 Discovery | — |",
    "| .14 | SMB/WinRM/RDP to 10 peers | T1021 Lateral Movement | — |",
    "",
    "**Next actions:** isolate .18 and .19, pull host EDR on .22/.31, and feed the two",
    "unknown external IPs back into the intel feed as new indicators to close the loop.",
    "",
    "The `.27`/`.14` pair also shows the key false-positive discriminator: scanning is",
    "failed, zero-byte probes; lateral movement is *established* admin sessions moving",
    "data. Keying D005 on connection state keeps the scanner out of the lateral bucket.",
))

nb = {
    "cells": cells,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

NB.write_text(json.dumps(nb, indent=1))
print(f"wrote {NB} with {len(cells)} cells")
