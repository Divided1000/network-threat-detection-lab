# Detection Catalog

Every detection, its logic, its ATT&CK mapping, and its tuning/false-positive notes.
This is the artifact a detection engineer hands to an analyst or a reviewer.

Severity scoring: `score = (severity_rank/4 * 100) * confidence`, with a `+15` boost
when a threat-intel indicator corroborates the finding (capped at 100).

---

## D001 — C2 Beaconing
- **Type:** behavioral anomaly
- **ATT&CK:** T1071.001 Application Layer Protocol: Web Protocols (Command & Control)
- **Signal:** coefficient of variation (CV = std/mean) of inter-arrival gaps per
  (src, dst) external pair. Low CV = metronome-like = automated beacon.
- **Logic:** flag pairs with `>= 20` events and `CV <= 0.1`.
- **Why behavioral:** each callout is a normal HTTPS connection; only the *timing
  regularity across many events* reveals automation. Volume/payload are irrelevant.
- **FP notes:** legitimate pollers (NTP, update checks, monitoring agents) can beacon.
  Tune by allowlisting known-good (dst, interval) pairs; raise `min_events` to avoid
  short-lived coincidences. Jitter-heavy C2 raises CV — pair with D006 intel.
- **Tuning knobs:** `cv_max`, `min_events`.

## D002 — DNS Tunneling / Exfiltration over DNS
- **Type:** behavioral anomaly
- **ATT&CK:** T1048.001 Exfiltration Over Alternative Protocol (Exfiltration)
- **Signal:** many long, high-Shannon-entropy DNS labels to a single parent domain.
- **Logic:** keep queries with `entropy >= 3.5` bits/char and `qname_len >= 40`;
  flag any (host, parent_domain) with `>= 20` such queries.
- **FP notes:** some CDNs and antivirus/telemetry services use long hashed
  subdomains. Tune by allowlisting known parent domains; TXT-record volume is a
  stronger tunneling signal than A records.
- **Tuning knobs:** `entropy_min`, `len_min`, `min_queries`.

## D003 — Outbound Data Volume Anomaly
- **Type:** behavioral anomaly
- **ATT&CK:** T1030 Data Transfer Size Limits (Exfiltration)
- **Signal:** robust (median/MAD) z-score of total outbound bytes per host vs fleet.
- **Logic:** flag hosts with `bytes_out_total` z-score `>= 8`; report the single
  external destination that received the bulk of the data.
- **Why robust stats:** a mean/std baseline would be dragged up by the very upload
  we're hunting; median/MAD resists that.
- **FP notes:** backup jobs, large legitimate uploads (video, datasets). Tune per
  host-role baselines; combine with off-hours timing and destination reputation.
- **Tuning knobs:** `z_min`.

## D004 — Network Scanning / Host Discovery
- **Type:** anomaly + rule
- **ATT&CK:** T1046 Network Service Discovery (Discovery)
- **Signal:** anomalous distinct-port fan-out **and** a high failed-connection ratio.
- **Logic:** flag hosts with `distinct_resp_ports` z-score `>= 3` **and**
  `failed_conn_ratio >= 0.3` (REJ/S0/RSTO states).
- **FP notes:** vulnerability scanners and asset-inventory tools scan legitimately —
  allowlist their source IPs. Requiring the failure ratio avoids flagging a busy but
  successful host.
- **Tuning knobs:** `port_z_min`, `failed_ratio_min`.

## D005 — Internal Lateral Movement
- **Type:** rule
- **ATT&CK:** T1021 Remote Services (Lateral Movement)
- **Signal:** a workstation opening **established** admin-protocol sessions
  (SMB/WinRM/RDP) to many internal peers.
- **Logic:** keep internal flows on ports {445,3389,5985,5986,135,139} with
  `conn_state == SF` and `total_bytes > 1000`; flag sources reaching `>= 3` peers.
- **Key FP discriminator:** scanning produces *failed, zero-byte* probes on admin
  ports; lateral movement produces *completed sessions that move data*. Requiring
  `SF` + byte transfer is what keeps the D004 scanner out of this detection.
- **FP notes:** IT admin hosts, patch/config-management (SCCM/Ansible) fan out
  legitimately — maintain an admin-host allowlist.
- **Tuning knobs:** `min_targets`.

## D006 — Known-Bad IOC Contact (intel-driven)
- **Type:** rule + intel
- **ATT&CK:** T1071 / T1071.004 Application Layer Protocol (Command & Control)
- **Signal:** any connection to an IOC IP, or DNS resolution of an IOC domain, present
  in the threat-intel feed.
- **Logic:** exact IP match on `conn.resp_h`; domain match (incl. parent) on
  `dns.query`.
- **Value:** corroborates behavioral findings (raises their score) and catches threats
  the behavioral detections might miss. Severity tracks indicator confidence.
- **FP notes:** stale/low-confidence indicators cause noise — weight by feed
  confidence and age; expire indicators.

---

## Coverage summary

| Tactic | Techniques covered |
|--------|--------------------|
| Discovery | T1046 |
| Lateral Movement | T1021 |
| Command & Control | T1071, T1071.001, T1071.004 |
| Exfiltration | T1030, T1048.001 |

Gaps to extend next: Collection (T1074 staging), Credential Access over the wire
(Kerberoasting patterns), and encrypted-SNI / DoH blind spots for DNS detections.
