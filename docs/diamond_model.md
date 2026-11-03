# Diamond Model Analysis — "APT-DEMO" Campaign

The Diamond Model frames an intrusion around four linked vertices — **adversary,
capability, infrastructure, victim** — plus meta-features. Below, the NetHunt findings
are correlated into a single campaign instead of six isolated alerts. This is the
analytic leap from *alerting* to *tracking a threat cluster*.

## The four vertices

```
                 ADVERSARY
                 APT-DEMO (intel: high confidence)
                /                         \
               / develops / uses           \ targets
              /                             \
       CAPABILITY ---------- over ---------- INFRASTRUCTURE
       - timed TLS C2 beacon                 - 185.220.101.45  (beacon C2)
       - DNS tunneling exfil                 - 193.201.9.7     (known C2)
       - bulk TLS exfil                      - malicious-c2.example (C2 domain)
       - SMB/WinRM/RDP lateral move          - exfil-cdn.net   (tunnel)
              \                             - 45.133.1.77     (exfil sink)
               \ employed against           /
                \                           /
                 VICTIM
                 Corporate /24: hosts .14 .18 .19 .22 .27 .31
                 Crown-jewel: file share 10.10.0.5
```

## Vertex detail

### Adversary
- Attributed cluster **APT-DEMO** via high-confidence intel on `193.201.9.7` and
  `malicious-c2.example` (D006). The beaconing infra (`185.220.101.45`) is tagged
  `COMMODITY-BEACON` — possibly shared/rented infrastructure, a common meta-feature.
- The internal scanning + lateral movement (`.27`, `.14`) show **post-compromise
  operator activity**, not just malware calling home.

### Capability
| Capability | Evidence | Detection | ATT&CK |
|-----------|----------|-----------|--------|
| Timed C2 beacon over TLS | 60s interval, CV 0.015 | D001 | T1071.001 |
| DNS tunneling exfil | 400 high-entropy TXT queries | D002 | T1048.001 |
| Bulk data exfil | 4 GB to one external sink | D003 | T1030 |
| Network discovery | port/host fan-out, failed conns | D004 | T1046 |
| Lateral movement | established SMB/WinRM/RDP to 10 peers | D005 | T1021 |
| Known C2 usage | contact with intel IOCs | D006 | T1071 |

### Infrastructure
- **C2:** `185.220.101.45`, `193.201.9.7` / `malicious-c2.example`
- **Exfil:** `exfil-cdn.net` (DNS tunnel), `45.133.1.77` (bulk sink, bulletproof-hosted)
- Meta-feature: mix of attributed and commodity infra suggests staged tooling.

### Victim
- Immediate victims: workstations `.14 .18 .19 .22 .27 .31`.
- Target of interest: internal file share `10.10.0.5` (crown-jewel data store from the
  [threat model](threat_model.md)).

## Activity thread (kill-chain ordering)

1. **C2 established** — `.22` beacons to `185.220.101.45` (T1071.001).
2. **Discovery** — `.27` scans the internal `/24` (T1046).
3. **Lateral movement** — `.14` opens admin sessions to 10 peers (T1021).
4. **Collection + Exfiltration** — `.18` ships 4 GB to a sink (T1030); `.31` tunnels
   data over DNS (T1048.001).
5. **Corroboration** — `.19` contacts known APT-DEMO C2 (T1071), anchoring attribution.

## Why this matters operationally

Treating these as one campaign changes the response: instead of closing six medium/high
alerts, the analyst scopes a single intrusion, pivots on shared infrastructure, and
feeds the two **unattributed** external IPs (`185.220.101.45`, `45.133.1.77`) back into
the intel feed as new indicators — converting a one-off hunt into durable, long-term
coverage (campaign tracking → countermeasures).
