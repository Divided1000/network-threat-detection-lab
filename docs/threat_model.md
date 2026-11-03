# Threat Model — NetHunt Monitored Environment

This is a TTP-based threat model for the environment NetHunt observes: a corporate
`/24` of workstations with a few internal servers and egress to the internet. The
goal is to decide **what to log and what to detect**, which is the first job of a
detection engineer.

## 1. Assets

| Asset | Why it matters | Primary threat |
|-------|----------------|----------------|
| Workstations (`10.10.0.10-39`) | Hold user data, creds, session tokens | Compromise -> C2, exfil, pivot |
| File share (`10.10.0.5:445`) | Concentrated sensitive data | Bulk collection / exfil |
| Internal DNS (`10.10.0.7`) | Resolver all hosts trust | Covert channel (tunneling) |
| Internet egress | Data leaves here | Exfiltration, C2 |

## 2. Trust boundaries

1. **Host ↔ internal network** — a compromised workstation can reach peers and
   servers (lateral movement, internal recon).
2. **Internal network ↔ internet** — the egress boundary where C2 and exfil cross.
3. **Host ↔ DNS resolver** — every host implicitly trusts DNS; this is abused for
   tunneling because DNS is rarely inspected as a data channel.

## 3. Actors

- **External attacker** with an initial foothold (phishing/exploit, out of scope
  here) who now needs C2, discovery, and exfil.
- **Malicious insider** with legitimate access who abuses it to stage and exfil
  data. Hardest case: their traffic is "authorized" one event at a time.

## 4. TTP-based threats (what we model and detect)

Modeled on MITRE ATT&CK tactics, mapped to the detections that cover them:

| Tactic | Technique | How it shows on the wire | Detection |
|--------|-----------|--------------------------|-----------|
| Command & Control | T1071.001 Web protocols | Regular timed callouts | D001 |
| Command & Control | T1071 / T1071.004 | Contact with known-bad infra/domain | D006 |
| Exfiltration | T1048 Alt protocol | High-entropy DNS labels | D002 |
| Exfiltration | T1030 Transfer size | Large one-way byte volume | D003 |
| Discovery | T1046 Service discovery | Port/host fan-out, failed conns | D004 |
| Lateral Movement | T1021 Remote services | SMB/WinRM/RDP to many peers | D005 |

## 5. Logging decisions (detect/prevent controls)

The model drives concrete logging requirements:

- **Zeek `conn.log`** — per-flow summaries give timing (beaconing), volume (exfil),
  ports/states (scanning), and internal admin sessions (lateral movement).
- **Zeek `dns.log`** — query names and types are required to catch tunneling; without
  DNS logging the covert channel is invisible.
- **Retention over a full baseline window** — behavioral detection needs enough
  history to learn "normal" per host; point-in-time logging defeats it.

Prevention controls the model recommends (out of scope for detection code but part of
the architecture review): egress filtering/allowlisting, DNS egress through inspected
resolvers only, and network segmentation to shrink the lateral-movement blast radius.

## 6. What this model deliberately excludes

Initial access, host-level execution/persistence, and credential theft are assumed to
happen off-wire; NetHunt is a **network-behavior** sensor and models only what is
observable in flow and DNS telemetry. A complete program pairs this with endpoint
(EDR) and identity telemetry.
