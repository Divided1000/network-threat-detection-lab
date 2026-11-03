# NetHunt — Network Anomaly Detection & Intel-Driven Threat Hunting

A detection-engineering project that ingests **Zeek-style network logs** (connection +
DNS), establishes per-host behavioral baselines, and runs a mix of **statistical anomaly
detection** and **rule-based detections** to surface insider-threat and external-attack
behavior. Every finding is mapped to **MITRE ATT&CK** and modeled with the **Diamond Model**,
then enriched against a **threat-intel IOC feed** for intel-driven hunting.

The project is built to mirror the day-to-day of a Detection & Response engineer:
model the threat, decide what to log, write the detection, validate it against both
true-positive and false-positive traffic, and hand an analyst context instead of a raw alert.

---

## Why this exists

Rule-only detection misses the behavior that defines insider threats and modern C2:
low-and-slow beaconing, DNS tunneling, and abnormal data volume all look like valid
traffic one connection at a time. NetHunt baselines what *normal* looks like per host and
flags deviations, so detections key on **behavior over time**, not single events.

## Architecture

```
          synthetic Zeek logs (conn.log, dns.log)
                        |
                 [ ingest / normalize ]      -> common event schema (pandas)
                        |
          +-------------+--------------------+
          |                                  |
   [ baseline engine ]               [ rule detections ]
   per-host/user stats               ATT&CK-mapped signatures
          |                                  |
          +-------------+--------------------+
                        |
                 [ findings model ]  severity scoring + de-dup
                 ATT&CK technique + Diamond Model vertices
                        |
                 [ intel enrichment ]  IOC feed match
                        |
             CLI report  +  Jupyter hunt notebook
```

## Detections

| ID | Detection | Type | ATT&CK |
|----|-----------|------|--------|
| D001 | C2 beaconing (regular inter-arrival) | anomaly | T1071.001 / T1573 |
| D002 | DNS tunneling / exfil (entropy + length) | anomaly | T1071.004 / T1048 |
| D003 | Data exfiltration volume spike | anomaly | T1030 / T1048 |
| D004 | Port / host scan fan-out | rule+anomaly | T1046 |
| D005 | Internal lateral movement | rule | T1021 |
| D006 | Known-bad IOC contact (intel) | rule | T1071 |

Full catalog with rationale and tuning notes: [`docs/detection_catalog.md`](docs/detection_catalog.md).

## Quick start

```bash
# 1. set up env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. generate the synthetic dataset (deterministic)
python -m nethunt.generate --out data/

# 3. run the full detection pipeline
python -m nethunt.cli --data data/ --intel data/intel_feed.json

# 4. validate detection coverage (purple team)
python -m nethunt.validate --data data/ --intel data/intel_feed.json

# 5. (optional) run the hunt notebook
jupyter notebook notebooks/threat_hunt.ipynb

# 6. run tests
pytest -q
```

## Layout

```
src/nethunt/
  generate.py     synthetic Zeek conn/dns log generator (seeded)
  ingest.py       parse + normalize logs into the common schema
  baseline.py     per-host behavioral baselining
  detections.py   anomaly + rule detections, ATT&CK/Diamond mapping
  intel.py        IOC feed loading + enrichment
  findings.py     finding model, severity scoring, de-dup
  cli.py          end-to-end pipeline + analyst report
  validate.py     purple-team attack-emulation + coverage validation
data/             generated logs + sample intel feed
notebooks/        threat-hunt notebook
docs/             threat model, detection catalog, Diamond Model, coverage
tests/            pytest TP/FP coverage
```

## Blue + purple

NetHunt is primarily a **blue-team** (defensive) tool — it baselines, detects, hunts,
and triages. It also ships the **purple-team** loop: `validate.py` emulates a set of
ATT&CK-mapped attacks, runs the detections against the telemetry they produce, and
reports **detection coverage** (which techniques were caught vs missed). That validation
gates CI, so a change that silently breaks a detection fails the build. See
[detection coverage](docs/detection_coverage.md).

## Documentation

- [Threat model](docs/threat_model.md) — assets, actors, STRIDE/TTP view
- [Detection catalog](docs/detection_catalog.md) — every detection, mapping, tuning
- [Diamond Model analysis](docs/diamond_model.md) — one campaign fully modeled
- [Hunt methodology](docs/hunt_methodology.md) — how the notebook hunt is run
- [Detection coverage](docs/detection_coverage.md) — purple-team attack validation

---

## What this demonstrates (for reviewers)

- **Network traffic analysis** — detections built directly on Zeek `conn.log` and
  `dns.log` (timing, volume, ports, connection state, DNS entropy).
- **Behavioral / insider-threat detection** — per-host baselining with robust
  statistics, not single-event signatures.
- **Threat hunting** — a hypothesis-driven Jupyter hunt that closes the loop by
  promoting findings to new intel indicators.
- **Intel-driven hunting** — IOC-feed enrichment that corroborates and prioritizes.
- **Threat modeling** — a TTP-based threat model and a full Diamond Model campaign
  analysis, with every detection mapped to MITRE ATT&CK.
- **Purple-team validation** — an attack-emulation harness that measures detection
  coverage against ATT&CK and gates CI on it.
- **Detection engineering rigor** — TP/FP unit tests (incl. the scan-vs-lateral
  discriminator), deterministic data, and CI.

## Results (deterministic, seed 1337)

6 injected TTPs across 30 hosts and ~6k flows; all 6 detected on the correct host,
0 false positives on benign hosts, 100% ATT&CK coverage in the validation harness,
35/35 tests passing.

| Detection | ATT&CK | Caught host |
|-----------|--------|-------------|
| D001 C2 beaconing | T1071.001 | 10.10.0.22 |
| D002 DNS tunneling | T1048.001 | 10.10.0.31 |
| D003 data exfil volume | T1030 | 10.10.0.18 |
| D004 network scan | T1046 | 10.10.0.27 |
| D005 lateral movement | T1021 | 10.10.0.14 |
| D006 known-bad IOC | T1071 | 10.10.0.19 |
