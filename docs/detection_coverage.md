# Detection Coverage Validation (Purple Team)

Detections are only trustworthy if you prove they fire. This harness is the purple-team
half of the project: it emulates a set of attacks, declares what each *should* trigger,
runs the detection suite against the resulting telemetry, and measures coverage against
MITRE ATT&CK. It is the "attack testing automation to validate detection coverage"
workflow a detection engineer owns.

Run it:

```bash
PYTHONPATH=src python -m nethunt.validate --data data/ --intel data/intel_feed.json
```

## How it works

```
   attack scenarios (spec)        telemetry (emulation)
   AS-* : technique + host   +    generate.py injectors
            |                             |
            +-------------+---------------+
                          |
                 run detections
                          |
             match findings to scenarios
                          |
         coverage report  (ATT&CK technique -> detected / missed)
                          |
              CI gate: fail if coverage < threshold
```

Each `AttackScenario` is an **independent expectation**: an ATT&CK technique, the
ground-truth host, and the detection that should fire. The synthetic generator produces
the matching telemetry. Keeping the spec separate from the generator is what makes this
a validation *oracle* rather than a tautology — the harness also verifies that the
detection reported the **correct ATT&CK technique**, not just that something fired.

## Emulated scenarios

| Scenario | ATT&CK | Tactic | Host | Expected |
|----------|--------|--------|------|----------|
| AS-C2-BEACON | T1071.001 | Command & Control | 10.10.0.22 | D001 |
| AS-DNS-TUNNEL | T1048.001 | Exfiltration | 10.10.0.31 | D002 |
| AS-EXFIL-VOL | T1030 | Exfiltration | 10.10.0.18 | D003 |
| AS-SCAN | T1046 | Discovery | 10.10.0.27 | D004 |
| AS-LATERAL | T1021 | Lateral Movement | 10.10.0.14 | D005 |
| AS-IOC-C2 | T1071 | Command & Control | 10.10.0.19 | D006 |

## Current result

```
Coverage: 6/6 scenarios (100.0%)
ATT&CK techniques covered: 6/6
PASS: all emulated techniques detected with correct ATT&CK mapping.
```

## Why it gates CI

The harness exits non-zero when coverage drops below `--min-coverage` (default 100%) or
when a detection fires under the wrong ATT&CK technique. Wired into CI, that means a code
change which silently breaks a detection **fails the build** instead of quietly eroding
coverage — the same guard rail you want around production detections. The unit tests in
`tests/test_validate.py` prove the oracle itself works by asserting it reports a MISS when
a detection's findings are removed and a mapping error when a technique is corrupted.

## Extending it

Add a new `AttackScenario` to `SCENARIOS` in `validate.py` and a matching injector in
`generate.py`. In a production setting the emulation side would be driven by a framework
such as Atomic Red Team or Caldera, with the same scenario-spec/coverage-report loop.
