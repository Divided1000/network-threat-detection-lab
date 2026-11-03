# Hunt Methodology

How the hunt in [`notebooks/threat_hunt.ipynb`](../notebooks/threat_hunt.ipynb) is run,
written so it is repeatable by someone else and defensible in review.

## 1. Hypothesis-driven, not alert-driven

The hunt starts from a hypothesis, not an alert:

> An actor is using the network such that each individual connection looks legitimate,
> but whose behavior *over time* deviates from the host's own normal pattern.

This framing targets exactly the threats signatures miss — low-and-slow C2, insider
exfil, tunneling — and is the reason the engine is built on **baselining** rather than
per-event rules.

## 2. The loop

```
hypothesis -> baseline normal -> score deviations -> corroborate with intel
     ^                                                          |
     +---------------- new indicators / refined hypothesis <----+
```

1. **Normalize** both Zeek logs into one schema (`ingest`), so hunt logic is
   source-agnostic.
2. **Baseline** each host behaviorally (`baseline`) using robust median/MAD statistics
   so attack-sized outliers cannot poison their own baseline.
3. **Score deviations** per hypothesis — beacon regularity (CV), outbound-volume
   z-score, DNS entropy/length, port fan-out + failure ratio, admin-session fan-out.
4. **Corroborate** with the threat-intel feed (`intel`) to raise confidence and
   attribute an adversary.
5. **Map** each confirmed behavior to ATT&CK + the Diamond Model.
6. **Close the loop** — unattributed infrastructure found during the hunt is promoted
   to new intel indicators, so the next hunt starts smarter.

## 3. Why robust statistics

Mean/standard-deviation baselines are self-defeating for exfiltration: the single huge
upload you want to catch inflates the mean and shrinks its own z-score. Median and MAD
(median absolute deviation) are resistant to outliers, so the attack stays an outlier.
`robust_z()` scales MAD by 1.4826 to be comparable to a normal-distribution std.

## 4. Separating look-alikes (false-positive discipline)

The clearest example is **scanning vs lateral movement** — both touch admin ports on
many internal hosts. The discriminator is connection outcome:

- **Scan (D004):** failed, zero-byte probes (REJ/S0/RSTO).
- **Lateral movement (D005):** *established* sessions (`SF`) that transfer data.

Keying each detection on connection state keeps the scanner out of the lateral-movement
bucket. Every detection in the [catalog](detection_catalog.md) carries its own FP notes
and tuning knobs for the same reason.

## 5. Reproducibility

- The dataset is generated from a fixed seed (`build_world(seed=1337)`), so the hunt and
  its findings are identical on every run and diffable in review.
- The notebook is generated from `notebooks/_build_notebook.py` and executed with
  `jupyter nbconvert --execute`, so its outputs are never stale relative to the code.
- 27 unit tests assert each detection fires on its known attacker and stays quiet on
  benign hosts, so a logic regression fails CI rather than silently degrading coverage.

## 6. From hunt to durable detection

A finding in the notebook is not the deliverable — the codified detection is. Anything
proven useful in the interactive hunt is promoted into `detections.py` with a test, so
it runs automatically in the pipeline (`python -m nethunt.cli`) forever after. That is
the hand-off from *hunting* to *detection engineering*.
