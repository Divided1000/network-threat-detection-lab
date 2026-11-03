"""Tests for the purple-team detection-coverage validation harness."""
from nethunt.detections import run_all
from nethunt.findings import dedup
from nethunt.validate import (
    SCENARIOS,
    validate,
    technique_mapping_errors,
)


def _findings(conn, dns, baseline, feed):
    return dedup(run_all(conn, dns, baseline, feed))


# ---------------- coverage ----------------

def test_full_coverage_on_seeded_dataset(conn, dns, baseline, feed):
    report = validate(_findings(conn, dns, baseline, feed))
    assert report.coverage_pct == 100.0
    assert report.detected == report.total == len(SCENARIOS)
    assert report.missed == []


def test_every_scenario_detected(conn, dns, baseline, feed):
    report = validate(_findings(conn, dns, baseline, feed))
    for r in report.results:
        assert r.detected, f"{r.scenario.scenario_id} was not detected"


def test_no_attack_mapping_errors(conn, dns, baseline, feed):
    report = validate(_findings(conn, dns, baseline, feed))
    assert technique_mapping_errors(report) == []


def test_every_technique_covered(conn, dns, baseline, feed):
    report = validate(_findings(conn, dns, baseline, feed))
    tcov = report.technique_coverage()
    assert all(tcov.values()), f"uncovered techniques: {tcov}"


# ---------------- the oracle actually catches misses ----------------

def test_harness_flags_a_miss_when_findings_removed(conn, dns, baseline, feed):
    """If a detection's findings disappear, the harness must report a MISS.

    This is the whole point of a validation oracle: it has to fail when coverage
    regresses, not just pass when everything works.
    """
    findings = _findings(conn, dns, baseline, feed)
    # simulate D001 (beaconing) being broken/disabled: drop its findings
    degraded = [f for f in findings if f.detection_id != "D001"]
    report = validate(degraded)

    assert report.coverage_pct < 100.0
    missed_ids = {r.scenario.scenario_id for r in report.missed}
    assert "AS-C2-BEACON" in missed_ids


def test_harness_flags_mapping_error_when_technique_wrong(conn, dns, baseline, feed):
    """A detection firing on the right host but wrong technique is a mapping error."""
    findings = _findings(conn, dns, baseline, feed)
    # corrupt the technique on the beaconing finding
    for f in findings:
        if f.detection_id == "D001":
            f.attack_technique = "T9999"
    report = validate(findings)
    errs = technique_mapping_errors(report)
    assert any("AS-C2-BEACON" in e for e in errs)


# ---------------- scenarios reference real detections ----------------

def test_scenarios_map_to_real_detection_ids(conn, dns, baseline, feed):
    findings = _findings(conn, dns, baseline, feed)
    emitted_detection_ids = {f.detection_id for f in findings}
    for s in SCENARIOS:
        assert s.expected_detection in emitted_detection_ids, (
            f"{s.scenario_id} expects {s.expected_detection}, which no detection emitted"
        )


def test_scenarios_are_unique():
    ids = [s.scenario_id for s in SCENARIOS]
    assert len(ids) == len(set(ids))
