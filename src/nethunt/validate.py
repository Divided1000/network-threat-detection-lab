"""Purple-team detection-coverage validation harness.

This closes the loop between offense and defense: instead of trusting that the
detections work, we declare the attacks we expect to catch (each tied to a MITRE
ATT&CK technique and a ground-truth host), run the detection suite against the
telemetry those attacks produced, and measure coverage.

Output is an ATT&CK-style coverage report: for every emulated technique, did a
detection fire on the right host? This is exactly the "attack testing automation
to validate detection coverage" workflow a detection engineer owns, and it lets
CI fail when a code change silently regresses coverage.

Design note: the attack scenarios here are the *specification* of expected
behavior. The synthetic generator (`generate.py`) is the attack emulation that
produces the matching telemetry. Keeping the spec separate from the generator is
what makes this a validation oracle rather than a tautology — a detection can
pass the generator's ground truth yet still be asserted here against an
independent, technique-level expectation (host + ATT&CK ID + detection ID).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .baseline import build_host_baseline
from .detections import run_all
from .findings import Finding, dedup
from .ingest import load_all
from .intel import load_intel


@dataclass(frozen=True)
class AttackScenario:
    """One emulated attack, as an independent coverage expectation."""

    scenario_id: str          # e.g. "AS-C2-BEACON"
    name: str
    attack_tactic: str
    attack_technique: str     # MITRE ATT&CK technique id
    attacker_host: str        # ground-truth source host
    expected_detection: str   # detection id that should fire (e.g. "D001")


# The emulation plan. Each entry corresponds to one injector in generate.py,
# but is declared here independently so the harness validates behavior, not the
# generator's own bookkeeping.
SCENARIOS: list[AttackScenario] = [
    AttackScenario(
        "AS-C2-BEACON", "Timed C2 beaconing over TLS",
        "Command and Control", "T1071.001", "10.10.0.22", "D001",
    ),
    AttackScenario(
        "AS-DNS-TUNNEL", "Data exfiltration via DNS tunneling",
        "Exfiltration", "T1048.001", "10.10.0.31", "D002",
    ),
    AttackScenario(
        "AS-EXFIL-VOL", "Bulk outbound data exfiltration",
        "Exfiltration", "T1030", "10.10.0.18", "D003",
    ),
    AttackScenario(
        "AS-SCAN", "Internal network service discovery (scan)",
        "Discovery", "T1046", "10.10.0.27", "D004",
    ),
    AttackScenario(
        "AS-LATERAL", "Lateral movement over admin protocols",
        "Lateral Movement", "T1021", "10.10.0.14", "D005",
    ),
    AttackScenario(
        "AS-IOC-C2", "Contact with known-bad C2 infrastructure",
        "Command and Control", "T1071", "10.10.0.19", "D006",
    ),
]


@dataclass
class ScenarioResult:
    scenario: AttackScenario
    detected: bool
    matched_findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "DETECTED" if self.detected else "MISSED"


@dataclass
class CoverageReport:
    results: list[ScenarioResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def detected(self) -> int:
        return sum(1 for r in self.results if r.detected)

    @property
    def missed(self) -> list[ScenarioResult]:
        return [r for r in self.results if not r.detected]

    @property
    def coverage_pct(self) -> float:
        if not self.results:
            return 0.0
        return round(100.0 * self.detected / self.total, 1)

    def technique_coverage(self) -> dict[str, bool]:
        """Map each ATT&CK technique -> whether every scenario for it was caught."""
        cov: dict[str, bool] = {}
        for r in self.results:
            tech = r.scenario.attack_technique
            cov[tech] = cov.get(tech, True) and r.detected
        return cov


def _matches(scenario: AttackScenario, findings: list[Finding]) -> list[Finding]:
    """A scenario is covered when a finding fires on its host for its detection.

    We match on (detection_id, host). The ATT&CK technique is validated separately
    so a detection that fires but with the wrong technique is still caught as a
    mapping error.
    """
    return [
        f
        for f in findings
        if f.detection_id == scenario.expected_detection
        and f.src_host == scenario.attacker_host
    ]


def validate(findings: list[Finding], scenarios: list[AttackScenario] | None = None) -> CoverageReport:
    scenarios = scenarios or SCENARIOS
    results = []
    for s in scenarios:
        matched = _matches(s, findings)
        results.append(ScenarioResult(scenario=s, detected=bool(matched), matched_findings=matched))
    return CoverageReport(results=results)


def run_validation(data_dir: str = "data", intel_path: str | None = "data/intel_feed.json") -> CoverageReport:
    """Load telemetry, run detections, and validate coverage against SCENARIOS."""
    data = load_all(data_dir)
    baseline = build_host_baseline(data["conn"], data["dns"])
    feed = load_intel(intel_path) if intel_path and Path(intel_path).exists() else None
    findings = dedup(run_all(data["conn"], data["dns"], baseline, feed))
    return validate(findings)


def technique_mapping_errors(report: CoverageReport) -> list[str]:
    """Scenarios where NO matched finding carried the expected ATT&CK technique.

    A single detection may legitimately emit several related techniques (e.g. D006
    reports both T1071 for an IP contact and the T1071.004 sub-technique for the
    DNS resolution). The mapping is correct as long as at least one matched finding
    carries the technique the scenario expects; it is only an error when the
    expected technique is absent entirely.
    """
    errors = []
    for r in report.results:
        if not r.matched_findings:
            continue
        techniques = {f.attack_technique for f in r.matched_findings}
        if r.scenario.attack_technique not in techniques:
            errors.append(
                f"{r.scenario.scenario_id}: expected {r.scenario.attack_technique}, "
                f"detection reported {sorted(techniques)}"
            )
    return errors


# ---------------------------------------------------------------------------
# CLI  (python -m nethunt.validate)
# ---------------------------------------------------------------------------

def _render(report: CoverageReport) -> None:
    print("=" * 78)
    print("NetHunt — detection coverage validation (purple team)")
    print("=" * 78)
    print(f"{'SCENARIO':16s} {'TECHNIQUE':11s} {'HOST':12s} {'DET':4s} STATUS")
    print("-" * 78)
    for r in report.results:
        s = r.scenario
        flag = "ok " if r.detected else "!! "
        print(
            f"{s.scenario_id:16s} {s.attack_technique:11s} {s.attacker_host:12s} "
            f"{s.expected_detection:4s} {flag}{r.status}"
        )
    print("-" * 78)
    print(f"Coverage: {report.detected}/{report.total} scenarios "
          f"({report.coverage_pct}%)")

    # ATT&CK technique roll-up
    tcov = report.technique_coverage()
    covered = sum(1 for v in tcov.values() if v)
    print(f"ATT&CK techniques covered: {covered}/{len(tcov)}  "
          f"[{', '.join(t for t, ok in tcov.items() if ok)}]")

    if report.missed:
        print("\nMISSED:")
        for r in report.missed:
            print(f"  {r.scenario.scenario_id} ({r.scenario.attack_technique}) "
                  f"on {r.scenario.attacker_host} — expected {r.scenario.expected_detection}")

    errs = technique_mapping_errors(report)
    if errs:
        print("\nATT&CK MAPPING ERRORS:")
        for e in errs:
            print(f"  {e}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate detection coverage against emulated attacks."
    )
    parser.add_argument("--data", default="data")
    parser.add_argument("--intel", default="data/intel_feed.json")
    parser.add_argument(
        "--min-coverage", type=float, default=100.0,
        help="fail (exit 1) if coverage %% is below this threshold (CI gate)",
    )
    args = parser.parse_args()

    report = run_validation(args.data, args.intel)
    _render(report)

    mapping_ok = not technique_mapping_errors(report)
    if report.coverage_pct < args.min_coverage or not mapping_ok:
        reason = []
        if report.coverage_pct < args.min_coverage:
            reason.append(f"coverage {report.coverage_pct}% < {args.min_coverage}%")
        if not mapping_ok:
            reason.append("ATT&CK mapping errors")
        print(f"\nFAIL: {'; '.join(reason)}")
        raise SystemExit(1)
    print("\nPASS: all emulated techniques detected with correct ATT&CK mapping.")


if __name__ == "__main__":
    main()
