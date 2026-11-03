"""Finding model: ATT&CK + Diamond Model, severity scoring, de-duplication.

A detection does not return a raw alert; it returns a Finding that carries the
context an analyst needs to triage without pivoting to the raw logs:
  - what fired and why (title, rationale, evidence)
  - how it maps to MITRE ATT&CK (tactic + technique)
  - how it maps to the Diamond Model (adversary / capability / infrastructure /
    victim) so related findings can be correlated into a campaign
  - a severity score derived from confidence and impact

Keeping this deliberately small and explainable is the point: the value is in
the behavioral detection and the hunt, not in heavyweight alert plumbing.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Severity ordering for sorting / reporting.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class DiamondModel:
    """The four core vertices of the Diamond Model of intrusion analysis."""

    adversary: str = "unknown"
    capability: str = ""          # the TTP / tooling
    infrastructure: str = ""      # IPs / domains used
    victim: str = ""              # affected host / asset

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class Finding:
    detection_id: str             # e.g. "D001"
    title: str
    severity: str                 # critical|high|medium|low|info
    confidence: float             # 0..1
    src_host: str
    attack_tactic: str
    attack_technique: str         # e.g. "T1071.001"
    attack_technique_name: str
    rationale: str                # why this fired, in plain language
    evidence: dict[str, Any] = field(default_factory=dict)
    diamond: DiamondModel = field(default_factory=DiamondModel)
    intel: list[dict[str, Any]] = field(default_factory=list)

    # ---- derived ----
    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    @property
    def score(self) -> float:
        """0-100 priority score = impact(severity) * confidence, intel-boosted."""
        base = self.severity_rank / 4 * 100
        score = base * self.confidence
        if self.intel:
            # corroborating intel raises priority (capped at 100)
            score = min(100.0, score + 15)
        return round(score, 1)

    def dedup_key(self) -> tuple:
        return (self.detection_id, self.src_host, self.attack_technique)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["score"] = self.score
        return d

    def summary_line(self) -> str:
        intel_tag = "  [INTEL]" if self.intel else ""
        return (
            f"[{self.severity.upper():8s}] {self.detection_id} "
            f"score={self.score:5.1f}  {self.src_host:12s} "
            f"{self.attack_technique:11s} {self.title}{intel_tag}"
        )


def dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings, keeping the highest-scoring instance."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = f.dedup_key()
        if key not in best or f.score > best[key].score:
            best[key] = f
    return sorted(best.values(), key=lambda f: f.score, reverse=True)
