"""End-to-end pipeline + analyst report.

Runs ingest -> baseline -> detections -> intel enrichment -> prioritized report.
This is the batch/automation face of the project; the investigative, narrative
face is notebooks/threat_hunt.ipynb.

Usage:
    python -m nethunt.cli --data data/ --intel data/intel_feed.json
    python -m nethunt.cli --data data/ --json findings.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .baseline import build_host_baseline
from .detections import run_all
from .findings import dedup
from .ingest import load_all
from .intel import load_intel


def run_pipeline(data_dir: str, intel_path: str | None):
    data = load_all(data_dir)
    baseline = build_host_baseline(data["conn"], data["dns"])
    feed = load_intel(intel_path) if intel_path else None
    findings = dedup(run_all(data["conn"], data["dns"], baseline, feed))
    return findings, data, baseline, feed


def _print_report(findings) -> None:
    print("=" * 78)
    print("NetHunt — prioritized findings")
    print("=" * 78)
    if not findings:
        print("No findings.")
        return
    for f in findings:
        print(f.summary_line())
    print("-" * 78)
    print(f"{len(findings)} findings total. Top finding detail:\n")
    top = findings[0]
    print(f"  {top.detection_id}  {top.title}")
    print(f"  host        : {top.src_host}")
    print(f"  ATT&CK      : {top.attack_technique} {top.attack_technique_name}")
    print(f"               ({top.attack_tactic})")
    print(f"  severity    : {top.severity}  score={top.score}")
    print(f"  rationale   : {top.rationale}")
    d = top.diamond
    print("  Diamond     :")
    print(f"     adversary      = {d.adversary}")
    print(f"     capability     = {d.capability}")
    print(f"     infrastructure = {d.infrastructure}")
    print(f"     victim         = {d.victim}")
    if top.intel:
        print(f"  intel match : {top.intel[0].get('threat')} "
              f"(confidence={top.intel[0].get('confidence')})")


def main() -> None:
    parser = argparse.ArgumentParser(description="NetHunt detection pipeline.")
    parser.add_argument("--data", default="data", help="dir with conn.log/dns.log")
    parser.add_argument("--intel", default=None, help="path to intel feed JSON")
    parser.add_argument("--json", default=None, help="write findings JSON to path")
    args = parser.parse_args()

    findings, _data, _baseline, _feed = run_pipeline(args.data, args.intel)
    _print_report(findings)

    if args.json:
        Path(args.json).write_text(
            json.dumps([f.as_dict() for f in findings], indent=2, default=str)
        )
        print(f"\nWrote {len(findings)} findings -> {args.json}")


if __name__ == "__main__":
    main()
