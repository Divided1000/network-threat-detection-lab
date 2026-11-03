"""Tests for ingest normalization, baseline stats, and the finding model."""
import math

from conftest import GROUND_TRUTH

from nethunt.ingest import shannon_entropy
from nethunt.baseline import robust_z, beacon_scores
from nethunt.findings import Finding, DiamondModel, dedup


# ---------------- ingest ----------------

def test_entropy_low_for_repetitive_string():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_high_for_random_string():
    assert shannon_entropy("a1b2c3d4e5f6g7h8") > 3.0


def test_conn_schema_normalized(conn):
    for col in ("ts", "orig_h", "resp_h", "resp_p", "orig_bytes", "total_bytes", "hour"):
        assert col in conn.columns
    assert conn["resp_p"].dtype.kind in "iu"      # integer port
    assert (conn["hour"] >= 0).all() and (conn["hour"] <= 23).all()


def test_dns_derived_features(dns):
    for col in ("qname_len", "entropy", "parent_domain"):
        assert col in dns.columns
    # the tunnel host's queries should have the highest entropy in the set
    top = dns.sort_values("entropy", ascending=False).iloc[0]
    assert top["orig_h"] == GROUND_TRUTH["dns_tunnel"]


# ---------------- baseline ----------------

def test_robust_z_flags_outlier():
    import pandas as pd
    s = pd.Series([10, 11, 9, 10, 12, 10_000])  # one huge outlier
    z = robust_z(s)
    assert z.iloc[-1] > 10            # outlier strongly flagged
    assert abs(z.iloc[0]) < 3         # normal points stay small


def test_robust_z_handles_constant_series():
    import pandas as pd
    z = robust_z(pd.Series([5, 5, 5, 5]))
    assert (z == 0).all()             # no variance => no anomaly, no divide-by-zero


def test_beacon_regularity_ranks_c2_first(conn):
    scores = beacon_scores(conn)
    assert not scores.empty
    # the most regular (lowest CV) pair should be the beacon host -> its C2
    top = scores.iloc[0]
    assert top["orig_h"] == GROUND_TRUTH["beaconing"]
    assert top["cv"] < 0.1


# ---------------- findings ----------------

def _mk(**kw):
    base = dict(
        detection_id="D999", title="t", severity="high", confidence=0.9,
        src_host="10.0.0.1", attack_tactic="TA", attack_technique="T1",
        attack_technique_name="n", rationale="r",
    )
    base.update(kw)
    return Finding(**base)


def test_score_scales_with_severity_and_confidence():
    hi = _mk(severity="critical", confidence=1.0)
    lo = _mk(severity="low", confidence=0.5)
    assert hi.score > lo.score


def test_intel_raises_score():
    without = _mk()
    with_intel = _mk(intel=[{"threat": "x"}])
    assert with_intel.score > without.score


def test_dedup_keeps_highest_scoring():
    a = _mk(confidence=0.5)
    b = _mk(confidence=0.95)  # same dedup key, higher score
    out = dedup([a, b])
    assert len(out) == 1
    assert out[0].confidence == 0.95


def test_diamond_model_serializes():
    d = DiamondModel(adversary="APT-X", capability="c", infrastructure="1.1.1.1", victim="h")
    assert d.as_dict()["adversary"] == "APT-X"
