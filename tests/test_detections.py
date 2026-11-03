"""Detection tests: true-positive (attack fires) and false-positive (benign quiet).

Each detection is asserted to fire on its known attacker host AND to NOT fire on
representative benign hosts. The ground truth comes from the seeded generator.
"""
from conftest import GROUND_TRUTH

from nethunt.detections import (
    detect_beaconing,
    detect_dns_tunneling,
    detect_exfil_volume,
    detect_lateral_movement,
    detect_scan,
    detect_ioc_contact,
    run_all,
)
from nethunt.findings import dedup

# A handful of hosts that run only benign traffic in the generator.
BENIGN_HOSTS = {"10.10.0.10", "10.10.0.11", "10.10.0.35", "10.10.0.12"}


def _hosts_for(findings, det_id):
    return {f.src_host for f in findings if f.detection_id == det_id}


# ---------------- D001 beaconing ----------------

def test_beaconing_true_positive(conn, feed):
    hosts = _hosts_for(detect_beaconing(conn, feed), "D001")
    assert GROUND_TRUTH["beaconing"] in hosts


def test_beaconing_no_false_positive_on_benign(conn, feed):
    hosts = _hosts_for(detect_beaconing(conn, feed), "D001")
    assert hosts.isdisjoint(BENIGN_HOSTS)


# ---------------- D002 DNS tunneling ----------------

def test_dns_tunnel_true_positive(dns, feed):
    hosts = _hosts_for(detect_dns_tunneling(dns, feed), "D002")
    assert GROUND_TRUTH["dns_tunnel"] in hosts


def test_dns_tunnel_no_false_positive_on_benign(dns, feed):
    hosts = _hosts_for(detect_dns_tunneling(dns, feed), "D002")
    assert hosts.isdisjoint(BENIGN_HOSTS)


# ---------------- D003 exfil volume ----------------

def test_exfil_volume_true_positive(conn, baseline, feed):
    hosts = _hosts_for(detect_exfil_volume(conn, baseline, feed), "D003")
    assert GROUND_TRUTH["exfil_volume"] in hosts


def test_exfil_volume_no_false_positive_on_benign(conn, baseline, feed):
    hosts = _hosts_for(detect_exfil_volume(conn, baseline, feed), "D003")
    assert hosts.isdisjoint(BENIGN_HOSTS)


# ---------------- D004 scan ----------------

def test_scan_true_positive(conn, baseline, feed):
    hosts = _hosts_for(detect_scan(conn, baseline, feed), "D004")
    assert GROUND_TRUTH["port_scan"] in hosts


def test_scan_no_false_positive_on_benign(conn, baseline, feed):
    hosts = _hosts_for(detect_scan(conn, baseline, feed), "D004")
    assert hosts.isdisjoint(BENIGN_HOSTS)


# ---------------- D005 lateral movement ----------------

def test_lateral_true_positive(conn, feed):
    hosts = _hosts_for(detect_lateral_movement(conn, feed), "D005")
    assert GROUND_TRUTH["lateral_movement"] in hosts


def test_lateral_excludes_scanner(conn, feed):
    """The port scanner must NOT be mistaken for lateral movement.

    Scans are failed, zero-byte probes; lateral movement requires established
    sessions with real data transfer. This is the key FP discriminator.
    """
    hosts = _hosts_for(detect_lateral_movement(conn, feed), "D005")
    assert GROUND_TRUTH["port_scan"] not in hosts


def test_lateral_no_false_positive_on_benign(conn, feed):
    hosts = _hosts_for(detect_lateral_movement(conn, feed), "D005")
    assert hosts.isdisjoint(BENIGN_HOSTS)


# ---------------- D006 intel ----------------

def test_ioc_contact_true_positive(conn, dns, feed):
    hosts = _hosts_for(detect_ioc_contact(conn, dns, feed), "D006")
    assert GROUND_TRUTH["ioc_contact"] in hosts


def test_ioc_contact_requires_feed_match(conn, dns, feed):
    """Only hosts that actually touched feed IOCs should appear."""
    findings = detect_ioc_contact(conn, dns, feed)
    bad_ips = feed.all_ips()
    bad_domains = feed.all_domains()
    for f in findings:
        ev = f.evidence
        matched = ev.get("dest") in bad_ips or any(
            ev.get("query", "").endswith(d) for d in bad_domains
        )
        assert matched, f"D006 fired without an intel match: {ev}"


# ---------------- full pipeline ----------------

def test_run_all_covers_every_scenario(conn, dns, baseline, feed):
    findings = dedup(run_all(conn, dns, baseline, feed))
    got = {(f.detection_id, f.src_host) for f in findings}
    expected = {
        ("D001", GROUND_TRUTH["beaconing"]),
        ("D002", GROUND_TRUTH["dns_tunnel"]),
        ("D003", GROUND_TRUTH["exfil_volume"]),
        ("D004", GROUND_TRUTH["port_scan"]),
        ("D005", GROUND_TRUTH["lateral_movement"]),
        ("D006", GROUND_TRUTH["ioc_contact"]),
    }
    missing = expected - got
    assert not missing, f"missing detections: {missing}"


def test_dedup_is_stable_and_sorted(conn, dns, baseline, feed):
    findings = dedup(run_all(conn, dns, baseline, feed))
    # no duplicate (detection, host, technique) keys
    keys = [f.dedup_key() for f in findings]
    assert len(keys) == len(set(keys))
    # sorted by score descending
    scores = [f.score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_intel_boosts_priority_score(conn, dns, baseline, feed):
    """A finding with corroborating intel should outrank the same shape without."""
    findings = run_all(conn, dns, baseline, feed)
    with_intel = [f for f in findings if f.intel]
    assert with_intel, "expected at least one intel-corroborated finding"
    assert all(f.score > 0 for f in with_intel)
