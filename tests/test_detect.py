"""Tests for the KL-divergence detector."""

import numpy as np

from mtd_hr.detect import KLDivergenceDetector, kl_divergence


def test_kl_identical_is_zero():
    p = np.array([1.0, 2.0, 3.0, 4.0])
    assert abs(kl_divergence(p, p)) < 1e-9


def test_kl_nonnegative():
    p = np.array([0.5, 0.5])
    q = np.array([0.9, 0.1])
    assert kl_divergence(p, q) >= 0


def test_detector_flags_shifted_distribution():
    rng = np.random.default_rng(0)
    det = KLDivergenceDetector(kl_threshold=3.0, window=10, cusum_h=999)
    det.fit_baseline(rng.normal(3.0, 0.5, 300))
    # Benign traffic: few alarms.
    benign_alarms = sum(det.update(v)["alarm"] for v in rng.normal(3.0, 0.5, 200))
    # Attack traffic: strongly shifted -> many alarms.
    attack_alarms = sum(det.update(v)["alarm"] for v in rng.normal(9.0, 1.0, 200))
    assert attack_alarms > benign_alarms
    assert attack_alarms > 100  # high recall on clearly-shifted data


def test_detector_warms_up_before_fit():
    det = KLDivergenceDetector(baseline_window=50)
    # Before enough data, updates should not alarm.
    states = [det.update(1.0) for _ in range(10)]
    assert all(not s["alarm"] for s in states)


def test_reset_cusum():
    det = KLDivergenceDetector(kl_threshold=0.1, window=5, cusum_h=1.0)
    det.fit_baseline(np.zeros(50))
    for _ in range(20):
        det.update(100.0)
    det.reset_cusum()
    assert det._cusum == 0.0
