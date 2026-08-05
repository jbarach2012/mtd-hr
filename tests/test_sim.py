"""Tests for metrics, the log generator, and the simulator."""

import numpy as np

from mtd_hr.config import ExperimentConfig
from mtd_hr.metrics import (
    compliance_risk,
    encryption_ratio,
    mttc,
    mutation_cost,
    spread,
    summarize_runs,
)
from mtd_hr.sim import MTDSimulator
from mtd_hr.sim.log_generator import HRLogGenerator


def test_mttc():
    assert mttc([0.0, 1.0], [2.0, 4.0]) == 2.5


def test_encryption_ratio():
    assert encryption_ratio(20.0, 100.0) == 0.2
    assert encryption_ratio(5.0, 0.0) == 0.0


def test_mutation_cost():
    assert mutation_cost({"a": 2.0, "b": 1.0}, {"a": 1, "b": 3}) == 5.0


def test_spread():
    assert abs(spread([0.5, 0.5], [2.0, 4.0]) - 3.0) < 1e-9


def test_compliance_risk():
    assert compliance_risk([1.0, 2.0, 3.0], [False, True, True]) == 5.0


def test_summarize_runs():
    runs = [{"acc": 0.8}, {"acc": 0.82}, {"acc": 0.84}]
    agg = summarize_runs(runs)
    assert abs(agg["acc"]["mean"] - 0.82) < 1e-9
    assert agg["acc"]["ci95"] >= 0


def test_log_generator_attack_ratio():
    gen = HRLogGenerator(seed=1, benign_ratio=0.85)
    events = gen.session("payroll", 2000)
    attack_frac = sum(e["label"] for e in events) / len(events)
    # Should be near 15% (paper's skew), with tolerance.
    assert 0.10 <= attack_frac <= 0.20


def test_log_generator_fields():
    gen = HRLogGenerator(seed=1)
    events = gen.session("exit", 100)
    for e in events:
        assert set(e.keys()) >= {"module", "label", "inter_arrival", "payload_bucket"}
        assert e["label"] in (0, 1)


def test_simulator_mtd_reduces_encryption():
    cfg = ExperimentConfig()
    cfg.sim.n_runs = 3
    cfg.sim.events_per_session = 800
    cfg.detect.baseline_window = 200

    full = MTDSimulator(cfg, mtd_enabled=True).run()
    baseline = MTDSimulator(cfg, mtd_enabled=False).run()

    full_enc = np.mean([r["encryption_rate"] for r in full])
    base_enc = np.mean([r["encryption_rate"] for r in baseline])
    # MTD should reduce encryption success relative to no-MTD baseline.
    assert full_enc < base_enc


def test_simulator_metrics_present():
    cfg = ExperimentConfig()
    cfg.sim.n_runs = 2
    cfg.sim.events_per_session = 600
    cfg.detect.baseline_window = 150
    runs = MTDSimulator(cfg).run()
    for r in runs:
        for key in ("accuracy", "precision", "recall", "f1", "fpr",
                    "mttc", "encryption_rate"):
            assert key in r
