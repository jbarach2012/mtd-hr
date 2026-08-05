"""Typed configuration for MTD-HR.

Defaults encode the paper's reported setup (Sec. 4-5): 3-node Kubernetes
cluster, ~85% benign / 15% ransomware traffic skew, 30-min sessions repeated
100x, 60-s mutation interval as the favourable trade-off, KL-divergence
detection threshold, and the cost/compliance trade-off weight lambda.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import List

import yaml

from . import HR_MODULES


@dataclass
class SimConfig:
    """HR traffic + ransomware simulation settings (paper Sec. 4)."""

    modules: List[str] = field(default_factory=lambda: list(HR_MODULES))
    n_nodes: int = 3               # 3-node Kubernetes cluster
    session_minutes: int = 30      # each session lasted 30 min
    n_runs: int = 100              # repeated 100 times for averaging
    events_per_session: int = 2000
    benign_ratio: float = 0.85     # ~85% benign / 15% ransomware
    seed: int = 42
    # Employee dataset (Kaggle) used to seed identities/roles/departments.
    employee_csv: str = ""         # optional; synthetic identities if empty


@dataclass
class DetectConfig:
    """KL-divergence anomaly detector (paper Sec. 3.9, Eq. 8)."""

    n_bins: int = 16               # histogram bins for P_t / Q_t
    kl_threshold: float = 3.0     # epsilon: divergence threshold
    window: int = 10               # sliding window of events for P_t
    score_window: int = 10         # chunk size for window-level scoring
    baseline_window: int = 300     # events used to learn Q_t
    ewma_alpha: float = 0.3        # EWMA booster
    cusum_k: float = 0.5           # CUSUM slack
    cusum_h: float = 8.0           # CUSUM decision threshold


@dataclass
class MTDConfig:
    """Moving Target Defense controller settings (paper Sec. 3, Algorithm 1)."""

    mutation_interval_s: float = 60.0   # favourable trade-off (Sec. 5)
    min_mutation_interval_s: float = 10.0  # T_min cooldown
    lambda_cost: float = 0.5            # trade-off weight (Eq. 7)
    cpu_budget: float = 100.0           # B_cpu
    mem_budget: float = 100.0           # B_mem
    # Per-action resource costs (relative units) and latencies (ms), seeded
    # from Table 4 so the simulator's overhead matches the paper's profile.
    ip_hop_cost: float = 3.2
    container_mut_cost: float = 9.5
    node_reassign_cost: float = 16.0
    ip_hop_latency_ms: float = 38.0
    container_mut_latency_ms: float = 114.0
    node_reassign_latency_ms: float = 192.0
    # Compliance (GDPR/SOC 2) risk weight per non-compliant placement (Eq. 12).
    compliance_weight: float = 1.0


@dataclass
class ExperimentConfig:
    sim: SimConfig = field(default_factory=SimConfig)
    detect: DetectConfig = field(default_factory=DetectConfig)
    mtd: MTDConfig = field(default_factory=MTDConfig)
    output_dir: str = "outputs"

    @classmethod
    def from_yaml(cls, path: str) -> "ExperimentConfig":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return cls(
            sim=SimConfig(**(raw.get("sim") or {})),
            detect=DetectConfig(**(raw.get("detect") or {})),
            mtd=MTDConfig(**(raw.get("mtd") or {})),
            output_dir=raw.get("output_dir", "outputs"),
        )

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)
