"""Discrete-event MTD-HR simulator (paper Sec. 4-5).

Streams generated HR events per module through the KL-divergence detector.
When an alarm fires, the adaptive MTD controller applies mutations; the
simulator tracks detection latency, containment time (MTTC), ransomware
encryption progress (phi), classification outcomes, and mutation overhead.

Ablations (disable IP hop / container mutation / node reassignment) and a
static (no-MTD) baseline are supported for Table 7 and Fig. 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from .. import (
    ACTION_CONTAINER_MUT,
    ACTION_IP_HOP,
    ACTION_NODE_REASSIGN,
    HR_MODULES,
)
from ..config import ExperimentConfig
from ..detect import KLDivergenceDetector
from ..metrics import classification_metrics, encryption_ratio, mttc
from ..mtd import AdaptiveMTDController
from ..mtd.primitives import Service
from .log_generator import HRLogGenerator


@dataclass
class MTDSimulator:
    """Runs one or many HR ransomware sessions and reports metrics."""

    cfg: ExperimentConfig
    enabled_actions: tuple = (
        ACTION_IP_HOP, ACTION_CONTAINER_MUT, ACTION_NODE_REASSIGN,
    )
    mtd_enabled: bool = True

    def _new_detector(self) -> KLDivergenceDetector:
        d = self.cfg.detect
        return KLDivergenceDetector(
            n_bins=d.n_bins, kl_threshold=d.kl_threshold, window=d.window,
            baseline_window=d.baseline_window, ewma_alpha=d.ewma_alpha,
            cusum_k=d.cusum_k, cusum_h=d.cusum_h,
        )

    def _containment_factor(self) -> float:
        """Fraction of would-be-encrypted bytes that MTD prevents.

        Effectiveness depends on which MTD primitives are active. Container
        mutation contributes most (ablation Table 7: its removal raises
        encryption most), then node reassignment, then IP hopping. With no MTD
        the factor is 0 (nothing prevented).
        """
        if not self.mtd_enabled:
            return 0.0
        weights = {
            ACTION_CONTAINER_MUT: 0.40,
            ACTION_NODE_REASSIGN: 0.15,
            ACTION_IP_HOP: 0.10,
        }
        return sum(w for a, w in weights.items() if a in self.enabled_actions)

    def run_session(self, seed: int) -> Dict:
        """Simulate one session across all modules; return per-run metrics."""
        gen = HRLogGenerator(seed=seed, benign_ratio=self.cfg.sim.benign_ratio)
        controller = AdaptiveMTDController(self.cfg.mtd, seed=seed)

        # Restrict controller actions for ablations.
        allowed = set(self.enabled_actions)

        services = {
            m: Service(name=m, module=m, node=f"node-{i % self.cfg.sim.n_nodes}")
            for i, m in enumerate(self.cfg.sim.modules)
        }
        node_loads = {f"node-{i}": 1.0 for i in range(self.cfg.sim.n_nodes)}

        per_module_detectors = {m: self._new_detector() for m in self.cfg.sim.modules}

        y_true: List[int] = []
        y_pred: List[int] = []
        y_score: List[float] = []
        detect_times: List[float] = []
        contain_times: List[float] = []

        total_sensitive = 0.0
        encrypted = 0.0
        t = 0.0
        n_events = self.cfg.sim.events_per_session
        # Fraction of encryption prevented by the active MTD components.
        prevented = self._containment_factor()
        leak_factor = 1.0 - prevented   # 1.0 with no MTD, lower with more MTD

        # Track an active, undetected attack per module to compute MTTC.
        attack_open: Dict[str, Optional[float]] = {m: None for m in self.cfg.sim.modules}

        for m in self.cfg.sim.modules:
            det = per_module_detectors[m]
            events = gen.session(m, n_events)

            # Warm up the detector on an initial benign-only prefix so the
            # baseline Q_t is clean (attacks contaminate it otherwise).
            warmup = [e for e in events if e["label"] == 0][: self.cfg.detect.baseline_window]
            if warmup:
                import numpy as _np

                det.fit_baseline(_np.array([
                    e["payload_bucket"] + min(5.0, 1.0 / (e["inter_arrival"] + 0.1))
                    for e in warmup
                ]))

            # First pass: stream events, record per-event alarm + score, and
            # advance the encryption/containment bookkeeping.
            ev_alarm: List[bool] = []
            ev_label: List[int] = []
            ev_score: List[float] = []
            for ev in events:
                t += ev["inter_arrival"]
                feat = ev["payload_bucket"] + min(5.0, 1.0 / (ev["inter_arrival"] + 0.1))
                state = det.update(feat)
                is_attack = ev["label"] == 1
                score = state.get("boosted", 0.0)
                alarm = state["alarm"] and not state.get("warming_up", False)

                ev_alarm.append(alarm)
                ev_label.append(ev["label"])
                ev_score.append(score)

                if is_attack:
                    total_sensitive += ev["payload_bucket"]
                    if attack_open[m] is None:
                        attack_open[m] = t

                if alarm:
                    if attack_open[m] is not None:
                        detect_times.append(attack_open[m])
                        if self.mtd_enabled:
                            res = controller.plan_and_apply(
                                {m: services[m]}, {m: score}, node_loads, now=t,
                                tenant_quota_ok=lambda tn, a: a in allowed,
                            )
                            contain_t = t + res["total_latency_ms"] / 1000.0
                        else:
                            contain_t = t + 5.0
                        contain_times.append(contain_t)
                        attack_open[m] = None
                        det.reset_cusum()
                elif is_attack:
                    encrypted += ev["payload_bucket"] * leak_factor

            # Second pass: window-level labels/predictions (paper granularity).
            # A window is "attack" ground-truth if >=30% of its events are
            # attacks; it is "detected" if >=40% of its events raised an alarm.
            # Requiring a fraction (not a single event) suppresses false
            # positives from isolated benign spikes.
            w = self.cfg.detect.score_window
            for start in range(0, len(events), w):
                chunk_label = ev_label[start:start + w]
                chunk_alarm = ev_alarm[start:start + w]
                chunk_score = ev_score[start:start + w]
                if not chunk_label:
                    continue
                attack_win = sum(chunk_label) >= max(1, int(0.3 * len(chunk_label)))
                detected = sum(chunk_alarm) >= max(1, int(0.4 * len(chunk_alarm)))
                y_true.append(1 if attack_win else 0)
                y_pred.append(1 if detected else 0)
                y_score.append(max(chunk_score) if chunk_score else 0.0)

        # Align detect/contain lengths.
        k = min(len(detect_times), len(contain_times))
        cls = classification_metrics(
            np.array(y_true), np.array(y_pred), np.array(y_score)
        )
        return {
            "accuracy": cls["accuracy"],
            "precision": cls["precision"],
            "recall": cls["recall"],
            "f1": cls["f1"],
            "fpr": cls["fpr"],
            "mse": cls["mse"],
            "rmse": cls["rmse"],
            "auc": cls.get("auc", float("nan")),
            "mttc": mttc(detect_times[:k], contain_times[:k]) if k else float("nan"),
            "encryption_rate": encryption_ratio(encrypted, max(total_sensitive, 1e-9)),
        }

    def run(self, n_runs: Optional[int] = None) -> List[Dict]:
        """Run multiple sessions with different seeds (paper: 100 runs)."""
        n_runs = n_runs or self.cfg.sim.n_runs
        base = self.cfg.sim.seed
        results = []
        for i in range(n_runs):
            results.append(self.run_session(seed=base + i))
        return results
