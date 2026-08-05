"""HR access-log generator (paper Sec. 4).

Produces synthetic HR access events across the five modules with a realistic
~85% benign / 15% ransomware skew. Benign events use per-module inter-arrival
and payload-size distributions; ransomware events follow staged templates
(discovery -> lateral movement -> staging -> encryption) modelled after CIC
Ransomware 2020 *timing/ordering only* (no packet fields are copied — see the
paper's data-handling controls).

The mapping from network-style fields to HR event fields follows Table 2:
    arrival rate     -> user action rate per service
    flow size        -> document-size bucket
    service/port     -> HR endpoint class (payroll, records, leave, ...)
    dest IP          -> pod/node identifier
    label            -> benign or ransomware stage

Identities/roles/departments can be seeded from the Kaggle Employee dataset
(ref [44]); if none is supplied, synthetic identities are generated.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

from .. import ATTACK_STAGES, HR_MODULES

# Per-module benign behaviour: (mean inter-arrival s, payload-size mean bucket).
_MODULE_PROFILE = {
    "onboarding":       (2.0, 3.0),
    "employee_records": (1.5, 2.0),
    "leave":            (2.5, 1.5),
    "payroll":          (1.2, 4.0),
    "exit":             (3.0, 1.0),
}


@dataclass
class HRLogGenerator:
    """Generate benign + ransomware HR access events."""

    seed: int = 42
    benign_ratio: float = 0.85
    n_roles: int = 8
    n_departments: int = 5

    def __post_init__(self):
        self._rng = np.random.default_rng(self.seed)
        self._roles = [f"role_{i}" for i in range(self.n_roles)]
        self._depts = [f"dept_{i}" for i in range(self.n_departments)]

    def _benign_event(self, module: str) -> dict:
        ia_mean, sz_mean = _MODULE_PROFILE[module]
        return {
            "module": module,
            "user": f"u{self._rng.integers(0, 500)}",
            "role": self._rng.choice(self._roles),
            "department": self._rng.choice(self._depts),
            "inter_arrival": float(self._rng.exponential(ia_mean)),
            "payload_bucket": float(max(0.0, self._rng.normal(sz_mean, 0.5))),
            "endpoint": module,
            "stage": "benign",
            "label": 0,
        }

    def _ransomware_event(self, module: str, stage: str) -> dict:
        # Ransomware stages: fast, bursty access with progressively larger and
        # more irregular payloads, peaking at the encryption stage (spikes in
        # access frequency and unusual endpoints).
        stage_idx = ATTACK_STAGES.index(stage)
        ia = float(self._rng.exponential(0.15 / (1 + stage_idx)))
        sz = float(self._rng.normal(8.0 + 3.0 * stage_idx, 1.0))
        return {
            "module": module,
            "user": f"adv{self._rng.integers(0, 10)}",
            "role": "unknown",
            "department": self._rng.choice(self._depts),
            "inter_arrival": ia,
            "payload_bucket": sz,
            "endpoint": self._rng.choice(HR_MODULES),  # lateral probing
            "stage": stage,
            "label": 1,
        }

    def session(self, module: str, n_events: int) -> List[dict]:
        """Generate one module's event stream for a session.

        Attacks occur in occasional multi-stage bursts, but the overall
        attack fraction is calibrated to ``1 - benign_ratio`` so the class
        skew matches the paper (~85% benign / 15% ransomware).
        """
        target_attacks = int(round(n_events * (1.0 - self.benign_ratio)))
        events: List[dict] = []
        in_attack = False
        stage_ptr = 0
        attacks_emitted = 0

        for _ in range(n_events):
            remaining = n_events - len(events)
            # Probability of *starting* a new burst, tuned to hit the target
            # attack count given a typical burst length of ~len(ATTACK_STAGES).
            if not in_attack and attacks_emitted < target_attacks:
                burst_len = len(ATTACK_STAGES) + 2
                start_p = max(0.0, (target_attacks - attacks_emitted) /
                              max(remaining, 1) / burst_len)
                if self._rng.random() < start_p:
                    in_attack = True
                    stage_ptr = 0

            if in_attack and attacks_emitted < target_attacks:
                stage = ATTACK_STAGES[min(stage_ptr, len(ATTACK_STAGES) - 1)]
                events.append(self._ransomware_event(module, stage))
                attacks_emitted += 1
                stage_ptr += 1
                if stage_ptr > len(ATTACK_STAGES) + self._rng.integers(0, 3):
                    in_attack = False
            else:
                events.append(self._benign_event(module))
        return events


def generate_dataset(
    out_dir: str,
    modules: Optional[List[str]] = None,
    events_per_module: int = 2000,
    benign_ratio: float = 0.85,
    seed: int = 42,
) -> str:
    """Write a CSV of HR access events (one file, all modules)."""
    modules = modules or list(HR_MODULES)
    gen = HRLogGenerator(seed=seed, benign_ratio=benign_ratio)
    rows: List[dict] = []
    for m in modules:
        rows.extend(gen.session(m, events_per_module))

    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "hr_access_logs.csv")
    fields = ["module", "user", "role", "department", "inter_arrival",
              "payload_bucket", "endpoint", "stage", "label"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    n_atk = sum(r["label"] for r in rows)
    print(f"Wrote {len(rows)} events to {path} ({100*n_atk/len(rows):.1f}% ransomware)")
    return path
