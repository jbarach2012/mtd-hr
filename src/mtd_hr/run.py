"""End-to-end experiment runner (paper Sec. 5).

Runs the full MTD-HR evaluation and writes a summary JSON:
  * overall + per-run aggregated metrics (Table 3, Table 6),
  * the ablation study over MTD components (Table 7),
  * a static (no-MTD) baseline for comparison.

Usage:
    python -m mtd_hr.run --config configs/default.yaml
    python -m mtd_hr.run --config configs/smoke.yaml     # fast
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Dict, List

from .config import ExperimentConfig
from .metrics import summarize_runs
from .sim import MTDSimulator
from .utils import set_seed, setup_logging
from . import (
    ACTION_CONTAINER_MUT,
    ACTION_IP_HOP,
    ACTION_NODE_REASSIGN,
)

logger = logging.getLogger(__name__)


def _aggregate(runs: List[Dict]) -> Dict:
    agg = summarize_runs(runs)
    return {k: round(v["mean"], 4) for k, v in agg.items()} | {
        "_std": {k: round(v["std"], 4) for k, v in agg.items()},
        "_ci95": {k: round(v["ci95"], 4) for k, v in agg.items()},
    }


def run_all(cfg: ExperimentConfig) -> Dict:
    set_seed(cfg.sim.seed)
    os.makedirs(cfg.output_dir, exist_ok=True)

    # 1) Full system.
    logger.info("Running full MTD-HR system (%d runs)...", cfg.sim.n_runs)
    full = MTDSimulator(cfg, mtd_enabled=True)
    full_runs = full.run()
    full_agg = _aggregate(full_runs)
    logger.info("Full system: acc=%.3f mttc=%.1fs enc=%.3f",
                full_agg["accuracy"], full_agg["mttc"], full_agg["encryption_rate"])

    # 2) Static baseline (no MTD).
    logger.info("Running static (no-MTD) baseline...")
    baseline = MTDSimulator(cfg, mtd_enabled=False)
    base_agg = _aggregate(baseline.run())

    # 3) Ablations: drop one MTD component at a time (Table 7).
    all_actions = (ACTION_IP_HOP, ACTION_CONTAINER_MUT, ACTION_NODE_REASSIGN)
    ablations = {}
    for drop in all_actions:
        enabled = tuple(a for a in all_actions if a != drop)
        sim = MTDSimulator(cfg, enabled_actions=enabled, mtd_enabled=True)
        ablations[f"without_{drop}"] = _aggregate(sim.run())
        logger.info("Ablation without %s: enc=%.3f mttc=%.1fs",
                    drop, ablations[f"without_{drop}"]["encryption_rate"],
                    ablations[f"without_{drop}"]["mttc"])

    summary = {
        "config": cfg.to_dict(),
        "full_system": full_agg,
        "static_baseline": base_agg,
        "ablations": ablations,
    }
    out = os.path.join(cfg.output_dir, "summary.json")
    with open(out, "w") as fh:
        json.dump(summary, fh, indent=2)
    logger.info("Wrote %s", out)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="MTD-HR experiment runner")
    parser.add_argument("--config", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--runs", type=int, default=None)
    args = parser.parse_args(argv)

    setup_logging()
    cfg = ExperimentConfig.from_yaml(args.config) if args.config else ExperimentConfig()
    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.runs:
        cfg.sim.n_runs = args.runs
    run_all(cfg)


if __name__ == "__main__":
    main()
