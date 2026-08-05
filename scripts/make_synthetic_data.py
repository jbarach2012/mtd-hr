"""Generate the synthetic HR access-log dataset used in the experiments.

Produces a CSV of HR access events across the five modules with a ~85% benign
/ 15% ransomware skew and staged attack behaviour (paper Sec. 4).

Usage:
    python scripts/make_synthetic_data.py --out data/hr_logs --events 2000
"""

from __future__ import annotations

import argparse

from mtd_hr.sim.log_generator import generate_dataset


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="data/hr_logs")
    parser.add_argument("--events", type=int, default=2000,
                        help="events per module")
    parser.add_argument("--benign-ratio", type=float, default=0.85)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    generate_dataset(
        out_dir=args.out,
        events_per_module=args.events,
        benign_ratio=args.benign_ratio,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
