"""Prepare the public datasets referenced by the paper.

The MTD-HR evaluation uses **synthetic HR access logs** whose timing and attack
staging are shaped by public datasets (paper Sec. 4). No packet fields are
copied; only high-level statistics (inter-arrival, burst size, session length)
and attack ordering are matched. The datasets referenced are:

  1. Employee/HR Dataset (Kaggle) — seeds identities, roles, departments.
       https://www.kaggle.com/ds/3620223
  2. CIC Ransomware 2020 — informs attack-stage ordering/timing only.
       https://www.unb.ca/cic/datasets/ransomware.html
  3. UNSW-NB15 and CTU-13 — aggregate benign timing/burst statistics.
       https://research.unsw.edu.au/projects/unsw-nb15-dataset
       https://www.stratosphereips.org/datasets-ctu13

Because these require registration/licensing and are only used at the
*statistics* level, this repository ships a fully self-contained synthetic log
generator (``scripts/make_synthetic_data.py`` / ``mtd_hr.sim.log_generator``)
that reproduces the HR-domain traffic without any download. That is the
default and recommended path for reproduction.

This script only prints where to obtain the optional real datasets and, if a
Kaggle token is present, can fetch the Employee dataset to seed richer
identities.

Usage:
    python scripts/download_data.py                 # print sources
    python scripts/download_data.py --employee-kaggle   # fetch Kaggle employee set
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

SOURCES = """
Public datasets referenced by the paper (all optional — the synthetic
generator reproduces the experiments without them):

  1. Employee/HR Dataset (Kaggle) : https://www.kaggle.com/ds/3620223
  2. CIC Ransomware 2020          : https://www.unb.ca/cic/datasets/ransomware.html
  3. UNSW-NB15                    : https://research.unsw.edu.au/projects/unsw-nb15-dataset
  4. CTU-13                       : https://www.stratosphereips.org/datasets-ctu13

To generate the HR access logs used in the experiments (no download needed):
  python scripts/make_synthetic_data.py --out data/hr_logs
"""


def _fetch_employee_kaggle(out: str) -> None:
    os.makedirs(out, exist_ok=True)
    try:
        subprocess.run(
            ["kaggle", "datasets", "download", "-d", "ravindrasinghrana/employeedataset",
             "-p", out, "--unzip"],
            check=True,
        )
        print(f"Employee dataset downloaded to {out}/")
    except FileNotFoundError:
        print("The `kaggle` CLI is not installed. Run: pip install kaggle")
        print("Then place your token at ~/.kaggle/kaggle.json. See:")
        print("  https://www.kaggle.com/ds/3620223")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"Kaggle download failed: {exc}")
        print("Download manually from https://www.kaggle.com/ds/3620223")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--employee-kaggle", action="store_true",
                        help="Fetch the Kaggle Employee dataset (needs kaggle token).")
    parser.add_argument("--out", default="data/employee")
    args = parser.parse_args()

    if args.employee_kaggle:
        _fetch_employee_kaggle(args.out)
    else:
        print(SOURCES)


if __name__ == "__main__":
    main()
