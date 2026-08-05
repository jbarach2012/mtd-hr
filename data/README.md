# Data directory

Datasets are not committed. Generate the synthetic HR logs used in the
experiments (no download needed):

    python scripts/make_synthetic_data.py --out data/hr_logs --events 2000

See `scripts/download_data.py` for the optional public datasets referenced by
the paper (Employee/Kaggle, CIC Ransomware 2020, UNSW-NB15, CTU-13) — all used
only at the statistics level.
