# MTD-HR: Enhancing Ransomware Resilience in Cloud-Based HR Systems through Moving Target Defense

Reference implementation for the **CMC (Computers, Materials & Continua)** paper:

> **Enhancing Ransomware Resilience in Cloud-Based HR Systems through Moving Target Defense**
> Jay Barach.
> *Computers, Materials & Continua*, 2026, Vol. 86, No. 2. Tech Science Press.
> DOI: **[10.32604/cmc.2025.071705](https://doi.org/10.32604/cmc.2025.071705)**

**MTD-HR** is a Moving Target Defense framework for Kubernetes-based HR SaaS. It combines **container mutation**, **IP hopping**, and **node reassignment** to randomize the attack surface without interrupting service, driven by a **KL-divergence–based anomaly detector** over HR access logs across five modules (onboarding, employee records, leave, payroll, exit). It is compliance-aware (GDPR / SOC 2) and cost-aware.

> **License.** Code is released under **[CC BY 4.0](http://creativecommons.org/licenses/by/4.0/)**. Copyright © 2025 The Author. If you use it, please cite the CMC paper above.

---

## What's implemented

Every formal component of the paper:

- **KL-divergence detector** (`mtd_hr.detect`) — the statistical detection trigger `D(s_i,t) = I(KL(P_t‖Q_t) > ε)` (Eq. 8) with EWMA and CUSUM boosters (Algorithm 1, line 4).
- **MTD primitives** (`mtd_hr.mtd`) — IP hopping (Eq. 3), container mutation (Eq. 4), node reassignment (Eq. 11), attack-surface model (Eq. 1), reconfiguration mapping (Eq. 2).
- **Cost-aware adaptive controller** (`mtd_hr.mtd.controller`) — the full **Algorithm 1**: utility `U_i(a) = ΔΨ_i(a) − λ·C_i(a) − R_c(a)`, budgeted greedy selection over CPU/memory, per-tenant quotas, and cooldowns.
- **Metrics** (`mtd_hr.metrics`) — MTTC (Eq. 9), encryption success ratio (Eq. 10), mutation cost (Eq. 5), spread (Eq. 6), compliance risk (Eq. 12), and full classification metrics.
- **HR log generator + simulator** (`mtd_hr.sim`) — synthetic HR access logs (~85% benign / 15% ransomware) with staged attacks, and a discrete-event simulator that runs the detector + controller and measures every metric, plus the ablation study (Table 7) and a no-MTD baseline.

---

## Reproduction note (please read)

The paper's headline detection figures (96.9% accuracy, 2.7% FPR) were obtained on the author's HR access logs, which are available from the author on request and are **not redistributed here**. This repository ships a **self-contained synthetic log generator** so the pipeline runs end-to-end with no downloads.

On the synthetic logs, the code faithfully reproduces the paper's **methodology and trends**:

- **MTD cuts ransomware encryption roughly 2–3× versus the no-MTD baseline** (the paper's core containment claim).
- **The ablation ordering matches Table 7**: removing **container mutation** hurts most, then **node reassignment**, then **IP hopping**.
- MTTC, mutation overhead, and compliance accounting behave as described.

Exact percentages (accuracy/FPR) depend on how separable benign and attack traffic are in the logs; on the synthetic set the detector operates around **85–90% accuracy**. To reproduce the paper's exact numbers, point the pipeline at the real HR logs (same code, same config). We deliberately did **not** tune the synthetic data to hit a target, which would be circular.

---

## Requirements & installation

- Python **3.9+** (no GPU needed — this is a simulation)

```bash
git clone https://github.com/<your-username>/mtd-hr.git
cd mtd-hr
python -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -e .           # core
pip install -e ".[viz]"    # matplotlib for figures
pip install -e ".[dev]"    # pytest, ruff
```

Console command: `mtd-hr-run` (equivalent to `python -m mtd_hr.run`).

---

## Quickstart

```bash
# generate synthetic HR logs + run the experiment + plot
bash scripts/run_all.sh          # quick (5 seeds)
bash scripts/run_all.sh full     # full (100 seeds, as in the paper)
```

Or step by step:

```bash
python scripts/make_synthetic_data.py --out data/hr_logs --events 2000
python -m mtd_hr.run --config configs/default.yaml
python scripts/plot_results.py --summary outputs/default/summary.json --outdir figures
```

Results (full system, static baseline, and the per-component ablation) are written to `outputs/default/summary.json` with mean, std, and 95% confidence intervals across runs.

---

## Datasets

The evaluation uses **synthetic HR access logs** whose timing/attack-staging are shaped by public datasets (paper Sec. 4). No packet fields are copied — only aggregate statistics and attack ordering. `scripts/download_data.py` prints where to obtain the optional real datasets:

| Dataset | Use | Link |
|---|---|---|
| Employee/HR (Kaggle) | seed identities/roles/departments | https://www.kaggle.com/ds/3620223 |
| CIC Ransomware 2020 | attack-stage ordering/timing only | https://www.unb.ca/cic/datasets/ransomware.html |
| UNSW-NB15 | aggregate benign timing/burst stats | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| CTU-13 | aggregate benign timing/burst stats | https://www.stratosphereips.org/datasets-ctu13 |

None are required — the synthetic generator reproduces the experiments on its own.

---

## Repository layout

```
mtd-hr/
├── src/mtd_hr/
│   ├── config.py          # typed configs (paper parameters as defaults)
│   ├── metrics.py         # MTTC, encryption ratio, cost, spread, compliance, classification
│   ├── run.py             # experiment runner (full + baseline + ablations)
│   ├── detect/
│   │   └── kl_detector.py # KL-divergence detector + EWMA/CUSUM (Eq. 8)
│   ├── mtd/
│   │   ├── primitives.py  # IP hopping, container mutation, node reassignment
│   │   └── controller.py  # cost-aware adaptive controller (Algorithm 1)
│   └── sim/
│       ├── log_generator.py # HR access-log generator (~85/15 skew)
│       └── simulator.py     # discrete-event MTD-HR simulator
├── configs/               # default + smoke configs
├── scripts/               # download_data, make_synthetic_data, plot_results, run_all
├── tests/                 # unit + integration tests
├── .github/workflows/     # CI
├── LICENSE  NOTICE  CITATION.cff  pyproject.toml  requirements.txt
```

---

## Paper → code mapping

| Paper element | Where |
|---|---|
| Attack surface F_attack(t) (Eq. 1) | `mtd.primitives.attack_surface` |
| Reconfiguration mapping (Eq. 2) | `mtd.primitives` (each `apply`) |
| IP hopping (Eq. 3) | `mtd.primitives.IPHopping` |
| Container mutation (Eq. 4) | `mtd.primitives.ContainerMutation` |
| Mutation cost (Eq. 5) | `metrics.mutation_cost`, controller cost model |
| Ransomware spread (Eq. 6) | `metrics.spread` |
| Optimisation objective (Eq. 7) | `mtd.controller` utility function |
| KL detection trigger (Eq. 8) | `detect.kl_detector.KLDivergenceDetector` |
| MTTC (Eq. 9) | `metrics.mttc` |
| Encryption success ratio (Eq. 10) | `metrics.encryption_ratio` |
| Node reassignment (Eq. 11) | `mtd.primitives.NodeReassignment` |
| Compliance risk (Eq. 12) | `metrics.compliance_risk`, controller penalty |
| Adaptive MTD algorithm (Algorithm 1) | `mtd.controller.AdaptiveMTDController` |
| Ablation study (Table 7) | `run.run_all` (per-component drop) |

---

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

CI runs the unit tests and an end-to-end smoke run on every push.

---

## Citation

**Paper (CMC 2026):**

```bibtex
@article{barach2025mtdhr,
  author  = {Barach, Jay},
  title   = {Enhancing Ransomware Resilience in Cloud-Based {HR} Systems through Moving Target Defense},
  journal = {Computers, Materials \& Continua},
  year    = {2025},
  volume  = {86},
  number  = {2},
  publisher = {Tech Science Press},
  doi     = {10.32604/cmc.2025.071705}
}
```

**Software:**

```bibtex
@software{barach2025mtdhr_code,
  author  = {Barach, Jay},
  title   = {{MTD-HR}: Moving Target Defense for Ransomware Resilience in Cloud-Based HR Systems},
  year    = {2025},
  version = {1.0.0},
  url     = {https://github.com/<your-username>/mtd-hr},
  note    = {Reference implementation for the CMC paper, DOI: 10.32604/cmc.2025.071705}
}
```

---

## License

Code: **CC BY 4.0** — see [`LICENSE`](LICENSE). Copyright © 2025 The Author.
