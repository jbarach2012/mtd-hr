#!/usr/bin/env bash
# Run the MTD-HR pipeline end-to-end.
#
#   ./scripts/run_all.sh          # quick run (5 seeds)
#   ./scripts/run_all.sh full     # full run (100 seeds, as in the paper)

set -euo pipefail
MODE="${1:-quick}"

echo "==> Generating synthetic HR access logs"
python scripts/make_synthetic_data.py --out data/hr_logs --events 2000

if [[ "$MODE" == "full" ]]; then
  CFG=configs/default.yaml
else
  CFG=configs/smoke.yaml
fi

echo "==> Running MTD-HR experiment (${CFG})"
python -m mtd_hr.run --config "${CFG}"

OUT=$(python -c "import yaml;print(yaml.safe_load(open('${CFG}'))['output_dir'])")
echo "==> Plotting figures"
python scripts/plot_results.py --summary "${OUT}/summary.json" --outdir figures || true

echo "==> Done. Metrics in ${OUT}/summary.json"
