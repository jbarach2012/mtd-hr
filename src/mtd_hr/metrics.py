"""Evaluation metrics (paper Sec. 3.6-3.13, 5).

  * MTTC = E[t_r - t_d]                          (Eq. 9)
  * encryption success ratio phi(t)             (Eq. 10)
  * mutation cost C_mtd(t)                        (Eq. 5)
  * ransomware spread Psi(t)                      (Eq. 6)
  * compliance risk R_c                           (Eq. 12)
  * classification metrics (accuracy, FPR, precision, recall, F1, MSE, RMSE)
    and AUC for the ROC/PR analyses (Tables 3, 6, 8).
"""

from __future__ import annotations

from typing import Dict, List

import numpy as np


def mttc(detect_times: List[float], contain_times: List[float]) -> float:
    """Mean Time To Containment E[t_r - t_d] (Eq. 9)."""
    if not detect_times:
        return float("nan")
    deltas = [tr - td for td, tr in zip(detect_times, contain_times)]
    return float(np.mean(deltas))


def encryption_ratio(encrypted_bytes: float, total_sensitive_bytes: float) -> float:
    """phi(t) = encrypted / total sensitive (Eq. 10)."""
    if total_sensitive_bytes <= 0:
        return 0.0
    return float(encrypted_bytes / total_sensitive_bytes)


def mutation_cost(service_weights: Dict[str, float],
                  triggered: Dict[str, int]) -> float:
    """C_mtd(t) = sum_i R(s_i) * delta(s_i, t) (Eq. 5)."""
    return float(sum(service_weights.get(s, 1.0) * triggered.get(s, 0)
                     for s in triggered))


def spread(infection_probs: List[float], encryption_effects: List[float]) -> float:
    """Psi(t) = sum_v p(v,t) * e(v) (Eq. 6)."""
    return float(np.dot(np.asarray(infection_probs), np.asarray(encryption_effects)))


def compliance_risk(weights: List[float], violations: List[bool]) -> float:
    """R_c = sum_i gamma_i * I(s_i not in P_gdpr) (Eq. 12)."""
    return float(sum(w for w, v in zip(weights, violations) if v))


def classification_metrics(y_true: np.ndarray, y_pred: np.ndarray,
                           y_score: np.ndarray = None) -> Dict[str, float]:
    """Accuracy, FPR, precision, recall, F1, MSE, RMSE (+AUC if scores given).

    Reproduces the columns in Tables 3 and 6.
    """
    from sklearn.metrics import (
        accuracy_score,
        f1_score,
        mean_squared_error,
        precision_score,
        recall_score,
    )

    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    mse = mean_squared_error(y_true, y_pred)
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "mse": float(mse),
        "rmse": float(np.sqrt(mse)),
    }
    if y_score is not None:
        try:
            from sklearn.metrics import roc_auc_score

            out["auc"] = float(roc_auc_score(y_true, y_score))
        except Exception:
            pass
    return out


def summarize_runs(runs: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
    """Mean/std/95% CI across repeated runs (paper: 100 runs)."""
    keys = runs[0].keys()
    out = {}
    for k in keys:
        vals = np.array([r[k] for r in runs], dtype=np.float64)
        mean = float(vals.mean())
        std = float(vals.std(ddof=1)) if len(vals) > 1 else 0.0
        ci = 1.96 * std / np.sqrt(len(vals)) if len(vals) > 1 else 0.0
        out[k] = {"mean": mean, "std": std, "ci95": float(ci)}
    return out
