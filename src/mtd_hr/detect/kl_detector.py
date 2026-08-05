"""KL-divergence anomaly detector (paper Sec. 3.9, Eq. 8; Algorithm 1 line 4).

Detection trigger:

    D(s_i, t) = I( KL(P_t || Q_t) > epsilon )

where P_t is the recent (windowed) traffic distribution for a service/module
and Q_t is the learned baseline. The raw KL score is optionally boosted with
EWMA smoothing and a CUSUM change detector, matching Algorithm 1's
"EWMA/CUSUM boosters".

Traffic features are discretised into histograms; any 1-D numeric feature
stream works (e.g. action inter-arrival time or payload-size bucket, per the
feature mapping in Table 2).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional

import numpy as np


def kl_divergence(p: np.ndarray, q: np.ndarray, eps: float = 1e-9) -> float:
    """KL(P || Q) for two discrete distributions (nats)."""
    p = np.asarray(p, dtype=np.float64) + eps
    q = np.asarray(q, dtype=np.float64) + eps
    p /= p.sum()
    q /= q.sum()
    return float(np.sum(p * np.log(p / q)))


def _histogram(values: np.ndarray, n_bins: int, value_range) -> np.ndarray:
    hist, _ = np.histogram(values, bins=n_bins, range=value_range)
    return hist.astype(np.float64)


@dataclass
class KLDivergenceDetector:
    """Windowed KL detector with EWMA + CUSUM boosters (per service/module)."""

    n_bins: int = 16
    kl_threshold: float = 0.35
    window: int = 50
    baseline_window: int = 500
    ewma_alpha: float = 0.3
    cusum_k: float = 0.5
    cusum_h: float = 5.0

    # internal state
    _baseline: Optional[np.ndarray] = field(default=None, repr=False)
    _value_range: Optional[tuple] = field(default=None, repr=False)
    _recent: Deque[float] = field(default=None, repr=False)
    _baseline_buf: Deque[float] = field(default=None, repr=False)
    _ewma: float = field(default=0.0, repr=False)
    _cusum: float = field(default=0.0, repr=False)
    _fitted: bool = field(default=False, repr=False)

    def __post_init__(self):
        self._recent = deque(maxlen=self.window)
        self._baseline_buf = deque(maxlen=self.baseline_window)

    # -- baseline learning --------------------------------------------------
    def fit_baseline(self, values: np.ndarray) -> "KLDivergenceDetector":
        """Learn Q_t from a benign baseline sample."""
        values = np.asarray(values, dtype=np.float64)
        lo, hi = float(values.min()), float(values.max())
        if hi <= lo:
            hi = lo + 1.0
        # Widen the range so anomalous (out-of-baseline) values land in
        # distinct edge bins rather than being clipped, preserving divergence.
        span = hi - lo
        self._value_range = (lo - span, hi + 2.0 * span)
        self._baseline = _histogram(values, self.n_bins, self._value_range)
        self._baseline /= max(self._baseline.sum(), 1.0)
        self._baseline_buf.extend(values.tolist())
        self._fitted = True
        return self

    # -- streaming update ---------------------------------------------------
    def update(self, value: float) -> dict:
        """Feed one event value; return the current detection state.

        Returns a dict with the raw KL score, boosted score, and an ``alarm``
        boolean (Eq. 8 indicator, OR the CUSUM trigger).
        """
        if not self._fitted:
            # Bootstrap baseline from the first events seen.
            self._baseline_buf.append(float(value))
            if len(self._baseline_buf) >= min(self.baseline_window, 50):
                self.fit_baseline(np.array(self._baseline_buf))
            return {"kl": 0.0, "boosted": 0.0, "alarm": False, "warming_up": True}

        self._recent.append(float(value))
        if len(self._recent) < max(5, self.window // 5):
            return {"kl": 0.0, "boosted": 0.0, "alarm": False, "warming_up": True}

        p = _histogram(np.array(self._recent), self.n_bins, self._value_range)
        kl = kl_divergence(p, self._baseline)

        # EWMA smoothing of the KL signal.
        self._ewma = self.ewma_alpha * kl + (1 - self.ewma_alpha) * self._ewma

        # CUSUM on the KL signal (detects sustained shifts). The accumulator
        # only grows on excess above (threshold + slack) and decays otherwise,
        # so benign noise near the threshold does not latch it high.
        excess = kl - (self.kl_threshold + self.cusum_k)
        self._cusum = max(0.0, self._cusum + excess)
        # Gentle decay when below threshold prevents slow benign drift alarms.
        if kl < self.kl_threshold:
            self._cusum = max(0.0, self._cusum - self.cusum_k)

        # Detection trigger per Eq. (8): the instantaneous windowed divergence
        # exceeding the threshold is the primary signal. EWMA and CUSUM are
        # retained as reported "boosters" for sustained shifts, but the
        # instantaneous term keeps benign windows from latching an alarm.
        alarm = (kl > self.kl_threshold) or (self._cusum > self.cusum_h)
        return {
            "kl": kl,
            "boosted": self._ewma,
            "cusum": self._cusum,
            "alarm": bool(alarm),
            "warming_up": False,
        }

    def score(self, value: float) -> float:
        """Convenience: return the boosted anomaly score for one event."""
        return self.update(value)["boosted"]

    def reset_cusum(self) -> None:
        """Reset the CUSUM accumulator (e.g. after a mutation contains a threat)."""
        self._cusum = 0.0
