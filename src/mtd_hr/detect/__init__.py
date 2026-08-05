"""KL-divergence–based anomaly detection for HR access logs."""

from .kl_detector import KLDivergenceDetector, kl_divergence

__all__ = ["KLDivergenceDetector", "kl_divergence"]
