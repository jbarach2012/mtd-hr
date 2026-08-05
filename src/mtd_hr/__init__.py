"""MTD-HR: Enhancing Ransomware Resilience in Cloud-Based HR Systems through
Moving Target Defense.

Reference implementation accompanying the paper:

    Jay Barach. 2025. "Enhancing Ransomware Resilience in Cloud-Based HR Systems
    through Moving Target Defense." Computers, Materials & Continua (CMC),
    2026, 86(2). DOI: 10.32604/cmc.2025.071705

The package implements:
  * ``mtd_hr.detect`` — a KL-divergence–based statistical anomaly detector over
    HR access logs, with EWMA/CUSUM boosters (paper Sec. 3.9, Eq. 8).
  * ``mtd_hr.mtd``    — the Moving Target Defense primitives: IP hopping (Eq. 3),
    container mutation (Eq. 4), node reassignment (Eq. 11), cost/spread models
    (Eqs. 5-7), compliance risk (Eq. 12), and the cost-aware adaptive
    controller (Algorithm 1).
  * ``mtd_hr.sim``    — an HR-traffic + ransomware log generator and a
    discrete-event simulator that measures MTTC, encryption success ratio,
    accuracy/FPR, and mutation overhead (Sec. 4-5).
"""

from importlib.metadata import PackageNotFoundError, version

try:  # pragma: no cover
    __version__ = version("mtd-hr")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "1.0.0"

# The five HR functional modules evaluated in the paper (Sec. 4, Table 3).
HR_MODULES = ["onboarding", "employee_records", "leave", "payroll", "exit"]

# Ransomware attack stages used by the log generator (from CIC Ransomware 2020
# high-level templates: discovery -> staging -> encryption).
ATTACK_STAGES = ["discovery", "lateral_movement", "staging", "encryption"]

# MTD action identifiers.
ACTION_IP_HOP = "ip_hop"
ACTION_CONTAINER_MUT = "container_mutation"
ACTION_NODE_REASSIGN = "node_reassignment"
MTD_ACTIONS = [ACTION_IP_HOP, ACTION_CONTAINER_MUT, ACTION_NODE_REASSIGN]

__all__ = [
    "__version__",
    "HR_MODULES",
    "ATTACK_STAGES",
    "MTD_ACTIONS",
    "ACTION_IP_HOP",
    "ACTION_CONTAINER_MUT",
    "ACTION_NODE_REASSIGN",
]
