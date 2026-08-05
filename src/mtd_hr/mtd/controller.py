"""Cost-aware adaptive MTD controller (paper Algorithm 1, Sec. 3.14).

Given per-service anomaly scores, the controller builds candidate actions
{IPHop, ContainerMut, NodeReassign}, scores each by utility

    U_i(a) = dPsi_i(a) - lambda * C_i(a) - R_c(a)

(risk reduction minus cost minus compliance penalty), then greedily applies
the highest-utility actions subject to CPU/memory budgets and per-tenant
quotas. This matches the budgeted selection loop in Algorithm 1.
"""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .. import ACTION_CONTAINER_MUT, ACTION_IP_HOP, ACTION_NODE_REASSIGN
from ..config import MTDConfig
from .primitives import (
    ContainerMutation,
    IPHopping,
    NodeReassignment,
    Service,
)


@dataclass
class MTDAction:
    service: str
    action: str
    utility: float
    cpu: float
    mem: float
    tenant: str


@dataclass
class AdaptiveMTDController:
    """Stateless per-service MTD controller (Algorithm 1)."""

    cfg: MTDConfig
    seed: int = 42

    _ip: IPHopping = field(default=None, repr=False)
    _mut: ContainerMutation = field(default=None, repr=False)
    _node: NodeReassignment = field(default=None, repr=False)
    _last_mutation: Dict[str, float] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self._ip = IPHopping(seed=self.seed)
        self._mut = ContainerMutation(seed=self.seed)
        self._node = NodeReassignment()

    # -- cost / utility models ---------------------------------------------
    def _action_cost(self, action: str) -> float:
        """C_i(a): resource cost of an action (Eq. 5 per-term)."""
        return {
            ACTION_IP_HOP: self.cfg.ip_hop_cost,
            ACTION_CONTAINER_MUT: self.cfg.container_mut_cost,
            ACTION_NODE_REASSIGN: self.cfg.node_reassign_cost,
        }[action]

    def _risk_reduction(self, action: str, anomaly: float) -> float:
        """dPsi_i(a): estimated ransomware-spread reduction (Eq. 6-7).

        Container mutation is the strongest lever (ablation Table 7 shows its
        removal raises encryption most), then node reassignment, then IP hop.
        """
        base = {
            ACTION_CONTAINER_MUT: 1.0,
            ACTION_NODE_REASSIGN: 0.7,
            ACTION_IP_HOP: 0.5,
        }[action]
        return base * max(0.0, anomaly)

    def _compliance_penalty(self, svc: Service, action: str) -> float:
        """R_c(a): penalty for a placement violating policy (Eq. 12)."""
        if action == ACTION_NODE_REASSIGN and not svc.compliant:
            return self.cfg.compliance_weight
        return 0.0

    def _latency_ms(self, action: str) -> float:
        return {
            ACTION_IP_HOP: self.cfg.ip_hop_latency_ms,
            ACTION_CONTAINER_MUT: self.cfg.container_mut_latency_ms,
            ACTION_NODE_REASSIGN: self.cfg.node_reassign_latency_ms,
        }[action]

    # -- main step ----------------------------------------------------------
    def plan_and_apply(
        self,
        services: Dict[str, Service],
        anomaly_scores: Dict[str, float],
        node_loads: Dict[str, float],
        now: Optional[float] = None,
        tenant_quota_ok: Optional[Callable[[str, str], bool]] = None,
    ) -> Dict:
        """Run one control cycle (Algorithm 1). Returns applied plan + telemetry."""
        now = now if now is not None else time.time()
        quota_ok = tenant_quota_ok or (lambda tenant, action: True)

        # 1) Build candidate utilities into a max-heap (via negated utility).
        heap: List = []
        for name, svc in services.items():
            z = anomaly_scores.get(name, 0.0)
            if z <= 0:
                continue
            last = self._last_mutation.get(name, -1e9)
            if (now - last) < self.cfg.min_mutation_interval_s:
                continue  # cooldown T_min
            for action in (ACTION_IP_HOP, ACTION_CONTAINER_MUT, ACTION_NODE_REASSIGN):
                d_psi = self._risk_reduction(action, z)
                cost = self._action_cost(action)
                rc = self._compliance_penalty(svc, action)
                utility = d_psi - self.cfg.lambda_cost * cost - rc
                heapq.heappush(
                    heap, (-utility, name, action, cost, svc.tenant)
                )

        # 2) Budgeted greedy selection.
        b_cpu, b_mem = self.cfg.cpu_budget, self.cfg.mem_budget
        applied: List[MTDAction] = []
        total_latency = 0.0
        while heap:
            neg_u, name, action, cost, tenant = heapq.heappop(heap)
            cpu = mem = cost  # treat cost as a shared CPU/mem unit for budgeting
            if cpu <= b_cpu and mem <= b_mem and quota_ok(tenant, action):
                svc = services[name]
                self._execute(svc, action, node_loads)
                b_cpu -= cpu
                b_mem -= mem
                self._last_mutation[name] = now
                total_latency += self._latency_ms(action)
                applied.append(MTDAction(name, action, -neg_u, cpu, mem, tenant))

        return {
            "applied": applied,
            "n_actions": len(applied),
            "cpu_used": self.cfg.cpu_budget - b_cpu,
            "mem_used": self.cfg.mem_budget - b_mem,
            "total_latency_ms": total_latency,
        }

    def _execute(self, svc: Service, action: str, node_loads: Dict[str, float]):
        if action == ACTION_IP_HOP:
            self._ip.apply(svc)
        elif action == ACTION_CONTAINER_MUT:
            self._mut.apply(svc)
        elif action == ACTION_NODE_REASSIGN:
            self._node.apply(svc, node_loads)
