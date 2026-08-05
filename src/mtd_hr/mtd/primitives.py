"""MTD primitives (paper Sec. 3.4, 3.5, 3.12).

Each primitive transforms a running service to break the attacker's
assumptions about topology continuity, per the reconfiguration mapping
M_reconfig : s_i(t) -> s'_i(t + dt)  (Eq. 2).

  * IPHopping        — IP(s_i, t+T) = H1(IP(s_i, t), r)              (Eq. 3)
  * ContainerMutation— c'_i = H2(c_i, theta), theta ~ N(0, sigma^2) (Eq. 4)
  * NodeReassignment — s_i(t+dt) = argmin_n L(n) * xi(s_i, n)        (Eq. 11)
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Service:
    """A containerized HR microservice instance with (v_i, c_i, d_i)."""

    name: str
    module: str
    version: int = 1
    image: str = "hr-svc:base"          # c_i, container image
    node: str = "node-0"               # d_i, deployment node
    ip: str = "10.0.0.1"
    tenant: str = "default"
    compliant: bool = True             # within GDPR/SOC2 policy domain


@dataclass
class IPHopping:
    """Rotate a service's visible IP via a keyed hash (Eq. 3)."""

    seed: int = 42
    _rng: random.Random = field(default=None, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    def apply(self, svc: Service) -> Service:
        r = self._rng.random()
        h = hashlib.sha256(f"{svc.ip}:{r}".encode()).hexdigest()
        # Map hash to a 10.x.x.x address (H1).
        octets = [10, int(h[0:2], 16) % 256, int(h[2:4], 16) % 256,
                  1 + int(h[4:6], 16) % 254]
        svc.ip = ".".join(map(str, octets))
        return svc


@dataclass
class ContainerMutation:
    """Perturb the container image/config while preserving function (Eq. 4)."""

    sigma: float = 1.0
    seed: int = 42
    _rng: random.Random = field(default=None, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    def apply(self, svc: Service) -> Service:
        theta = self._rng.gauss(0.0, self.sigma)   # theta ~ N(0, sigma^2)
        tag = hashlib.sha256(f"{svc.image}:{theta}".encode()).hexdigest()[:8]
        svc.image = f"hr-svc:{tag}"
        svc.version += 1
        return svc


@dataclass
class NodeReassignment:
    """Move a service to the node minimising L(n) * xi(s_i, n) (Eq. 11)."""

    def apply(self, svc: Service, node_loads: Dict[str, float],
              compat: Dict[str, float] = None) -> Service:
        compat = compat or {}
        best_node, best_cost = svc.node, float("inf")
        for node, load in node_loads.items():
            xi = compat.get(node, 1.0)   # resource-fit / compatibility factor
            cost = load * xi
            if cost < best_cost:
                best_cost, best_node = cost, node
        svc.node = best_node
        return svc


def attack_surface(services: List[Service]) -> set:
    """F_attack(t): union of exposed IP/port/config entry points (Eq. 1).

    Represented here as the set of (ip, image, node) tuples currently exposed.
    Randomising these shrinks the predictable surface.
    """
    return {(s.ip, s.image, s.node) for s in services}
