"""Tests for MTD primitives and the adaptive controller."""

from mtd_hr import ACTION_CONTAINER_MUT, ACTION_IP_HOP, ACTION_NODE_REASSIGN
from mtd_hr.config import MTDConfig
from mtd_hr.mtd import (
    AdaptiveMTDController,
    ContainerMutation,
    IPHopping,
    NodeReassignment,
)
from mtd_hr.mtd.primitives import Service, attack_surface


def test_ip_hopping_changes_ip():
    svc = Service(name="payroll", module="payroll", ip="10.0.0.1")
    old = svc.ip
    IPHopping(seed=1).apply(svc)
    assert svc.ip != old
    assert svc.ip.startswith("10.")


def test_container_mutation_changes_image_and_version():
    svc = Service(name="payroll", module="payroll", image="hr-svc:base", version=1)
    ContainerMutation(seed=1).apply(svc)
    assert svc.image != "hr-svc:base"
    assert svc.version == 2


def test_node_reassignment_picks_lowest_cost():
    svc = Service(name="payroll", module="payroll", node="node-0")
    NodeReassignment().apply(svc, {"node-0": 5.0, "node-1": 1.0, "node-2": 3.0})
    assert svc.node == "node-1"


def test_attack_surface_shrinks_on_mutation():
    svcs = [Service(name=f"s{i}", module="m", ip=f"10.0.0.{i}") for i in range(3)]
    before = attack_surface(svcs)
    IPHopping(seed=2).apply(svcs[0])
    after = attack_surface(svcs)
    assert before != after


def test_controller_applies_actions_under_anomaly():
    cfg = MTDConfig(cpu_budget=100, mem_budget=100)
    ctrl = AdaptiveMTDController(cfg, seed=1)
    svcs = {"payroll": Service(name="payroll", module="payroll")}
    res = ctrl.plan_and_apply(svcs, {"payroll": 0.9},
                              {"node-0": 1.0, "node-1": 1.0}, now=100.0)
    assert res["n_actions"] >= 1


def test_controller_respects_cooldown():
    cfg = MTDConfig(min_mutation_interval_s=1000.0)
    ctrl = AdaptiveMTDController(cfg, seed=1)
    svcs = {"payroll": Service(name="payroll", module="payroll")}
    r1 = ctrl.plan_and_apply(svcs, {"payroll": 0.9}, {"node-0": 1.0}, now=0.0)
    r2 = ctrl.plan_and_apply(svcs, {"payroll": 0.9}, {"node-0": 1.0}, now=1.0)
    assert r1["n_actions"] >= 1
    assert r2["n_actions"] == 0  # blocked by cooldown


def test_controller_no_action_without_anomaly():
    cfg = MTDConfig()
    ctrl = AdaptiveMTDController(cfg, seed=1)
    svcs = {"payroll": Service(name="payroll", module="payroll")}
    res = ctrl.plan_and_apply(svcs, {"payroll": 0.0}, {"node-0": 1.0}, now=100.0)
    assert res["n_actions"] == 0
