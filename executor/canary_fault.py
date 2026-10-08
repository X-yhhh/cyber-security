"""回环验收子进程的三个崩溃点；只在独立 canary 入口使用真实进程退出。"""
import argparse
import os
from pathlib import Path

from .__main__ import build
from .common import canonical, read_private, require, write_new
from .pf_canary import canary_scope
from .engine import Engine
from .transport import TargetResolver


def run(config, envelope, resolver_config, marker, stage):
    original = build(config, resolver=False)
    canary_scope(original.config(), "peer_inbound")
    engine = Engine(original.store, original.adapter, TargetResolver(lambda: read_private(resolver_config)),
                    original.config, original.trust, original.budget_key)
    require(stage in ("before_ledger", "after_ledger", "after_install"), "CANARY_FAULT_INVALID")

    def crash():
        write_new(marker, canonical({"stage": stage, "actualRules": len(engine.adapter.inventory())}))
        os._exit(71)

    save, install = engine.store.save, engine.adapter.install

    def save_intent(row):
        if row["status"] == "prepared" and stage == "before_ledger":
            crash()
        save(row)
        if row["status"] == "prepared" and stage == "after_ledger":
            crash()

    def install_rule(*args):
        install(*args)
        if stage == "after_install":
            crash()

    engine.store.save = save_intent
    engine.adapter.install = install_rule
    engine.accept(read_private(envelope))
    raise RuntimeError("CANARY_FAULT_NOT_REACHED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "envelope", "resolver-config", "marker"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--stage", required=True)
    args = parser.parse_args()
    run(args.config, args.envelope, args.resolver_config, args.marker, args.stage)
