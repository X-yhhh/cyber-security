from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import ExperimentConfig
from .data import DATA_ROOT, load_raw, load_subset_audit, write_json
from .pipeline import run_experiment
from .stage6_preflight import run_preflight
from .stage6_training import run_stage6_training
from .workflow import run_training_workflow


def main() -> None:
    parser = argparse.ArgumentParser(prog="cyber-training")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-data")
    verify.add_argument("--data-root", default=str(DATA_ROOT))
    train = sub.add_parser("train")
    train.add_argument("--data-root", default=str(DATA_ROOT))
    train.add_argument("--output")
    train.add_argument("--seed", type=int, default=20260923)
    train.add_argument("--epochs", type=int, default=20)
    preflight = sub.add_parser("stage6-preflight")
    preflight.add_argument("--run", required=True)
    preflight.add_argument("--output", required=True)
    stage6 = sub.add_parser("stage6-train")
    stage6.add_argument("--source-run", required=True)
    stage6.add_argument("--output", required=True)
    stage6.add_argument("--data-root", default=str(DATA_ROOT))
    stage6.add_argument("--seed", type=int, default=20260923)
    args = parser.parse_args()
    if args.command == "verify-data":
        data_root = Path(args.data_root)
        _, manifest = load_raw(data_root)
        manifest["subset_audit"] = load_subset_audit(data_root)
        print(json.dumps(manifest, indent=2, sort_keys=True))
    elif args.command == "train":
        result = run_training_workflow(ExperimentConfig(seed=args.seed, mlp_epochs=args.epochs), Path(args.data_root), Path(args.output) if args.output else None)
        print(result)
    elif args.command == "stage6-preflight":
        result = run_preflight(Path(args.run), Path(args.output))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        result = run_stage6_training(
            Path(args.source_run), Path(args.output), Path(args.data_root),
            ExperimentConfig(seed=args.seed, experiment_name="stage6-endpoint-stress"),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
