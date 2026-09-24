from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import ExperimentConfig
from .data import DATA_ROOT, load_raw, load_subset_audit, write_json
from .pipeline import run_experiment
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
    args = parser.parse_args()
    if args.command == "verify-data":
        data_root = Path(args.data_root)
        _, manifest = load_raw(data_root)
        manifest["subset_audit"] = load_subset_audit(data_root)
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        result = run_training_workflow(ExperimentConfig(seed=args.seed, mlp_epochs=args.epochs), Path(args.data_root), Path(args.output) if args.output else None)
        print(result)


if __name__ == "__main__":
    main()
