"""``python -m cyber_training.v2 <step>`` 入口。未实现的步骤显式失败，不做任何操作。"""

from __future__ import annotations

import argparse
import sys
from importlib import import_module
from pathlib import Path

STEPS = ("register", "eda", "split", "preprocess-compare", "feature-compare", "train", "train-multiclass", "final-eval", "export")
SIMPLE = {"register": "register", "split": "split", "eda": "eda"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyber_training.v2")
    parser.add_argument("step", choices=STEPS)
    parser.add_argument("--resume", type=Path, help="preprocess-compare / feature-compare / train / train-multiclass：续跑已有运行目录")
    parser.add_argument("--schemes", help="preprocess-compare：逗号分隔的方案子集，如 P0,P3")
    parser.add_argument("--models", help="preprocess-compare / train screen / train-multiclass：逗号分隔的模型子集，如 LR,RF")
    parser.add_argument("--seeds", help="preprocess-compare / feature-compare：逗号分隔的种子子集")
    parser.add_argument("--sample-rows", type=int, help="preprocess-compare / feature-compare：训练抽样行数")
    parser.add_argument("--stage", choices=("screen", "tune", "seeds"), help="train：阶段")
    parser.add_argument("--source", type=Path, help="train：上一阶段运行目录；train-multiclass：T1 调优目录（缺省取最新）")
    parser.add_argument("--variants", help="train-multiclass：逗号分隔的做法子集，如 cw,cw_smote")
    args = parser.parse_args(argv)
    if args.step in SIMPLE:
        print(import_module(f".{SIMPLE[args.step]}", __package__).run())
        return 0
    if args.step == "preprocess-compare":
        from . import preprocess

        kwargs = {"resume": args.resume}
        if args.schemes:
            kwargs["schemes"] = tuple(args.schemes.split(","))
        if args.models:
            kwargs["models"] = tuple(args.models.split(","))
        if args.seeds:
            kwargs["seeds"] = tuple(int(s) for s in args.seeds.split(","))
        if args.sample_rows:
            kwargs["sample_rows"] = args.sample_rows
        print(preprocess.run(**kwargs))
        return 0
    if args.step == "feature-compare":
        from . import feature_compare

        kwargs = {"resume": args.resume}
        if args.seeds:
            kwargs["seeds"] = tuple(int(s) for s in args.seeds.split(","))
        if args.sample_rows:
            kwargs["sample_rows"] = args.sample_rows
        print(feature_compare.run(**kwargs))
        return 0
    if args.step == "train":
        from . import train

        if not args.stage:
            parser.error("train 需要 --stage screen|tune|seeds")
        kwargs = {"resume": args.resume, "source_dir": args.source}
        if args.models:
            kwargs["models"] = tuple(args.models.split(","))
        print(train.run(args.stage, **kwargs))
        return 0
    if args.step == "train-multiclass":
        from . import multiclass

        kwargs = {"resume": args.resume, "tune_dir": args.source}
        if args.models:
            kwargs["models"] = tuple(args.models.split(","))
        if args.variants:
            kwargs["variants"] = tuple(args.variants.split(","))
        print(multiclass.run(**kwargs))
        return 0
    print(f"step '{args.step}' is not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
