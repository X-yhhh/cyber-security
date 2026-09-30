"""``python -m cyber_training.v2 <step>`` 入口。未实现的步骤显式失败，不做任何操作。"""

from __future__ import annotations

import argparse
import sys
from importlib import import_module
from pathlib import Path

STEPS = ("register", "eda", "split", "preprocess-compare", "feature-compare", "train", "train-multiclass", "final-eval", "export", "feature-audit", "feature-ablation", "feature-diagnose", "prepare-v4", "final-v4", "export-v4", "baseline-v4")
SIMPLE = {"register": "register", "split": "split", "eda": "eda", "feature-audit": "feature_audit", "feature-diagnose": "feature_diagnose", "prepare-v4": "route_b_v4"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyber_training.v2")
    parser.add_argument("step", choices=STEPS)
    parser.add_argument("--resume", type=Path, help="preprocess-compare / feature-compare / train / train-multiclass：续跑已有运行目录")
    parser.add_argument("--schemes", help="preprocess-compare：逗号分隔的方案子集，如 P0,P3")
    parser.add_argument("--models", help="preprocess-compare / train screen / train-multiclass：逗号分隔的模型子集，如 LR,RF")
    parser.add_argument("--seeds", help="preprocess-compare / feature-compare：逗号分隔的种子子集")
    parser.add_argument("--sample-rows", type=int, help="preprocess-compare / feature-compare：训练抽样行数")
    parser.add_argument("--stage", choices=("screen", "tune", "seeds"), help="train：阶段")
    parser.add_argument("--source", type=Path, help="train：上一阶段运行目录；train-multiclass：T1 调优目录；baseline-v4 package：基线运行目录（缺省取最新）")
    parser.add_argument("--variants", help="train-multiclass：逗号分隔的做法子集，如 cw,cw_smote")
    parser.add_argument("--final-stage", choices=("freeze", "evaluate", "generalization"), default="evaluate",
                        help="final-eval：freeze 冻结候选（不读 holdout）；evaluate 锁定评估；generalization 补跑 T3")
    parser.add_argument("--unlock-holdout", action="store_true", help="final-eval evaluate/generalization：显式解锁 holdout")
    parser.add_argument("--candidate", help="final-eval / export：T1 候选模型名，必须与冻结记录一致")
    parser.add_argument("--model-version", help="export：交付版本号（缺省 2026.09.0），目录为 delivery/unsw-binary-<版本>")
    parser.add_argument("--baseline-stage", choices=("compute", "package", "verify"), default="compute",
                        help="baseline-v4：compute 复现切分并算训练分区基线；package 写新交付并自校验；verify 只读自校验")
    parser.add_argument("--raw-root", type=Path, help="baseline-v4 compute：D1 原始 CSV 目录（缺省 data/raw/unsw-nb15）")
    parser.add_argument("--source-delivery", type=Path, help="baseline-v4：源交付目录（缺省 delivery/unsw-binary-2026.10.0）")
    parser.add_argument("--delivery-root", type=Path, help="baseline-v4 package/verify：新交付的父目录（缺省 delivery/）")
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
    if args.step == "final-eval":
        from . import final_eval

        if args.final_stage == "freeze":
            if args.unlock_holdout:
                parser.error("freeze 不读取 holdout，不能与 --unlock-holdout 同用")
            print(final_eval.freeze())
            return 0
        print(final_eval.run_evaluate(args.unlock_holdout, candidate=args.candidate, resume=args.resume,
                                      only_generalization=args.final_stage == "generalization"))
        return 0
    if args.step == "final-v4":
        from . import route_b_final

        if args.final_stage == "freeze":
            if args.unlock_holdout:
                parser.error("freeze 不读取 holdout，不能与 --unlock-holdout 同用")
            print(route_b_final.freeze())
            return 0
        if args.final_stage != "evaluate":
            parser.error("final-v4 只支持 --final-stage freeze 或 evaluate")
        print(route_b_final.run_evaluate(args.unlock_holdout))
        return 0
    if args.step == "export-v4":
        from . import route_b_export

        print(route_b_export.run(version=args.model_version or route_b_export.DEFAULT_VERSION))
        return 0
    if args.step == "baseline-v4":
        from . import route_b_baseline

        print(route_b_baseline.run(args.baseline_stage, raw_root=args.raw_root, source_delivery=args.source_delivery,
                                   baseline_run=args.source, delivery_root=args.delivery_root,
                                   version=args.model_version or route_b_baseline.TARGET_VERSION))
        return 0
    if args.step == "feature-ablation":
        from . import feature_ablation

        print(feature_ablation.run(resume=args.resume))
        return 0
    if args.step == "export":
        from . import export

        kwargs = {"candidate": args.candidate}
        if args.model_version:
            kwargs["version"] = args.model_version
        print(export.run(**kwargs))
        return 0
    print(f"step '{args.step}' is not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
