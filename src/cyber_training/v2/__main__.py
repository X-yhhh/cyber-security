"""``python -m cyber_training.v2 <step>`` 入口。未实现的步骤显式失败，不做任何操作。"""

from __future__ import annotations

import argparse
import sys

STEPS = ("register", "eda", "split", "preprocess-compare", "feature-compare", "train", "train-multiclass", "final-eval", "export")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyber_training.v2")
    parser.add_argument("step", choices=STEPS)
    args, _ = parser.parse_known_args(argv)
    if args.step == "register":
        from .register import run

        print(run())
        return 0
    print(f"step '{args.step}' is not implemented yet", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
