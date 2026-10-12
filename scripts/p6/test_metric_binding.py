"""验收文档与第二轮评价计划的字节绑定回归；只读仓库文档，不打开任何数据。"""
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

# 第二轮评价计划（host-guard-evaluation/2026-10-08.1，T3.7 起登记）的 metricDefinitionSha256。
# evaluate.py 与 scripts/p3/candidate_plan.py 的非 legacy 检查按此值比对 docs/验证与验收.md 原字节；
# 修改该文档正文会使已封存候选及 r4/r5 发布组合的复核失败。阶段状态请写入开发路线或执行记录。
# 只有登记新的评价计划修订时才能同步修改此常量。
REGISTERED_METRIC_DEFINITION_SHA256 = "0da3497f8f0ba0eecb16546acbfa3a9e2e6f941ed555ddb35ec678d4e220ec56"


class MetricBindingTest(unittest.TestCase):
    def test_acceptance_doc_matches_registered_plan(self):
        actual = hashlib.sha256((ROOT / "docs/验证与验收.md").read_bytes()).hexdigest()
        self.assertEqual(
            REGISTERED_METRIC_DEFINITION_SHA256, actual,
            "docs/验证与验收.md 与评价计划绑定的 metricDefinitionSha256 不一致；"
            "请恢复绑定字节，把状态说明写到开发路线或执行记录")


if __name__ == "__main__":
    unittest.main()
