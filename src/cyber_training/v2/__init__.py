"""基线 v2 训练流水线。

按训练计划的步骤组织（register → eda → split → preprocess-compare → feature-compare →
train → final-eval → export），统一入口为 ``python -m cyber_training.v2 <step>``。
旧的 phase/stage 模块保持不变，v2 不依赖它们。
"""

GLOBAL_SEED = 20260927
REPRO_SEEDS = (20260927, 20260928, 20260929, 20260930, 20260931)
