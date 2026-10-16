-- 发布组合与策略的控制台显示名（2026-10-16，命名规范见数据与模型方案）。
-- 只追加资料列，不改 bundle_key、subject、封存清单、状态或任何已执行迁移；显示名不参与 subject 摘要、授权或执行判定。
-- guard_decision_policy 已在 V27 具备 display_name/notes，本迁移只补发布组合。
ALTER TABLE guard_release_bundle
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名（如 R6 · 真实主机 · 只告警），不参与 subject 或封存证据',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不参与 subject 或封存证据';
