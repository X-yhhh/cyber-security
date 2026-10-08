-- B1 平台能力绑定只向前追加；V19—V21 的能力、发布组合与账号保持原样。
-- 历史能力一律视为 peer_service 且不带保护集，不能借迁移取得全入站资格。
ALTER TABLE guard_capability
  ADD COLUMN scope VARCHAR(24) NOT NULL DEFAULT 'peer_service' COMMENT '能力执行范围；peer_inbound 覆盖保护端口以外的全部入站端口',
  ADD COLUMN protection_set_sha256 CHAR(64) NULL COMMENT '全入站豁免所依据的保护集 JCS 摘要；须同时等于策略与当前保护文件，否则签发时按 PROTECTED_SERVICE 拒绝',
  ADD COLUMN exemption_evidence_sha256 CHAR(64) NULL COMMENT '签名的 E1—E3 豁免报告摘要；登记时已验签，缺失或不符的全入站能力不能登记',
  ADD CONSTRAINT ck_guard_capability_scope CHECK (
    (scope='peer_service' AND protection_set_sha256 IS NULL AND exemption_evidence_sha256 IS NULL)
    OR (scope='peer_inbound' AND protection_set_sha256 IS NOT NULL AND exemption_evidence_sha256 IS NOT NULL));
