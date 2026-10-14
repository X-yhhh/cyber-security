# P8 部署准备脚本

本目录当前实现 BE-14 和 DB-9 的准备、验证与登记。A21 允许本机独立 RabbitMQ vhost 和 r6 登记至 approved；常驻服务、真实资产、采集与激活须另按 A8/P8 授权。步骤和回退见 [部署与回退](../../docs/部署与回退.md)。脚本不调用 PF、不读 test、不训练、不启用自动化。

## 运行环境

从仓库根使用现有 `sh executor/python.sh -B`。JDK 固定 Temurin 25.0.2、Maven 3.9.13、MySQL 8.0.42 和 RabbitMQ 4.2.5，参数可指定已审查的安装目录。密钥和凭据由受控文件、现有 `DB_TEST_*`/`RABBITMQ_IT_*` 环境或 Keychain 读取，不写入命令行或 Git。每次 `--work` 必须是不存在的新目录；结果、日志、TLS 材料与数据库备份按 0700/0600 保存。

## Broker 验收

```sh
sh executor/python.sh -B scripts/p8/broker_acceptance.py --work .cache/p8/broker-isolated-01
sh executor/python.sh -B scripts/p8/broker_acceptance.py --existing --work .cache/p8/broker-existing-01
```

- 默认启动同一正式 RabbitMQ 安装下的临时独立节点，独立端口、数据、凭据与 cookie；完整进程重启只作用于该节点。原共享节点不重启。节点运行目录保留为故障证据。
- `--existing` 在 `127.0.0.1` 的现有 broker 创建随机 vhost，使用 `RABBITMQ_IT_USERNAME`/`RABBITMQ_IT_PASSWORD`，只声明、清空和删除自己的消息对象。该结果不单独证明进程重启。
- 每组强制连续两轮；使用生产 publisher/listener/消费者与随机 MySQL schema。包括真实发布确认、丢确认帧造成的超时、TTL 重试、非法消息死信、重试耗尽、重复投递幂等、持久未确认消息恢复。
- `result.json` 必须 `passed=true`，两轮检查及生产类哈希一致、消息为空、其他拓扑不变、vhost 删除，独立节点已停止；`SHA256SUMS` 绑定 JSON 证据。任何失败保留日志和结论，不当作通过。

## r6 完整登记

脚本只适用于未登记的 r6；已经登记时拒绝重复创建。不要靠改 policyId 重跑来回避失败。先构建并冻结已验证 JAR，两个模式必须使用相同 JAR、脚本、策略、r5 final 和信任文件。

```sh
sh executor/python.sh -B scripts/p8/register_alert_only.py --mode rehearsal \
  --work .cache/p8/r6-rehearsal-01 --jar .cache/p8/backend.jar \
  --policy .cache/p1-20261015/r6/policy-alert-only.json
sh executor/python.sh -B scripts/p8/register_alert_only.py --mode business \
  --work .cache/p8/r6-business-01 --jar .cache/p8/backend.jar \
  --policy .cache/p1-20261015/r6/policy-alert-only.json \
  --rehearsal .cache/p8/r6-rehearsal-01/result.json
```

1. 业务库无人连接、Flyway V25、来源策略 reviewed、r5 正式 final 签名和哈希有效；只关闭模式和自动开关，其他字段完全相同。
2. 整库转储含 routines/triggers/events，恢复到随机库；全部表的有效结构、主键对应行摘要和行数必须一致。DOUBLE/FLOAT 按 IEEE 位摘要；JSON 数字经 MySQL 8 文本解析可能漂移 1 ULP，随 dump 另存 `json-double-fidelity.sql`，用 SQL DOUBLE + JSON_SET 在恢复库精确还原。两份 SQL 均须保存、核对 SHA 并按顺序恢复；不放宽逐行比较、不改源库。备份在 MySQL 服务的 `backups/`，不会放入仓库。
3. 演练在随机库；业务模式在新的恢复演练后才写 `cyber_security`，并核对业务库与成功演练开始时逐表一致。
4. 启动临时回环 mTLS 后端，真实登录 `g3-operator` 与 `guard-reviewer`；策略登记、独立审查、组合登记、签发/导入正式 final、仅 final 封存、独立批准。每步保存响应；r6 停在 approved，无资产绑定。
5. 比较所有表：业务增量仅策略 +1、组合 +1、组合能力 +4、评价 +1，另允许幂等、审计、会话、登录变化。已有业务/审计记录必须逐行不变，所有用户身份/凭据不变（仅两位操作账号登录时间允许变化）。业务增量还须与演练一致。
6. 停止本次后端并核对端口关闭，删除本次随机 schema，保留 dump、报告、日志与摘要。失败不自动恢复业务库；从已保存的步骤定位，禁止盲目重跑。

final 复用 r5 的 `evaluation` 和 `provenance`，`sourceEligibility=[]`，模型与规则来源分别标记 `alert_only`；绑定新 subject、策略与 health 1.0.0，不产生新模型成绩、PF 证据或现场能力结论。

## 独立备份与恢复验证

```sh
sh executor/python.sh -B scripts/p8/backup_restore.py
```

该入口调用同一整库备份/恢复实现，要求业务库无人连接；恢复到随机库、逐表核对后删除随机库，保留受控备份。它不能覆盖或回滚业务库。需要实际恢复时执行手册中的停写、额外备份、审批及恢复后验收流程。
