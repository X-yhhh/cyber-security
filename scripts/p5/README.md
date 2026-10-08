# E3 联合链路准备与 B6 lab 配置

本目录只准备 Mac 回环联合环境，不切换现有服务，不执行业务库 V22，不部署常驻恢复器。真实 PF、sudo、lo0 别名操作须每轮 A4 单独授权；本次任务仅验证无权限演练。模型、能力及签名评价报告均为合成夹具，不能用于 G3、发布资格或生产能力声明。

## 入口与前置条件

从仓库根使用已有 `executor/python.sh` 包装器。要求 JDK 25、Maven 的 Java 同为 25、Go 1.26.4、执行器 requirements，以及本机 MySQL 8 测试身份。测试身份需具备临时 schema 的 CREATE/DROP 及迁移权限；脚本前置检查保守要求全局 CREATE/DROP，不会打印凭据或 grants。

预先在受控环境提供 `DB_TEST_BASE_URL=jdbc:mysql://127.0.0.1:3306`（仅服务地址，不带 schema、参数或凭据）、`DB_TEST_USERNAME`、`DB_TEST_PASSWORD`。不要把密码放在命令参数、Git 或报告中。`JAVA25_HOME` 指向已安装的 JDK 25；可用 `--maven/--go/--mysql` 指定正式工具绝对路径，否则按 PATH 查找。不要依赖默认 shell 的 Java 版本。

```sh
bash executor/python.sh scripts/p5/orchestrate.py \
  --mode dry-run --java-home "$JAVA25_HOME" \
  --directory "$HOME/Workspace/ai/outputs/<全新前置检查目录>"
```

`--directory` 必须为仓库外绝对路径且尚不存在；拒绝经软链接解析后位于仓库内的路径。目录 0700，生成文件 0600。dry-run 只查询工具、接口和 MySQL 版本/权限，输出完整 `preflight.json`；不会创建 schema、生成模型、启动后端、请求 sudo、安装规则或配置别名。`prepared=true` 表示准备条件满足，不能替代 PF ABI/根规则/清理验收；无 sudo 无法读取 PF 状态时如实记 `pfReadableWithoutSudo=false`。

## 无权限六场景演练

```sh
bash executor/python.sh scripts/p5/orchestrate.py \
  --mode rehearse --java-home "$JAVA25_HOME" \
  --directory "$HOME/Workspace/ai/outputs/<全新演练目录>"
```

顺序为 peer_service 的 revoke/disconnect/receipt_loss，再为 peer_inbound 的同三场景。每轮独立资产、授权、稳定预算密钥和账本，避免撤销墓碑或故障暂停状态污染下一轮。可用 `--scope` 与 `--scenario` 成对指定一轮。

`GuardJointLabTest#jointMatrix` 显式加载 lab profile，并创建 `cyber_guard_api_p4_<随机 UUID>` schema，应用现有迁移，结束仅删除自己的 schema。人工登记与批准复用 P4 API 夹具；机器领取、回执、撤销、核对走真实回环 HTTPS TLS1.3。执行器与本轮构建的 Go `guardtargets` 通过真实 mTLS 通信，collector/executor 证书分别认证。模拟观察没有抓包或攻击流量；真实端点只用 127.0.0.1/127.0.0.2、lo0。

演练模式的防火墙是 `MemoryFirewall`，独立恢复器由线程夹具模拟；不调用 PF，也不证明流量实际被阻断。链路覆盖签发→领取→规则替身安装→回执→人工撤销→实态核对→清理：

- revoke：应用成功后人工撤销，数据库 observed_state 与账本均为 revoked。
- disconnect：应用后注入 HTTPS 发送失败，清理自身规则并暂停，重连同步撤销。
- receipt_loss：服务端先接受首条 applied 回执，再丢弃响应；执行器保留原 receiptId/内容摘要并在重连重试，数据库该 public_id 仅一条，随后收敛为 revoked。

`summary.json` 汇总顺序、六轮结果、源码/guardtargets 二进制/执行器配置哈希。每轮 `result.json` 记录安装/清理时刻、规则摘要、账本、故障注入与原回执重试事实；`database-facts.json` 记录数据库末态、周期墓碑、预算 revision 与命令/回执数。`input.json`、credential、TLS 私钥及本机 SQLite 包含测试身份或端点，只留在受控外部目录，不提交、不公开。JUnit 失败时不自动打印 MockMvc 的完整认证请求。

## lab profile 与信任边界

`backend/src/main/resources/application-lab.yml` 必须显式选择。默认 `application.yml` 没有任何 `cyber.guard.*`，未启用 lab 时不会激活自动化；lab 的自动化默认也为 false。

| 环境变量 | 用途 |
|---|---|
| LAB_DB_URL | 专用隔离 lab schema 的 JDBC URL |
| DB_TEST_USERNAME / DB_TEST_PASSWORD | MySQL 测试身份，受控环境注入 |
| LAB_TLS_CERTIFICATE / LAB_TLS_KEY | 回环 HTTPS PEM 证书及私钥引用 |
| LAB_SIGNING_KEY_ID / LAB_SIGNING_KEY_FILE | Ed25519 控制面签名身份与 DER PKCS8 私钥引用 |
| LAB_REPORT_TRUST_FILE | 后端导入报告使用的 runner→公钥 DER base64 映射 |
| LAB_PROTECTION_FILE | P4 格式保护 JSON 引用 |
| LAB_ARTIFACT_ROOT | 仓库外受控制品根目录 |
| LAB_EXECUTOR_TRUST_FILE | lab.executor.trust-file，编排交给执行器 trustFile 的命令公钥清单 |
| LAB_AUTOMATION_ENABLED | 默认 false，独立授权的 lab 运行才显式启用 |

后端 `cyber.guard.report-trust-file` 验签评价报告；执行器 `trustFile` 验签 ActionCommand，两者格式与职责不同。命令清单按 keyId 含 `status/publicKeyDer/notBefore/notAfter`，不得把私钥发给执行器。独立部署可用 `bash executor/python.sh -m executor keygen --directory <仓库外全新目录> --key-id <身份>` 生成控制面私钥、公钥信任文件和稳定预算密钥；执行器的 `RuntimeConfig.trustFile` 指向公钥清单。

联合测试动态注入上述属性：同一次测试生成临时签名私钥、独立 runner/command 信任文件、TLS PKI，并按 lab.executor.trust-file 交给执行器。仅在专用随机 schema 注册合成模型和资格，不触及已有业务授权。它是协议夹具，不是服务切换或 B6 全阶段验收。

## T3.8 保护集来源

`scripts/p5/lab-protection.json` 为两种作用域共同的 P4 保护配置：

```json
{"protectedBudgetTargetIds":[],"protectedServicePorts":[22,53,3389]}
```

JCS SHA-256 为 `cfe3f15a5b8d6352dd3bef5965cc935973f2225d3ef774757d82da0842d22654`；有效保护端口摘要为 `0a8fc9174a067e5a12557351ed368486a68ea015d2416be8f510a77014929583`。T3.8 可读取该文件计算 protectionSetSha256；封装策略前仍须提供已登记能力 ID 和完整预算字段。22/53/3389 始终隐式保护，peer_inbound 区间由 P4/P5 各自扣除并复核。部署若增加保护目标/端口，必须重算摘要并重新绑定策略、能力和发布组合。

## A4 后的单轮 PF 入口

真实执行不属于本次验收。每次只允许一个 `--scope` 和 `--scenario`，同时须具备本轮授权引用并由管理员显式运行 root 进程；脚本不会自动调用 sudo。先 peer_service，独立验收后再 peer_inbound。禁止用一个模糊授权引用批量运行六轮。

```sh
# 仅供本轮 A4 已获授权且管理员已建立受控 root 环境后使用。
bash executor/python.sh scripts/p5/orchestrate.py \
  --mode pf --scope peer_service --scenario revoke \
  --authorization-reference '<本轮A4引用>' --java-home "$JAVA25_HOME" \
  --directory '<仓库外全新受控绝对目录>'
```

PF 会话只接受初始 Disabled PF、已知默认根或固定用户夹具组合、空专用 anchor，且没有已有 127.0.0.2 别名。核对 root-owned helper ABI，保存根/用户/apple 原始规则字节；仅挂专用 anchor，取得本轮 enable token，并启动单独恢复进程。正常退出或可处理的 SIGTERM/SIGINT 先清规则再停恢复器；最后仅在根字节仍匹配时恢复根，释放本轮 token，移除本轮别名。各清理动作独立尝试，外部改动保留并报失败，不全局 flush，不用 `pfctl -d`。`pf-session.json` 记录逐项清理结果。

SIGKILL、主机重启、系统工具故障或并行管理员变更可能使清理未完成；这些情况不能写成通过，须按保存的规则/本轮 token 与别名范围人工核对恢复。PF helper ABI、系统输出规范化、真实连接效果及异常清理尚待本轮 A4 实测，不能由演练和单元测试推断。

## 后端墓碑与 E4

控制面在资产→目标锁内追加 `guard_budget_event(event_kind=revoked)`，绑定当前 `cycleStartedAt`，包括未签发动作。同周期的新自动动作、人工申请、批准和签发均拒绝 TARGET_REVOKED；不改变计费或删除历史事件。健康恢复通过后开启新周期，零计费墓碑也须健康冷却，不能任意清零。没有新 migration。

执行器新增真实 Ed25519 key/keyId 与策略 hash 轮换测试，同一稳定 token 的四段 30 秒累计到 120 秒后拒绝；撤销后继续拒绝新动作。后端测试覆盖有/无签名撤销、短期引用/keyEpoch 轮换、预算保留和零计费墓碑的健康恢复。E4 的真实 PF 轮换证据仍待 A4。

```sh
# 在 backend/ 下，明确 JAVA_HOME/PATH 使用 JDK25。
mvn -B verify
# 在仓库根。
bash executor/python.sh -m unittest discover -s executor -t . -p 'test_*.py'
bash executor/python.sh -m unittest discover -s scripts/p5 -p 'test_*.py'
```

本次准备不等于 E1—E3 全部真实验收、P5 出口、G3 或生产发布；A5 业务库 V22、现有服务切换和 Windows/WFP 均保持未执行。
