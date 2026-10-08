# P5 本机执行与恢复

本目录实现独立执行器，不需要商业许可、程序发行证书或在线授权服务。命令使用本地 Ed25519 密钥，目标 IPC 使用本地生成的 CA；自动资格由 P4 登记的资产、能力、策略和授权限定。

## 当前范围

- 命令校验：rc.3 Schema、RFC8785/Ed25519、公钥有效期与吊销、资产/环境/执行器 boot、授权 revision/租约、能力/策略和保护清单；回执保持 rc.2。
- 本机目标：复用 Go P2 注册表，collector/executor 采用分离的 mTLS 身份；显式 `peer_inbound` 引用绑定方向与空服务端口，旧省略范围仅兼容 `peer_service`。`resolve-lease` 返回原始 lastPacketAt/expiresAt，不因查询刷新期限。执行器核验10秒证据期限、15秒引用期限，安装前再检查截止。
- 持久执行：SQLite FULL 同步，写规则前提交意图；同命令/动作/幂等键不重复安装、不延长 TTL。跨进程锁串行处理执行、撤销与恢复；稳定目标预算不随 boot、peerKey/keyEpoch 或策略变化。
- 独立恢复：`recover` 与 `run` 分开；到期、撤销、进程崩溃、时钟异常、密钥/授权撤销触发清理。启动先清理旧规则，未知归属不代删；不能确认时暂停并保留 uncertain/recovery_failed 和预算。
- P4 对接：HTTPS机器身份、心跳、命令/撤销领取、回执持久重试、guard-state/1实态核对、目标绑定和预算恢复证明。历史清零时刻单独追加审计，不能用补报提前恢复额度。

自动执行默认仍限 **IPv4/TCP 入站 peer_service**。B1（2026-10-08，代码与单元测试）把原 `LoopbackCanaryEngine` 硬编码例外改为正式校验：`peer_inbound` 命令只有在其 `capabilityId` 已登记在本机 `inboundCapabilities`、平台为 PF、环境为 lab，且登记的 `protectedPortsSha256` 等于按当前 `protectedServicePorts` 重算的值时才通过；未登记仍以 `PROTECTED_TARGET` 拒绝，平台/环境不符为 `CAPABILITY_NOT_SUPPORTED`，保护端口漂移为 `PROTECTION_SET_UNVERIFIED`。没有配置项以外的绕过开关，回环 canary 与正式 `build/run` 使用同一 `Engine` 门禁。此前在 PF/lo0/127.0.0.1—127.0.0.2 回环范围实测的全入站签名、真实 Go/mTLS 引用、TTL、撤销和进程崩溃结果仍有效；正式校验后的 lab 真实运行待 A4 授权，不构成 authorized 自动资格。PF 使用专用 `hg5<executorId 的 URL-safe Base64 无填充编码>/*`，保护端口（含固定 22/53/3389）从 1—65535 拆成闭区间，规则、枚举和精确状态清理共用区间。WFP 仍只有单端口实现，未在目标平台验收。

**Mac 全入站签名命令及主要恢复场景已实测；P5 整阶段未收口。** 本轮不重启主机，未安装常驻服务或接入真实业务库。PF 仅在回环测试期间临时挂接，结束恢复原过滤规则、释放本次 enable token、移除本次别名，并验证回到 Disabled。Windows 自动执行保持关闭。

### 本轮修复与验收

采用“先验执行器，再开放签发”。`canary_targets.py` 使用新建本地 PKI 和真实 Go `guardtargets`，collector/executor 身份分离；签名命令绑定实际短期引用和稳定目标 token。`pf_lab.py` 仅接受初始 Disabled 且只有预期 Apple 根规则的主机，用 `pfctl -R` 只临时调整过滤规则，不重载 NAT 等其他规则集。源文件/程序/配置哈希、规则状态摘要、清理时刻及失败记录保存在仓库外的新运行目录。

修复控制面断连/回执响应丢失只记审计的问题：`cycle` 现在把原动作记为 `uncertain`、暂停新动作并核对清理；仍保留原命令 ID、截止时刻及预算，回执重试同一 ID/内容。恢复失败继续为 `recovery_failed`。网络恢复不会静默重开自动能力，须先核对并重新启动执行器；旧命令不能重新应用。

2026-10-07 至 10-08 真实 PF 14 项矩阵已通过：TTL、显式撤销、写账本前/后和安装后回执前三个真实子进程退出、同目标并发预算、身份/目标/期限/签名负例、控制面断连、回执响应丢失、资产并发、动作速率、累计续封额度、授权撤销和到期。TTL 与撤销验证两个非保护端口、新建/已建连接、保护端口新建/已建连接及正常对端；TTL 清理不晚于 `blockUntil + 1s`。证据为 `Workspace/scratch/p5-peer-inbound-20261007-f/summary.json` 及各场景 `result.json`、SQLite 账本。控制面为本地 TLS 故障夹具，显式撤销直接调用执行器；尚未把这些结果表述为真实 P4 HTTP/数据库联合验收。

回归：Python 26 项、JDK 25 领域测试 10 项及两种 scope 的 Java/Python 对拍 2 项、Go 目标包测试、5 Schema/8 负例/55 观察、C helper 严格语法与 `git diff --check` 均通过。仍需收口自定义既有规则保护、并发撤销/续封组合及真实 P4 联合链路，保护清单和平台能力须显式绑定后才能讨论开放正式签发。未验证项不能由这 14 项通过替代。

首轮尝试因根规则规范化文字不同在系统改动前拒绝；第二轮新编译 helper 首次加载超过 0.5 秒并完整回滚。现先在挂接 PF 前完成 helper ABI 预热检查，执行期 0.5 秒上限不变；随后多轮实测通过。空子 anchor 名称可由 PF 保留，不代表活动规则。

### 2026-10-07 暂停与恢复记录

架构整理前曾暂停 P5；恢复后重新核对工作区与主机 PF 状态，未沿用旧二进制或旧服务配置。截图所列四层中，目标绑定已接通；P4 对 `peer_inbound` 的保护端口拒签及执行器的 `PROTECTED_TARGET` 拒绝仍是有意保留的门禁。PF 规则名称为 62 字节，保护端口区间和枚举已在 Mac 回环适配器实测，但不能据此开放自动封禁。

暂停前复核：临时新构建的 Go `guardtargets` 与 Python 执行器 21 项测试通过；Go 目标包测试、Java/Python JDK 25 签名对拍、C helper 严格语法检查及 `git diff --check` 通过。Java 对拍首次误用 JDK 17 失败，显式指定 Temurin 25 后通过；该失败不是代码回归。

恢复后的本机实测：原始 PF 为 Disabled，根规则仅挂接 Apple anchor。管理员临时加载仅增加本次 P5 anchor 的根规则、获取 PF enable token，并给 `lo0` 临时添加 `127.0.0.2` 别名。`peer_inbound` 适配器回环 canary 显示安装时新建与已建目标连接均失败，受保护的相邻控制端口保持连通；规则移除后目标连接恢复且枚举为空。helper ABI 与本机内核匹配。测试后重新加载 `/etc/pf.conf`、释放本次 token、移除别名，确认 PF 为 Disabled、根规则仅剩 Apple anchor、`lo0` 仅有原地址。证据为受控运行目录 `Workspace/scratch/p5-pf-canary-20261007/result.json`；此项是适配器直测，未签发命令，未验证 TTL/撤销/崩溃恢复。WFP、Windows 和 P7 G3 联合闭环仍未实测。

其后在同一受控回环边界运行 `pf_engine_canary.py`：由临时 Ed25519 密钥签发 `peer_service` 命令，固定目标解析夹具供给新鲜引用，独立恢复进程运行。验收结果 `passed=true`、`idempotentNoExtension=true`、`after.expired=true`、`after.clearedAtRecorded=true`、`after.rulesEmpty=true`；目标新建/已建连接受阻，控制端口连通，清理后目标恢复。证据在 `Workspace/scratch/p5-pf-engine-20261007/result.json`。测试退出后 PF 为 Disabled，根规则仅余 Apple anchor，回环别名已移除；PF 仍枚举到两个本次创建的空子 anchor 名称，但执行器 inventory 无规则，不能把空名称当作活动规则。该夹具绕过真实 mTLS 目标解析，不验证全入站命令、撤销、崩溃恢复或重启。

## 环境与验证

Python 3.12+，依赖固定在 `requirements.txt`；Go版本以 `sensor/go.mod` 为准。执行器使用独立环境，不复用训练虚拟环境。macOS包装器 `executor/python.sh` 为仓库内venv补全现有Python动态库路径。

```sh
python3 -m venv executor/.venv
sh executor/python.sh -m pip install -r executor/requirements.txt
go -C sensor build -o bin/guardtargets ./cmd/guardtargets
sh executor/python.sh -m unittest executor.test_engine executor.test_platform executor.test_transport executor.test_canary -v
go -C sensor test ./internal/hostguard ./cmd/guardtargets
```

后端使用JDK 25。`P5_EXECUTOR_INTEROP=true`启用Java/Python真实签名兼容测试，需要上述Python环境；普通后端构建不强制依赖Python。数据库测试使用已有 `DB_TEST_*`，只写专用测试schema。

```sh
P5_EXECUTOR_INTEROP=true mvn -f backend/pom.xml -Dtest=GuardDomainTest,GuardExecutorProtocolTest,GuardIntegrationTest test
```

## 本地配置

配置、密钥、账本和日志放仓库外受控服务目录：文件0600、目录0700。特权服务的源码、解释器、依赖与helper须由管理员控制，不能组写。Windows用专用服务身份及ACL提供等价隔离，不把训练目录作为服务目录。原始端点仅在本机解析器/恢复账本，不上传到控制面或写入日志。

`python -m executor keygen --directory <新的绝对目录> --key-id local-control` 生成 `signing.der`、`trust.json`、`budget.key`。已有目录拒绝覆盖，私钥不输出。后端使用 `cyber.guard.signing-key-id` / `cyber.guard.signing-key-file`；执行器仅取得公钥清单，不能取得控制面私钥。信任清单可含多个keyId：先预配新公钥，再切换签名，最后撤销旧key。

`python -m executor target-pki --directory <新的绝对目录>` 生成服务端、collector、executor三份独立证书/私钥及指纹。每个进程只分发自己的私钥；CA私钥不落盘，不提供任意证书签发接口。证书到期前重新预配并重启对应进程，不要求重启主机。

`--config` 使用受控JSON，字段如下，未知字段拒绝：

| 字段 | 内容 |
|---|---|
| platform / stateDir | pf或wfp；持久状态绝对目录 |
| assetId / executorId / sensorId / captureScopeId | P4登记UUID，collector和executor分离 |
| environment / interface | lab或authorized；精确接口，WFP使用接口别名 |
| localAddresses / peerAddresses / servicePorts | 非空精确允许列表 |
| protectedPeers / protectedServicePorts | 保护CIDR和端口；22/53/3389始终保护，网关/管理对端须登记 |
| capabilityIds / bundleIds / policyHashes | 本次批准的能力/组合UUID和策略SHA-256列表 |
| authorization | id、revision、status、validFrom、validUntil；UTC时间，status为active/revoked |
| limits | maxTtlSeconds、maxContinuousBlockSeconds、maxActiveRulesPerAsset、maxNewActionsPerMinute，不大于60/120/10/5 |
| trustFile / budgetKeyFile / credentialFile | 公钥清单、稳定预算密钥、executor专用bearer文件绝对路径 |
| controlPlaneURL / capabilityHash | HTTPS控制面根URL；能力集合摘要，加载时须等于由 capabilityIds 与 inboundCapabilities 推出的值（算法见 `contract.capability_set_sha256` 与[对拍向量](../docs/contracts/examples/capability-binding-vectors.json)），控制面领取时按 guard_capability 独立重算 |
| targetURL / targetCA / targetCertificate / targetKey | HTTPS回环解析器、CA、执行器证书和私钥路径 |

可选controlPlaneCA；PF须提供pfHelper。可选 `inboundCapabilities` 为 `[{capabilityId,protectionSetSha256,protectedPortsSha256}]`：capabilityId 必须在 capabilityIds 内且不重复，仅 PF lab 可填；protectionSetSha256 为 P4 保护文件摘要，protectedPortsSha256 为含 22/53/3389 的升序保护端口 JCS 摘要。改动保护端口后须重新登记并更新 capabilityHash，否则全入站命令被拒、控制面停止下发新命令。禁止HTTP、继承代理环境或跟随重定向；验证服务端证书。身份、预算密钥、状态目录、平台和连接地址变更须重启进程。不得删除账本或更换预算密钥取得新额度。

`guardtargets -config <绝对路径>` 使用listen、certificateFile、keyFile、caFile、authorizedUntil、scope；scope为P2 TargetScope的AssetID、SensorID、BootID、CaptureScopeID、Environment、ExecutorBootID、KeyEpoch、LocalAddresses、CollectorCertSHA256、ExecutorCertSHA256。`executor status`提供当前executorBootId；执行器每次启动后，目标服务/collector须采用新身份。

collector调用 `/v1/targets/lease`；旧请求省略scope仅登记`peer_service`，`peer_inbound`须显式传scope。`bind-target --config ... --input <受控文件>` 接受 `{binding,expiresAt}`，binding须包含scope与targetRef，全入站servicePort为null。本机解析确认后才向P4登记稳定目标，不创建规则。该入口没有改动 `guardlive` 的research运行路径，持续collector接线在相应部署/联合阶段完成。

## 运行与清理

先启动恢复器，再启动执行器。两个终端各运行一个进程；命令不会偷偷安装服务。

```sh
python -m executor recover --config <绝对配置路径>
python -m executor run --config <绝对配置路径>
python -m executor status --config <绝对配置路径>
python -m executor cleanup --config <绝对配置路径>
```

`cleanup`暂停新动作，仅清理账本可证明归属的规则；不能确认不存在时返回失败。提前故障清理保留uncertain等待核对/期限，不伪造正常到期。运行内用单调时钟；重启先清理旧规则，再领取绑定新boot的命令。

领取响应丢失时，先到达的撤销仍持久保存为墓碑，迟到命令不能再安装。服务退出与显式清理使用同一路径；残留规则或枚举失败返回失败状态。实态上报与执行/恢复共享跨进程锁，避免清理交错产生不一致摘要。

macOS先编译pf_state_helper.c并部署为root所有、不可组写的文件。管理员备份和核对PF配置后挂接精确anchor `hg5<executorId 的 URL-safe Base64 无填充编码>/*`；由 `PF.anchor_root(executorId)` 计算路径，不手填缩写。适配器不重载根规则、不启停PF、不改变默认放行规则；`check`核验PF启用、anchor挂接和内核ABI。

`launchd-config`生成可审查plist，需指定 `--directory --python --source --config --target-binary --target-config` 绝对路径，只生成不加载。解释器必须带实际运行所需的动态库/证书环境，不能假定launchd继承shell。Windows入口为 `python -m executor.windows_service --name HostGuard.P5.Executor --role run --config ...`，恢复服务用HostGuard.P5.Recovery和role=recover；安装SCM服务、权限和目标机运行尚未验证。

## 平台验收

`python -m executor.pf_canary --config ... --scope peer_inbound --output <新文件>` 是 Mac PF 适配器直测，不签发命令；完整 `peer_service` 路径另需 `--signing-key ... --key-id ...`、独立恢复器及 `stateDir/canary-binding.json` 中的新鲜 collector 引用。入口仅接受 127.0.0.1/127.0.0.2、lo0 和单个 49152—65533 端口；`peer_inbound` 还要求相邻控制端口位于保护清单。管理员须预先核对并临时配置专用 PF anchor/helper、PF enable token 和 `lo0` 的 `127.0.0.2` 别名；结束后逐项恢复并核验。入口检查新/已建目标连接、相邻控制端口及规则清理；只有完整命令路径才测试 TTL 恢复。不重启、不注入攻击流量；canary 不提供模型准确率或 P7 资格证据。

`python -m executor.pf_engine_canary --config ... --signing-key ... --key-id ... --scope peer_inbound --guardtargets <本轮构建的绝对路径> --scenario ttl --output <新文件>` 验证全入站签名命令与真实 mTLS 引用；状态目录须专用且为空。`--scenario` 还支持撤销、三个崩溃点、预算、授权和通信故障。省略 `--guardtargets` 只兼容旧 `peer_service` 固定解析夹具，不能运行全入站验收。

管理员可使用 `python -m executor.pf_lab --directory <不存在的绝对运行目录> --guardtargets <绝对二进制路径>` 运行矩阵。源码、依赖和解释器须先审查，运行期间禁止修改；入口不会请求提权、安装服务或重启主机。前置状态不符即拒绝，恢复证据不完整即失败，不得用全局 flush 或强制关闭 PF 来绕过。所有流量只走回环 echo，不访问外部目标。

仍须完成两平台实机故障矩阵、最小服务权限/ACL、常驻安装和完整运行接线。主机重启验收按用户本轮要求暂缓。G3 前须完成的“必需”场景见[验证与验收第 8 节](../docs/验证与验收.md#8-动作与恢复场景)；P6 模型门槛与 P7 联合资格独立判定。
