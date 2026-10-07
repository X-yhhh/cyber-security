# P5 本机执行与恢复

本目录实现独立执行器，不需要商业许可、程序发行证书或在线授权服务。命令使用本地 Ed25519 密钥，目标 IPC 使用本地生成的 CA；自动资格由 P4 登记的资产、能力、策略和授权限定。

## 当前范围

- 命令校验：rc.3 Schema、RFC8785/Ed25519、公钥有效期与吊销、资产/环境/执行器 boot、授权 revision/租约、能力/策略和保护清单；回执保持 rc.2。
- 本机目标：复用 Go P2 注册表，collector/executor 采用分离的 mTLS 身份；显式 `peer_inbound` 引用绑定方向与空服务端口，旧省略范围仅兼容 `peer_service`。`resolve-lease` 返回原始 lastPacketAt/expiresAt，不因查询刷新期限。执行器核验10秒证据期限、15秒引用期限，安装前再检查截止。
- 持久执行：SQLite FULL 同步，写规则前提交意图；同命令/动作/幂等键不重复安装、不延长 TTL。跨进程锁串行处理执行、撤销与恢复；稳定目标预算不随 boot、peerKey/keyEpoch 或策略变化。
- 独立恢复：`recover` 与 `run` 分开；到期、撤销、进程崩溃、时钟异常、密钥/授权撤销触发清理。启动先清理旧规则，未知归属不代删；不能确认时暂停并保留 uncertain/recovery_failed 和预算。
- P4 对接：HTTPS机器身份、心跳、命令/撤销领取、回执持久重试、guard-state/1实态核对、目标绑定和预算恢复证明。历史清零时刻单独追加审计，不能用补报提前恢复额度。

当前自动执行仍限 **IPv4/TCP 入站 peer_service**，其他方向/协议明确拒绝。rc.3 的 `peer_inbound` 命令已可验签识别；其目标引用与稳定预算身份已接通，Go/Python mTLS 对拍通过，但当前仍以 `PROTECTED_TARGET` 拒绝并生成 rc.2 回执。P4 保护资格也仍拒签。Mac PF 代码现把保护端口（含固定的22/53/3389）从1—65535拆成封禁闭区间，规则、枚举和精确状态清理共用区间；已通过离线测试、整组规则的 `pfctl -n` 语法检查与 helper 编译，**尚未安装或实测**。WFP 仍只处理单端口。PF 实际枚举格式、已有连接效果、保护端口不断连和恢复矩阵未实机证明前，不得解除 P4/P5 拒绝；端口扫描维持只告警。PF 使用专用 `hg5<executorId 的 URL-safe Base64 无填充编码>/*`，完整子规则路径为 62 字节；WFP 使用独立非持久子层、两层精确过滤器及接口 LUID。WFP 复用 P1 ABI，但对象生命周期不同，必须重新做平台验收。

**当前已验证代码、跨语言协议和隔离接口，P5整阶段未收口。** 本轮不重启主机；尚未安装常驻服务、挂接PF根规则或接入真实业务库。PF/WFP的新建/已建连接效果、目标机ACL、真实进程崩溃与主机重启均不能视为通过。Windows代码尚未在目标主机执行。

### 2026-10-07 暂停交接

用户将先整理本地与远端项目架构，P5 修复暂停。当前未提交的 P4/P5/P6 改动及 `scratch/` 原样保留；恢复工作时先核对工作区状态和整理后的路径，不沿用旧二进制或旧服务配置。截图所列四层中，目标绑定已接通；P4 对 `peer_inbound` 的保护端口拒签及执行器的 `PROTECTED_TARGET` 拒绝仍是有意保留的门禁。PF 规则名称已缩至 62 字节、保护端口区间和枚举代码已具备，但不能据此开放自动封禁。

本轮复核：临时新构建的 Go `guardtargets` 与 Python 执行器 21 项测试通过；Go 目标包测试、Java/Python JDK 25 签名对拍、C helper 严格语法检查及 `git diff --check` 通过。Java 对拍首次误用 JDK 17 失败，显式指定 Temurin 25 后通过；该失败不是代码回归。当前普通账号读取 `/dev/pf` 返回 `Permission denied`，无密码 sudo 不可用，故 PF 实际规则枚举、连接阻断与保护端口不断连、TTL/撤销/崩溃恢复均未验证。WFP 仍仅支持单端口，Windows 实测未做；P7 的 G3 联合闭环也未做。恢复后应先确认新架构中的 Mac lab 资产、管理员执行路径及网络隔离，再按下文平台验收逐项取证；在此之前保持端口扫描只告警。暂停期间不改动主机防火墙或远端环境。

## 环境与验证

Python 3.12+，依赖固定在 `requirements.txt`；Go版本以 `sensor/go.mod` 为准。执行器使用独立环境，不复用训练虚拟环境。macOS包装器 `executor/python.sh` 为仓库内venv补全现有Python动态库路径。

```sh
python3 -m venv executor/.venv
sh executor/python.sh -m pip install -r executor/requirements.txt
go -C sensor build -o bin/guardtargets ./cmd/guardtargets
sh executor/python.sh -m unittest executor.test_engine executor.test_platform executor.test_transport -v
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
| controlPlaneURL / capabilityHash | HTTPS控制面根URL；登记的能力集合摘要 |
| targetURL / targetCA / targetCertificate / targetKey | HTTPS回环解析器、CA、执行器证书和私钥路径 |

可选controlPlaneCA；PF须提供pfHelper。禁止HTTP、继承代理环境或跟随重定向；验证服务端证书。身份、预算密钥、状态目录、平台和连接地址变更须重启进程。不得删除账本或更换预算密钥取得新额度。

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

`python -m executor.pf_canary --config ... --signing-key ... --key-id ... --output <新文件>`仅接受127.0.0.1/127.0.0.2、lo0和单个49152—65533端口。必须有已配置的专用PF anchor/helper/恢复器，`stateDir/canary-binding.json`提供新鲜collector引用。该入口检查新/已建目标连接、相邻控制端口、到期恢复，最后清理自身规则；不重启、不注入攻击流量。固定命令不提供模型准确率或P7资格证据。

仍须完成两平台实机故障矩阵、最小服务权限/ACL、常驻安装和完整运行接线。主机重启验收按用户本轮要求暂缓。G3 前须完成的“必需”场景见[验证与验收第 8 节](../docs/验证与验收.md#8-动作与恢复场景)；P6 模型门槛与 P7 联合资格独立判定。
