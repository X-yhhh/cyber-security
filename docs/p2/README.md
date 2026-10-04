# P2 因果提取与契约冻结

日期：2026-10-04。状态：**passed（本阶段研究软件验收）**，可复算裁决见 [stage-exit.json](stage-exit.json)。P1-D 数据入口通过，P1 平台出口继续 blocked；P2 通过不改变平台、模型或自动执行资格。

同日后续已完成[数据补齐与重新冻结](data-readiness/README.md)：final研究集为23020条快照，训练/选型验证/独立校准的正常快照为880/2887/287条。下文4267条原始索引及软件出口作为历史验收保留；P3应使用[新数据清单](data-readiness/freeze-manifest.json)。prefix仍不具独立研究资格，最终测试仍未分配。

完成独立 v5 因果提取器、PCAP/live 共用输入引擎、鉴权目标引用原型、全量标签关联、分区、golden 和 Windows 实际离线验证。候选契约冻结为 `host-guard/5.0.0-rc.2`，45 个文件的集合 SHA-256 为 `327fa3aad84f32e55bd978d6e68bfe4c09ab814e4ccef5a2e7a240800bc95c69`，逐文件内容见 [freeze-manifest.json](freeze-manifest.json)。

## 交付内容

| 入口 | 本阶段实现 |
|---|---|
| [hostguard](../../sensor/internal/hostguard/engine.go) | 有界乱序和水位、因果 prefix/final、TCP parent/epoch/续段、1/5/30秒上下文、质量与容量边界 |
| [输入适配](../../sensor/internal/hostguard/input.go) | Ethernet/RAW IP PCAP、单接口单section PCAPNG，与 `RunLive` 使用同一引擎；现场抓包适配为cgo/libpcap入口 |
| [模型向量](../../sensor/internal/hostguard/vector.go) | 43个数值/缺失掩码和3个类别输入；不把身份、原始地址、端口或标签送入向量 |
| [目标引用](../../sensor/internal/hostguard/target.go) | 回环mTLS、collector/executor证书绑定、租约、身份/环境/boot/方向/服务核对、过期和时钟回退失效 |
| [guardextract](../../sensor/cmd/guardextract/main.go) | research-only离线观察、本机端点旁路和运行摘要；已有输出拒绝覆盖 |
| [guardjoin](../../sensor/cmd/guardjoin/main.go) | 全部选定TCP标签的包数/载荷数关联；独立有界HTTP起点旁路，仅生成结构候选 |
| [分区工具](../../scripts/p2/build_partition.py) | 活动/parent分组、隔离带、独立boot、整parent排除、跨分区近重复排除及样本权重 |
| [guardgolden](../../sensor/cmd/guardgolden/main.go) | 20个合成场景，55条冻结观察；用 `-check` 检查而不改写期望 |
| [评估计划](evaluation-plan.json) | 在模型选型前登记研究范围、分组、预算、独立校准与final补数条件 |

本地应用基线为 `main@f4429f5`；远端为 `win-dev` 的 `training/windows-cuda@9378f027e08d49192a54371a8ff23730358547ed`。原有 P1 修改和远端 phase2 训练文件保留；本轮没有提交或推送。

## 实施前语义补充

候选 `5.0.0-rc.1` 未规定新 SYN 关闭原因、分段后的握手状态、缺陷影响时长及 EOF 水位。P2 使用新版本冻结这些语义，旧 v4 资源不变：

- 新 SYN 关闭旧 epoch 的 final 原因为 `new_syn`。同一未完成握手、同发起端、同序号的 SYN 才算握手重传；已完成握手或不同序号的新 SYN 开新 parent。
- TCP 空闲/120秒切段保留 parent、初始方向、服务和握手状态；每个新 flow 重置长度、IAT、标志计数及快照序号。没有新报文不创建续段。连接身份保留在有界表中直到新 SYN 或引擎结束，满表拒收并记录 capacityDrop，不能遗忘后误计为独立连接。
- FIN/RST 后5秒吸收非 SYN 尾包；之后的无 SYN 段保留 parent，但方向降为 unknown。UDP 在空闲后开始新的观察 epoch；不赋予自动资格。
- 定时器在下一报文时刻之前逐个执行；相同时刻先处理全部可释放报文，再执行定时器。已完成水位上的迟到包不改历史。EOF 将已收到的缓冲释放到最大事件时刻，不虚构未来空闲，剩余活动流以 eof 结束。
- 捕获 gap、无法解析的必需头、分片及容量丢弃重置上下文覆盖，影响所有活动流；随后30秒内新流继续携带缺陷标记。超水位迟到包同样使上下文缺损。无法读取的特征不造值，卸载大包只保留诊断。
- 捕获帧副本和TCP重传都按实际观测包计数；captureSeq 重复或倒退拒绝。载荷不进入提取器；应用层起点只存在独立标签旁路。
- 本地目标引用仅为原型，research 永远为 null。原型通过双向 TLS 区分 collector/executor，绑定身份、环境、boot、捕获域、地址版本和短租约；不包含任何 OS 动作。

## 数据与评估预登记

复用 P1 已取得的完整原件。CIC 周三为开发暴露，按发布者活动分组；全量试点指已登记目标主机的完整捕获和对应标签行，不以抽查冒充全量。周五已暴露，不能转作盲测。受控良性任务只接受能匹配任务范围的连接。Attempted、歧义和起点未知显式排除；不会仅凭最终攻击标签给此前 prefix 标攻击。

同一 parent、活动或重复组必须同分区。实际使用300秒隔离：train截至 `2017-07-05T13:10:30Z`，validation从 `2017-07-05T13:15:30Z` 开始。各分区使用新引擎和独立boot；跨边界、Attempted、歧义或不支持家族关联到的parent整体排除。未取得独立且未暴露的同家族最终活动时，final_test 标为未分配，保留补数任务，不声称具备最终验收资格。

完整周三原件读取 **13,788,878 帧**、输出 **293,378 条观察**；登记目标TCP标签 **180,765/180,765** 关联匹配。这里“全量”指该原件内登记目标的全部TCP标签，非所有主机/协议。[标签统计](label-normalization.json)、[完整提取摘要](wednesday-final-extraction.json)和[分区统计](partition-manifest.json)保存来源哈希、质量、方向、保留和排除计数。

研究索引严格限制为 **IPv4/TCP/inbound/servicePort=80、flow-final-v1**：

| 分区 | 攻击快照 / parent | 正常快照 / parent | 攻击活动 |
|---|---:|---:|---|
| train | 3024 / 1731 | 1 / 1 | publisher Slowloris |
| validation | 1238 / 742 | 4 / 4 | publisher Slowhttptest |

合计4267条研究观察，每个parent总权重为1。其他服务的正常记录仅列为诊断；上述正常样本量严重不足，不能据此选模型或校准策略。475条Slowloris结构起点候选尚未成为批准的prefix监督。独立校准活动不足，final_test未分配、未读取；周三/已暴露周五及其镜像均不能改作未见最终集。

P1授权受控HTTP原件另作提取对拍：**2958帧、71条观察（62 prefix、9 final）**，见[受控摘要](controlled-final-extraction.json)。它使用自定义服务端口，只作为诊断和跨平台一致性证据，不并入上述TCP/80负例。

## 已执行验证

| 检查 | 结果与边界 |
|---|---|
| Go测试 | 82项通过（含子测试）；1项旧系统钥匙串集成测试 `TestKeychainRoundTrip` 因环境门禁跳过；失败0 |
| race / vet / gofmt | hostguard race通过，Go vet通过，新增Go文件格式一致 |
| 因果与输入边界 | 未来包不改变历史prefix；同时间/迟到/gap、握手重传/续段、截断/卸载/容量、RAW/IPv6、EOF及PCAP/live夹具对拍通过 |
| 目标IPC | 实际回环mTLS请求，角色错配、错误/过期引用、绑定差异、失效及回退时钟拒绝通过；没有OS动作 |
| golden | 20场景、55条观察；Mac和Windows均实际 `-check` 通过 |
| Java独立参考 | JDK `25.0.2+10-LTS`，独立两遍统计核对21条快照；不复用Go增量方差实现 |
| Schema | 5份Schema、8个负例、293310条分区与受控观察通过；注册日期格式检查器 |
| Windows实跑 | 最终冻结测试程序、golden和提取器均退出0；核对24份同步文件哈希 |
| 逐字节一致性 | Windows与Mac受控观察均为 `90e6a12ecd1afed3ac7cfe998f99a244736645a9ddf2f63463852b415583cc17` |
| Windows交付 | 50份源码/契约/golden/研究文件哈希全部匹配，见[交付验证](windows-delivery-verification.json)；接收端可直接运行冻结校验 |

本地使用 Go `1.26.4`（darwin/arm64）；Windows为 `10.0.26200`、AMD64、Python `3.14.4`，执行的是交叉编译后的真实程序。Windows提取摘要另见[windows-extraction-final.json](windows-extraction-final.json)。P2验证没有启动物理接口实时采集；live对拍范围是确定性输入夹具，实际抓包依赖仍需后续授权平台验收。

本轮执行的核心验证命令如下。Go命令工作目录为 `sensor/`，Python/Java命令工作目录为仓库根目录；`JAVA_HOME`须指向已确认的JDK25：

```sh
CGO_ENABLED=0 go test -json ./...
go test -race ./internal/hostguard
go vet ./...
CGO_ENABLED=0 go run ./cmd/guardgolden -check
```

```sh
"$JAVA_HOME/bin/java" scripts/p2/FeatureReference.java sensor/testdata/hostguard-v5
python3 scripts/p2/validate_contracts.py \
  --observations artifacts/p2/run-20261004/train-observations.jsonl \
  --observations artifacts/p2/run-20261004/validation-observations.jsonl \
  --observations artifacts/p2/run-20261004/controlled-final-observations.jsonl
python3 scripts/p2/freeze.py --check
python3 scripts/p2/report.py --run artifacts/p2/run-20261004 --check
git diff --check
```

Windows在训练仓库中执行：

```powershell
python .cache/host-guard-p2-freeze-20261004/verify_windows.py --bundle .cache/host-guard-p2-freeze-20261004
```

此验证器实际调用 `hostguard.test.exe -test.v`、`guardgolden.exe -dir <bundle>/golden -check` 和 `guardextract.exe -config <bundle>/windows-config.json -pcap <bundle>/controlled.pcap -out <bundle>/windows-observations.jsonl -report <bundle>/windows-extraction.json`；均退出0。输出采用独占创建，重跑时须先归档本任务的旧输出，不能覆盖证据。

## 已修复问题与保留风险

1. 分区初次复用了boot，完整性校验拒绝身份重叠；改为独立boot和引擎后重算。
2. 受控抓包使用RAW IP链路；加入显式12/101链路适配及与Ethernet的对拍，其他未知类型仍拒绝。
3. Mac ARM浮点融合运算导致标准差最后数位与Windows不同；在方差累加中显式float64舍入后，完整观察JSON逐字节一致。
4. Windows曾以4551拒绝最终冻结的golden/提取器。CodeIntegrity 3077/3033将拒绝归于 `VerifiedAndReputableDesktop`（Smart App Control）。同一位置、同一哈希的程序后续正常重试成功；本轮未签名、改名规避或修改策略。[最终状态核验](windows-state.json)记录了二进制哈希、拒绝事件、未变化的训练分支及仍然启用的保护策略。管理员权限及无Zone.Identifier不能保证程序获准。信誉判定变化的具体原因未确定，后续构建仍可能再次遇到此问题，不能称为永久修复。
5. 交付包最初只在顶层保存冻结清单，接收端的原路径校验无法直接运行；补齐 `docs/p2/freeze-manifest.json` 并在打包前校验全部冻结文件。Windows与Mac的Path排序差异还导致等价清单文本不同，已改为按相对POSIX路径文本排序及显式UTF-8。最终重新冻结和核对50份交付文件；提取器及二进制未因此改变。

微软的[Smart App Control说明](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)描述了应用信誉和受信任CA签名校验；本机当前没有可用签名证书。本轮成功证明冻结制品可执行，不推定未来制品可执行。

## 证据、恢复与下一阶段

公开目录只保存代码、合成golden及去敏汇总。原件、配置、随机密钥、原始端点账本、JSONL研究观察及历史失败均在忽略目录 `artifacts/p2/run-20261004/` 保留；报告中的SHA-256绑定对应实跑证据。原件与许可来源沿用[P1来源记录](../p1/README.md)。

Windows公开冻结材料位于训练仓库 `contracts/host-guard-v5-rc2`，4267条观察和分区索引位于忽略目录 `.cache/host-guard-p2-development`。交付不含端点账本或密钥；单独的离线验收缓存中受控配置与测试密钥只供本次同源对拍。远端训练分支及原有未提交文件保持原状，仅新增本阶段材料。

本轮没有切换v4服务、执行数据库迁移、训练/激活模型、实施防火墙动作、改系统防护或重启；无需服务重启。没有删除用户文件，失败/旧生成物以本任务命名归档。撤回P2时可先移出独立材料，再按差异撤回本轮新增源码/文档；保留P1及其他已有改动，不使用整仓重置。

后续入口为P3的final研究可行性。[数据补齐](data-readiness/README.md)已补充同服务困难良性、独立校准活动并裁决475条来源限定prefix候选；独立prefix选型/校准与未暴露最终活动仍待补齐。P1严格跨重启TTL、Mac平台动作和P5持久恢复继续待验收。目标IPC是易失原型，不承担动作执行、持久恢复或发布资格。
