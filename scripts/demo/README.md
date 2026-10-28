# 可复用实时演示工具

实现 [演示方案](../../docs/演示方案.md) 的 DEMO-1—DEMO-7。一次准备后，复用同一 lab 资产、发布组合、执行器与稳定预算密钥；每次运行使用新的短期授权、boot、目录和审计记录。默认命令只输出离线计划。源码交付不代表已经安装、登记、取得平台资格或完成彩排。

## 1. 范围与入口

| 入口 | 功能 |
|---|---|
| `prepare.py` | 私有材料初始化、幂等机器登记、安装 Windows worker；默认只打印计划，写入需要 `--execute` |
| `run.py` | 预检、备份恢复验证、独立审批、目标服务/采集/执行器、场景、健康冷却与收尾 |
| `worker.py` | Windows 本地截止时间、STOP、速率/并发上限；nmap 进程放入 kill-on-close Job Object |
| `targets.py` | 固定测试账号的 FTP、可选 SSH、HTTP；不提供文件、shell、exec、转发或 FTP 数据通道 |
| `report.py` | 按资产、运行时间和场景标记汇总事实；生成记录与两次一致性比对 |

`--dry-run` 不创建目录、不读取 Keychain、不登录、不运行子进程、不连接远端。实际运行仅允许一个 Mac Tailscale IPv4、一个 win-dev Tailscale IPv4、登记高位端口和动态解析的 utun。它不是任意攻击工具入口。目录、接口、端口、授权、证据或身份不符均拒绝。

S0 的 rate 为每秒 1 次、时长 10 秒、并发 1：先执行一次固定测试账号 FTP 正常登录，再在一条 HTTP/1.1 keep-alive 连接上发送请求；FTP 和 HTTP 合计至多新建 2 条连接。HTTP 连接意外中断时记录 `httpReconnectRefused` 并结束该段，不重连。HTTP 靶服务每条连接最多处理 64 个 `GET /`，首个请求头最多等待 40 秒，后续请求间空闲超过 5 秒即关闭。

S1 使用 `nmap -sS` 扫描显式登记的 64 个端口 `55300`—`55363`，rate 为 25 次/秒、并发 4、时长 15 秒；HTTP、FTP、SSH 三个服务端口加扫描端口共 67 个，低于 128 个端口上限。现场若证明 Tailscale 不支持 SYN 扫描，才改用同一端口范围和速率的有界 `connect_scan`。S2 为内置 FTP/SSH 测试登录；S3 为内置有界慢 HTTP；S4 为有界 HTTP 请求。后面三类没有直接调用 patator、slowhttptest、Hulk/GoldenEye；这些实现控制相同协议行为，但**不等同其流量分布，不保证当前模型识别**。所有工具/参数变更进入场景 SHA 和基线，不能复用历史成绩；S3 无告警可记为降级，S4 永远不能签发命令。

全局上限：50 次/秒、16 并发、单段 45 秒、段间至少 180 秒；授权最多 1800 秒、TTL 60 秒、稳定目标累计预算 120 秒。总控再次检查剩余窗口，不能靠修改时钟无限延长 worker 运行。外部工具先以 suspended 状态创建，加入 Windows Job 后才恢复执行；退出关闭 Job 清理工具子树。

## 2. 一次性准备（本次交付未执行）

1. 在仓库外选私有根目录，例如服务目录下的 `demo`。实际配置/证明/密钥/记录目录为 0700、文件为 0600，不含软链接；不得提交。复制 `demo.example.json` 并填写真实路径、地址、资产键、subject、capability payload 与哈希。示例 `100.64.0.10/20` 只是占位，不是授权目标。
2. 准备固定版本 Python 环境并安装 `requirements.txt`，构建本次提交的 `sensor/cmd/guardlive`、`sensor/cmd/guardtargets`。后端用 JDK 25 构建，部署到含预算恢复修正的 release **另行授权**。配置中的 `python` 必须是能正常导入 ssl、cryptography、rfc8785、pymysql、paramiko 的绝对稳定入口；迁移过的 macOS framework 可能需要启动包装器设置其 `DYLD_LIBRARY_PATH`，不能只检查 `--version`。
3. Windows 提前安装固定版本 Python（≥3.12）、Paramiko、nmap/Npcap，核实执行账号可使用 SYN 扫描；`install-worker` 不安装系统软件、驱动或修改 PATH。它只新建专用私有目录，ACL 限当前用户、SYSTEM、Administrators；已有目录须已满足条件，已有不同内容文件拒绝覆盖。
4. 复用 [P7 导入流程](../p7/README.md) 导入新的 lab 组合、审查 final/platform/canary、封存并独立批准。新策略须明确设置 `policyVersion=host-guard-decision/2026-10-08.1+demo-budget-20261017`，选择独立的 `host-guard-budget-recovery/2026-10-17.1` 恢复协议；旧策略保持原行为。新策略/组合摘要变化，必须重新取得对应 subject 的批准和报告，不复用旧成绩。`mode=auto`、60/120 上限和 dos_flood 只告警策略不变；不恢复已 suspended 组合，不改变模型/阈值，不转用真实资产 r6。utun platform/canary 资格由独立审查解决，脚本不自行授予资格。
5. 用 `prepare.py --operation init --execute` 建立长期 peer/budget 密钥与独立 IPC PKI。按现有后端 mTLS 管理流程信任此 CA、登记人工会话客户端证书；部署/信任变更另行授权。密码仅在 Keychain，配置保留 `keychainService`、可选 `keychainAccount` 与用户名。申请人和审核人必须是不同账户并具备既有 v2 权限，后台再次检查职责分离。
6. 用 `prepare.py --operation enroll --approval <私有批准文件> --execute` 登记独立 lab 资产、sensor、executor、采集配置并独立批准。整库备份及随机恢复库核验先于资源登记；幂等 Journal 可恢复部分失败，已有材料不覆盖。该步骤不建运行授权、不激活、不采集。生成 `enrollment.json` 和 `root-boundary.json`。
7. 用 `prepare.py --operation install-worker --approval <私有批准文件> --execute` 安装 worker/common 与固定白名单；文件相同可重试，不同则停止并要求明确升级处理。保留稳定 peer.key、budget.key、registrar 身份与 root 账本，不能删除/重建来获得额度。
8. 在网络层落实审核过的 Tailscale ACL：只允许登记测试流量，保留独立管理和恢复路径。确认 `en0` 正常且至少两个 BPF 设备对采集用户可读写。工具不修改 BPF 权限、不暂停 en0、不改 ACL。演示 `guardlive` 在固定私有 locks 目录按接口加锁；同一 utun 的本工具重复启动拒绝。其他抓包工具不遵守此锁，仍须现场核对。

操作批准文件格式（0600）：

```json
{"operation":"enroll","configSha256":"<common.digest(完整配置)>","reference":"<本次准备批准记录>","platformEvidenceRef":"<真实平台审查引用>"}
```

安装 worker 时 operation 改为 `install-worker`，无需 platformEvidenceRef。`init --execute` 仅初始化本地私有材料。批准引用是操作凭证记录，不能替代真正的用户批准、后端独立审核或网络隔离。

## 3. 现场前提与 root 冻结

`proofFile` 必须包含以下信息；每条证据都需已有私有文件、准确 SHA-256、操作者、不同审核人和批准引用。空 `passed=true` 不能替代证据。脚本校验绑定与摘要，证据的事实真实性由审核人负责。

```json
{
  "subjectSha256":"<组合 subject>","assetId":"<登记结果>","sensorId":"<登记结果>",
  "macAddress":"<Mac IPv4>","peerAddress":"<win-dev IPv4>","ports":{
    "http":55280,"ftp":55221,"ssh":55222,
    "scan":[55300,55301,55302,55303,55304,55305,55306,55307,55308,55309,55310,55311,55312,55313,55314,55315,
      55316,55317,55318,55319,55320,55321,55322,55323,55324,55325,55326,55327,55328,55329,55330,55331,
      55332,55333,55334,55335,55336,55337,55338,55339,55340,55341,55342,55343,55344,55345,55346,55347,
      55348,55349,55350,55351,55352,55353,55354,55355,55356,55357,55358,55359,55360,55361,55362,55363]
  },
  "evidence":{
    "networkIsolation":{"file":"/PRIVATE/acl-proof.json","sha256":"<sha>","operator":"<操作者>","reviewer":"<独立审核人>","approvalReference":"<引用>"},
    "utunDirection":{"file":"/PRIVATE/direction-proof.json","sha256":"<sha>","operator":"<操作者>","reviewer":"<独立审核人>","approvalReference":"<引用>"},
    "platformCanary":{"file":"/PRIVATE/platform-proof.json","sha256":"<sha>","operator":"<操作者>","reviewer":"<独立审核人>","approvalReference":"<引用>"},
    "capturePermission":{"file":"/PRIVATE/bpf-proof.json","sha256":"<sha>","operator":"<操作者>","reviewer":"<独立审核人>","approvalReference":"<引用>"},
    "coexistence":{"file":"/PRIVATE/en0-proof.json","sha256":"<sha>","operator":"<操作者>","reviewer":"<独立审核人>","approvalReference":"<引用>"}
  }
}
```

`ports` 必须逐字等于实际配置，示例只展示结构。`en0Plan` 格式为 `{"configFile":"<现有 guardlive 私有配置>","assetId":"<真实资产 UUID>","sensorId":"<现有 sensor UUID>"}`；预检和收尾比较准确 PID/启动身份、config SHA、boot 与新鲜心跳。

用已提交版本打包 root 源码、解释器、依赖、guardtargets：

```sh
python scripts/p5/lab_stage.py --commit <已提交SHA> --guardtargets /PRIVATE/release/guardtargets --output /PRIVATE/demo/stage-<SHA> --subject-binding /PRIVATE/demo/subject-binding.json --demo-boundary /PRIVATE/demo/root-boundary.json
```

`subject-binding.json` 沿用 P5 的完整 `{bundleId,subject,subjectSha256}`。demo boundary 和 subject 不一致拒绝打包。实际 `rootPlan` 为：

```json
{"launcher":"/PRIVATE/release/lab_root_launch.py","launcherSha256":"<sha>","stage":"/PRIVATE/demo/stage-<SHA>","manifestSha256":"<sha>"}
```

这里 stage 指输出目录（内含 manifest.json 和 stage/），`executorRelease` 等于其完整提交 SHA。启动器经系统密码框复制到 root 所有路径并核验，root 不执行可变工作区代码。持久账本为 `/private/var/root/hostguard-demo/<executorId>/state`，其 identity.json/budget.key 在复用时必须完全一致。

**两种模式都需要系统认证做只读 PF 预检和收尾核对**。alert-only 不启用、不修改 PF，不把普通用户查询失败当成“零规则”。PF 模式只使用专属 anchor 与本轮 enable token；utun 不创建任何回环别名。检测到既有启用 PF、未知根规则、旧项目规则或已有 127.0.0.2 别名立即停止，不自动清理其他项目。

当前流程复用 v2 已有 lab 机器/目标绑定路径，不为现场演示创建正式回放会话，不生成 G3 报告、不将 `replay_healthy` 用作额度恢复。utun 资格、网络隔离、现场方向仍必须先审查验证。

## 4. 每次运行

先离线查看，不会启动任何组件：

```sh
python scripts/demo/run.py --config scripts/demo/demo.example.json --dry-run --pf --scenes S0,S1,S2
python scripts/demo/prepare.py --config scripts/demo/demo.example.json --operation enroll
```

填写 grant 并取得针对该运行号的用户批准；端口、模式、完整场景文件 SHA、所选顺序必须精确一致，窗口≤30分钟，开始时仍须留够准备与全部场景冷却时间：

```json
{
  "runId":"demo-YYYYMMDD-HHMM-01","reference":"<本次批准记录>","purpose":"彩排-PF","operator":"<操作者>",
  "validFrom":"<UTC ISO时间>","validUntil":"<UTC ISO时间>",
  "macAddress":"<Mac IPv4>","peerAddress":"<win-dev IPv4>","ports":"<替换为完整 ports 对象>",
  "scenes":["S0","S1","S2"],"scenesSha256":"<完整 scenes.json SHA256>","mode":"pf"
}
```

取得上述批准后才执行（本次代码交付**没有执行**）：

```sh
VENV_PYTHON=/ABSOLUTE/PATH/TO/executor/.venv/bin/python
WORKTREE=/ABSOLUTE/PATH/TO/WORKTREE
ROOT=/PRIVATE/demo

"$VENV_PYTHON" -B "$WORKTREE/scripts/demo/run.py" --config "$ROOT/config.json" --grant "$ROOT/grants/demo-YYYYMMDD-HHMM-01.json" --run-id demo-YYYYMMDD-HHMM-01 --pf --scenes S0,S1,S2
```

只告警使用相同的绝对路径形式，grant.mode 为 `alert-only`：

```sh
VENV_PYTHON=/ABSOLUTE/PATH/TO/executor/.venv/bin/python
WORKTREE=/ABSOLUTE/PATH/TO/WORKTREE
ROOT=/PRIVATE/demo

"$VENV_PYTHON" -B "$WORKTREE/scripts/demo/run.py" --config "$ROOT/config.json" --grant "$ROOT/grants/demo-YYYYMMDD-HHMM-01.json" --run-id demo-YYYYMMDD-HHMM-01 --alert-only --scenes S0,S1,S2
```

真实运行要求 `run.py`、`--config` 和 `--grant` 使用 helper 可以逐词核对的绝对路径。B4 安装 LaunchDaemon 前，用演示 venv 的 Python 启动短暂进程并读取 `ps` 中显示的解释器路径；模板的 `__PYTHON_PS_PATH__` 必须填写该输出的第一个绝对路径字段，不要填 `.venv/bin/python` 符号链接：

```sh
VENV_PYTHON=/ABSOLUTE/PATH/TO/executor/.venv/bin/python

"$VENV_PYTHON" -B -c 'import time; time.sleep(30)' &
demo_pid=$!
ps -o command= -p "$demo_pid"
kill "$demo_pid"
wait "$demo_pid" 2>/dev/null || true
```

只告警不传模式默认只告警。S2 选择 SSH 时，在场景文件同时改 tool=`ssh_login`、ports 为登记 SSH 端口，再重新核对 SHA 和批准；不会使用系统 sshd。

预检要求干净的 release checkout、实际后端进程/JAR、Tailscale 对端在线、远端准确工具/worker/common 摘要与无残留进程、空闲测试端口、固定 enrollment、独立审批证据、上次清理完成。utun 编号动态查找，但编号与已批准 sensor 配置不同时拒绝，先重新审查配置。

在线备份使用同一个 **READ ONLY / REPEATABLE READ 一致快照**导出 InnoDB 基表、列值与行摘要，并保存 JSON DOUBLE 精度修复 SQL；恢复到本次随机 `cyber_r6_restore_<随机值>` 库后比较完整行与结构摘要，finally 只删除本次明确拥有的恢复库。保留备份，绝不恢复覆盖源库；views/triggers/routines/events/不支持列型直接拒绝。认证预检使用既有登录流程，会产生会话及登录审计；这些认证记录是资源写入前的明确例外，演示授权、绑定、机器资源写入必须在备份核验后。持续 en0 写入不要求暂停，也不纳入“源库前后必须不变”的错误条件。数据库结构迁移必须与备份错开。

worker 在 Windows 本地自主执行和冷却；下一段还需准确 GO 标记。控制端在断连期间不猜测完成。正常流程先等 TTL expired、无活动动作、连续健康≥120秒与后端预算恢复，再停采。只有激活的新演示策略允许断采后的新完整健康链恢复旧预算，证明保留恢复协议版本及策略 ID/摘要；为容忍上传延迟，通常需约130秒，不能拼接中断前后的链。

异常先撤销本次授权，然后 STOP、停止准确子进程、等待 root 清理、核对绑定与 en0。**没有组合暂停调用**。可重入收尾：

```sh
"/ABSOLUTE/PATH/TO/executor/.venv/bin/python" -B "/ABSOLUTE/PATH/TO/WORKTREE/scripts/demo/run.py" --config /PRIVATE/demo/config.json --teardown-only demo-YYYYMMDD-HHMM-01
```

收尾读取保存的场景与准确授权/进程身份；失败不会跳过其他清理项。清理不完整阻止下一次发包；只有预算未恢复时允许新授权先采集恢复，期间不发流量。仅预检失败且从未请求 root/子进程/授权的记录不阻塞修复配置后的重试。无法确认 root/PF 或远端进程退出时，保留失败证据，按原运行号继续核对，不能删除状态文件绕过。

## 5. 报告与展示

每次记录保存在 `<root>/runs/<runId>/`：state、scenes、api 幂等日志、backup、worker/facts、捕获轨迹、root 证据和 `record.json`/`record.md`。含端点与私有执行材料，均不提交 Git。报告只读采集该资产与本次起止范围内的业务事实，未归属场景的命令也导致失败；只接受 projected applied/expired、TTL≤60、对应目标预算恢复事件。错误类别、规则来源命令、S4 命令、缺失回执/清理项均不能通过。S3 没有告警/命令可以明确降级。

```sh
python scripts/demo/report.py --root /PRIVATE/demo/runs --run demo-YYYYMMDD-HHMM-01
python scripts/demo/report.py --root /PRIVATE/demo/runs --compare demo-YYYYMMDD-HHMM-01 demo-YYYYMMDD-HHMM-02
```

`--compare` 要求两次均通过、模式/基线/场景一致，比较告警类别、命令有无及范围、TTL、时延档位和全部收尾项。首次通过后，经核对将 record.json 的 `baseline` 对象保存为配置指定的 `baselineFile`（0600），保留原记录；未保存或不同则 `sameBaseline=false`，不会伪称同基线。基线变化需重新彩排。只告警与 PF 应分别验证；答辩使用前，同一最终模式和基线下连续两次完整彩排须一致。

控制台沿用实时态势、事件研判、处置记录：按 lab 资产和本次时间窗口筛选，对照 report 的 decision/command ID、applied/expired 与预算事件；没有新增页面、权限或接口。演示记录不是模型性能评估，不改写锁定测试成绩、G3 或发布资格。

## 6. 验证与边界

离线测试（不启动演示）覆盖配置/批准拒绝、零副作用 dry-run、协议替身、生命周期顺序、异常继续清理、稳定身份、精确撤销、TTL/回执/预算/跨次报告、备份值编码、PF 无别名会话、Go 双向过滤/读取水位/接口锁和后端新健康链恢复。运行：

```sh
python -B -m pytest scripts/demo scripts/p5 scripts/p8/test_observer_lifecycle.py scripts/p8/test_register_alert_only.py
(cd sensor && go test ./cmd/guardlive ./internal/hostguard ./internal/guardlab)
# 使用 JDK 25 的 JAVA_HOME
(cd backend && mvn -Dtest=GuardBudgetRecoveryTest,GuardHealthTest,GuardDomainTest test)
```

本次未启动演示/部署、未安装远端工具、未调整 ACL/BPF、未写业务库、未加载真实 PF。Windows Job/Npcap、真实 MySQL 在线备份恢复、utun 方向/权限/现场特征、en0 共存与完整双次彩排仍需现场授权验证；代码测试不能替代这些证据。
