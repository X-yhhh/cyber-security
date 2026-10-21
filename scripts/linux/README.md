# 远端 Linux 只告警传感器：A4 模板

规格为[远端传感器任务单](../../docs/任务/远端传感器任务单.md)第 0 节、F1—F5、A4 及 B1/B2/B5/B6。本目录的模板尚未安装或启动；下面的现场步骤分别属于后续卡片的授权范围，A4 仅做离线验证。

硬前提是**不影响远端 NewAPI**：不重启、重载或修改 newapi/nginx/mysql/ssh，不改防火墙、sshd 全局配置、sysctl 或网卡 offload，不执行系统升级或整机重启。远端不编译、不运行测试。单元只管理本项目进程，不依赖上述业务服务。

## 1. 占位符与目录

复制模板到仓库外的私有 staging 后替换；不在仓库模板中填入真实主机、地址、密钥或凭据。

| 占位符 | 替换内容 |
|---|---|
| `@ROOT@` | Linux 私有根的绝对路径，与 A3 的 `remoteRoot` 完全相同 |
| `@RELEASE@` | 不可变 release 绝对路径，建议位于 `@ROOT@/program/releases/<SHA>`，不使用 current 软链接 |
| `@VENV@` | Linux Python 3.12 venv 绝对路径，建议位于 `@ROOT@/program/venv` |
| `@REMOTE_HOST@` | 远端主机名或公网 IP，仅在 Mac 私有副本填写 |
| `@TUNNEL_PUBLIC_KEY_BASE64@` | 专用 ed25519 公钥的 base64 字段，不包含密钥类型或私钥 |
| `@TUNNEL_PRIVATE_KEY@` | Mac 专用私钥绝对路径，0600，不下发远端 |
| `@KNOWN_HOSTS@` | Mac 已通过可信途径核对远端主机指纹的专用 known_hosts 文件绝对路径 |
| `@MAC_LOG_DIR@` | Mac 已存在的私有日志目录，0700，预建两个隧道日志为 0600 |

单元路径应不含空白、引号、反斜线、控制字符、`%` 或 `$`，避免 systemd 分词、specifier 或环境展开；`@ROOT@`、release 和配置路径的任何层级均不能是符号链接。`ProtectHome=yes` 会隐藏 `/home`、`/root`、`/run/user`，Linux 根/release/venv 及 Python 解释器不能放在这些位置。venv 的正常 Python 解释器链接可以指向系统 `/usr/bin/python3.12`。

plist 中每个 `<string>` 是一个 argv；路径不用添加 shell 引号，含 `&`、`<` 等时要做 XML 转义，或用 Python `plistlib` 读写。`cybertunnel@@REMOTE_HOST@` 替换后为 `cybertunnel@主机`。渲染后查找 `@[A-Z][A-Z0-9_]*@`，必须没有残留，再重新 lint/verify。

远端布局（由 B1/B5 创建，目录均为 cybersensor 所有的 0700）：

```text
@ROOT@/
  config/
    sensor.json                 # A3 静态地址、authorized/all_inbound_tcp
    executor-observer.json      # mode=alert_only，capabilityIds=[]
    sensor.credential
    executor.credential
    backend-ca.pem
    peer.key
    ipc/                        # ca.pem、collector.pem/key、executor.pem/key
  program/
    releases/<SHA>/guardlive
    releases/<SHA>/scripts/...
    releases/<SHA>/executor/...
    venv/
  ledger/sensor/                # 每次采集独立 bootId
  ledger/executor/observer/     # recovery.json、run.json 脉冲
  logs/
```

配置、凭据、私钥及 ledger/log 普通文件为 cybersensor 所有的 0600，二进制为 0700。A3 的 `machine-tls.properties` **只供 Mac 后端使用，不下发远端**；A3 的本机包里实际路径为 `config/...`，不是包顶层。IPC 中远端只需要上列客户端证书/私钥及 CA；Mac 保留其余 PKI 原件。不得生成或下发 `targets.json`，不得加载 Linux 防火墙执行器。

## 2. 远端 venv 最小依赖及实际 import 来源

最小直接依赖如下，版本取自现有 [executor/requirements.txt](../../executor/requirements.txt)：

| 直接依赖 | 导入位置与原因 |
|---|---|
| `cryptography==49.0.0` | `scripts/p7/j1_run.py:29-33`、`executor/contract.py:7-9`；分别由 toolkit 和 observer 的 import 链载入 |
| `jsonschema==4.26.0` | `executor/contract.py:10` 无条件导入 `Draft202012Validator`、`FormatChecker`，即使 observer 只计算零能力摘要也需要 |
| `rfc8785==0.1.4` | `scripts/p7/j1_run.py:28`、`executor/common.py:11`，用于规范化 JSON 与摘要 |

导入链：`sensor_service.py:13 → scripts.p8.toolkit:13 → scripts.p7.j1_run`；`observer_executor.py:16-17 → toolkit / executor.contract:12 → executor.common`。`scripts/linux/supervisor.py` 本身仅用标准库，但其采集子进程会加载 toolkit。这个运行入口不校验动作 Schema，不需要 `jsonschema[format]` 的可选格式扩展；不需要 pytest、ONNX、numpy、scapy 或任何 Python 抓包包。pip 仍需安装上述三个包各自的必需传递依赖。

因此 B5 的 release 必须保留仓库相对结构，至少包括 `scripts/linux/`、`scripts/p8/`、**`scripts/p7/j1_run.py`**、`executor/__init__.py`、`executor/contract.py`、`executor/common.py` 和 `docs/contracts/`，加 B2 的 Linux `guardlive`。可以完整携带这些脚本目录的已跟踪源码；不打包 Mac `.venv`、缓存、数据、凭据、权重或 Mac 二进制。

B1 后续安装示例（占位符在私有副本中替换，wheelhouse 预先准备 Python 3.12 Linux amd64 兼容轮子及全部传递依赖）：

```sh
nice -n 19 /usr/bin/python3 -m venv '@VENV@'
nice -n 19 '@VENV@/bin/python' -m pip install --no-index --only-binary=:all: \
  --find-links '@WHEELHOUSE@' \
  'cryptography==49.0.0' 'jsonschema==4.26.0' 'rfc8785==0.1.4'
nice -n 19 '@VENV@/bin/python' -m pip check
```

`@WHEELHOUSE@` 是远端已审核的本地轮子目录。以 cybersensor 身份执行，venv 目录须尚不存在。缺少兼容轮子时停止，不能在远端转为源码构建。系统依赖仅是现有 Python 3.12/venv、`/usr/sbin/ip` 和 B1 核准的 `libpcap0.8t64` 及传递库，不安装 Go、gcc 或 libpcap-dev。

## 3. B2：两步构建模板（仅 Mac）

需要已运行且获准使用的 Docker 环境、Mac Go **1.26.4** 和 Python ≥ 3.11。脚本不启动 Docker Desktop。Go 的版本从**目标提交的** `sensor/go.mod` 读取，并要求本机 Go 同版本且 `GOTOOLCHAIN=local`。

1. 操作者预先取得官方 `go1.26.4.linux-amd64.tar.gz`，从可信的官方发布摘要核对 SHA-256。脚本只接收本地包及摘要，不下载 Go；包内容在宿主机及 Dockerfile 内各验证一次。官方摘要不内置在模板中。
2. 调用脚本。它先从目标提交读取 `sensor/go.mod`、`sensor/go.sum`，在隔离的 modules 目录运行 Mac `go mod download`，使用此次输出内独立的模块缓存；再用 `git archive <SHA>` 取得且仅取得 `sensor`、`docs/contracts`、`backend/src/main/resources/feature-contract`、`backend/src/test/resources/feature-contract`。随后以小构建上下文（只有 Dockerfile 和已验证 Go 包）构建 `FROM ubuntu:24.04` 的 amd64 镜像，apt 带重试安装 gcc/libc6-dev/libpcap-dev；最后 `docker run --network none` 只读挂载源码及模块缓存，完整运行 `go test -count=1 ./...`，成功后才以 cgo 构建 guardlive。

```sh
BUILD_GO='@MAC_GO@' BUILD_PYTHON=python3 \
  sh scripts/linux/builder/build_guardlive.sh \
  '@COMMIT_SHA@' '@GO_ARCHIVE@' '@GO_SHA256@' '@BUILD_OUT@'
```

构建参数：`@MAC_GO@` 为 Mac Go 正式入口；`@COMMIT_SHA@` 为 GA 合入的完整 40 位小写 SHA；`@GO_ARCHIVE@` 为本地 Linux amd64 Go 包绝对路径；`@GO_SHA256@` 为官方 64 位小写摘要；`@BUILD_OUT@` 为**尚不存在**的仓库外输出绝对路径，其父目录须已存在。归档与输出路径不得含逗号或控制字符。B2 的预演目录仅供对照，不覆盖或复用为正式输出。

第一步模块准备及镜像 apt 允许在 B2 授权下联网；第二步容器网络固定为 none，明确设置 `GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local GOMODCACHE=/modcache`。不执行 go mod tidy，不修改工作区源码。任何测试/构建失败均停止，不能修改共享代码以绕过失败。

输出在 `@BUILD_OUT@/evidence/`：`build.json`（同时打印到 stdout）、`guardlive`、`guardlive.sha256`、`test.log`、`test.rc`、`build.log`、`ldd.txt`、Go/libpcap/glibc 版本、镜像 ID 及准备阶段日志。JSON 包含提交 SHA、Go 包和源码归档 SHA-256、测试命令/结果、二进制 SHA-256、ldd 原文及依赖是否齐全。输入校验失败不创建输出；后续失败保留已有证据，缺少的字段为 null，`ok=false`。`source.tar`、归档源码、镜像上下文和模块缓存在此次输出内保留，不自动清理。

只有 `build.json` 的 `ok=true` 才能交 B5。B5 将 guardlive 放在 release 根，构建 JSON 留作证据；远端只核对 SHA-256 和 `ldd` 的全部库可解析，不编译、不跑测试。Go 版本、glibc 或测试不匹配时停止报告。

## 4. B1/B5/B6：后续安装步骤

1. **B1 基线和安装授权**：按任务单记录 newapi/nginx/mysql/ssh 的 active 状态、MainPID、启动时间、5 次 HTTPS 状态与中位时延、MemAvailable、1 分钟 load；每次变更后复测。任何 PID/启动时间改变或服务影响均停止。检查监听与全局 sshd 配置，不修改它们。
2. **B1 用户和运行库**：创建无登录 shell 的系统用户 cybersensor、cybertunnel；创建上述私有目录（含 ledger、logs，`ReadWritePaths` 不负责创建它们）。先执行 `LC_ALL=C apt-get -s --no-install-recommends install libpcap0.8t64`，清单须符合任务单 B1；只读扫描 `/proc/*/maps`，确认没有进程加载待变更的 libnl/ibverbs 库。之后按 B1 用 `NEEDRESTART_SUSPEND=1 apt-get install -y --no-install-recommends libpcap0.8t64`，暂停 needrestart，避免自动重启既有服务；不执行 apt upgrade。安装 venv 及轮子时用 nice 19。
3. **B1 单元**：在私有 staging 替换三份 service 的 `@ROOT@`、`@RELEASE@`、`@VENV@`。先确认同名单元不存在，记录新增文件清单；用 `systemd-analyze verify` 同时检查三份渲染文件。分别安装到 `/etc/systemd/system/cyber-sensor.service`、`cyber-observer.service`、`cyber-observer-recovery.service`（root 所有、0644），执行 `systemctl daemon-reload`。此阶段**不 enable、不 start**。After/Wants 仅涉及 network-online 和本项目 recovery，不涉及业务服务；Wants 拉起 recovery，run 自身检查脉冲，临时故障后按 Restart 继续尝试。
4. **B5 release 和配置**：按上面的 import 闭包及 A3 `config/` 布局下发；`machine-tls.properties` 留在 Mac。核对二进制/配置清单、属主、0700/0600 以及 guardlive SHA-256、ldd。以 `sudo -u cybersensor` 做可读/可执行检查；在 release 目录运行 venv Python 的纯 import 检查（`import scripts.p8.sensor_service, scripts.p8.observer_executor, scripts.linux.supervisor`），不调用 main/serve。传感器唯一能力为 CAP_NET_RAW，observer/recovery 的能力集合为空，不使用 setcap 或 root 运行。
5. **B1 公钥、B6 Mac 隧道**：在 Mac 配置包中生成专用 ed25519 密钥，私钥 0600；只将对应公钥按 `authorized_keys.template` 加到 cybertunnel 的私有 authorized_keys。目录 0700、文件 0600。`restrict` 禁用 PTY/agent/X11，`port-forwarding` 重新允许转发，`permitlisten` 限定反向监听；它本身不限定本地正向转发目的地。若全局 `AllowTcpForwarding no` 则停止报告，不改 sshd 全局配置。核对并预置 known_hosts，不能禁用主机指纹验证。
6. **B6 LaunchAgent**：替换 plist 的 Mac 路径与远端占位符，预建私有日志，`plutil -lint` 检查，再把独立 plist 安装到当前用户 `~/Library/LaunchAgents/` 并 bootstrap。RunAtLoad/KeepAlive 只在此刻生效，不修改其他作业。ssh 参数为 `-N`、BatchMode、断线探活、转发失败退出，以及固定 `-R 127.0.0.1:18082:127.0.0.1:18082`。远端核对 18082 **只监听 127.0.0.1**，用 collector 证书做一次只读机器请求；复测 Mac 现有服务和远端 NewAPI 基线。
7. **GB/C0/C1**：GB 完成后另按 D-R7 授权操作。先 recovery，再 observer（其 run 最多等待 recovery 脉冲 30 秒），最后 sensor。C0 仅 start，不 enable；C1 才 enable 三个单元。observer 用零能力存活脉冲和心跳，不领取命令、不调用 PF，不生成清理证明。

## 5. 退出、日志、容量和补传时机

以下退出码仅属于 supervisor（systemd 主进程），不能套用到 observer：

| 码 | 含义与后续 |
|---|---|
| 0 | 收到 SIGTERM/SIGINT 的主动停止，正常回收子进程，不重启 |
| 2 | Linux/用户/配置/文件权限/锁/地址等自检失败，或授权时间到期；修复并核对授权后人工恢复 |
| 3 | 可读取的 report 中出现授权/身份致命码；先核对并修复身份、范围或授权，不自动重启 |
| 4 | ledger 所有普通文件合计超过默认 5 GiB，保留数据；先人工处理容量与未确认批次 |
| 5 | 每 10 秒检查：MemAvailable < 300,000,000 字节或根分区可用 < 10,000,000,000 字节；停止让出主机资源，人工核对后恢复 |

`RestartPreventExitStatus=2 3 4 5` 保证这些 supervisor 退出不会被 systemd 自动拉起。其他 guardlive 退出（含 0、缺少报告）由仍存活的 supervisor 等待完整 30 秒，再调用原 sensor_service 生成新 bootId；supervisor 自身的其他异常才由 `Restart=on-failure`、`RestartSec=30` 处理。单元资源上限触发的 OOM 不等于上述退出码 5，需现场查 systemd 证据。修复前不能反复手工重启。

退出码 3 的集合来自 A2 `AUTH_IDENTITY_FATAL_CODES`：`UNAUTHENTICATED`、`FORBIDDEN`、`MACHINE_TLS_REQUIRED`、`MACHINE_IDENTITY_REQUIRED`、`SCOPE_DENIED`、`SENSOR_INACTIVE`、`AUTHORIZATION_INACTIVE`、`CONFIG_INACTIVE`、`BOOT_ID_MISMATCH`、`CAPTURE_SCOPE_INACTIVE`、`BUILD_NOT_APPROVED`、`SPOOL_IDENTITY_MISMATCH`。Go 某些启动/失败路径不落 report，A2 无法仅凭报告识别这些拒绝；本模板不改变此行为。

supervisor 锁在 `ledger/sensor.supervisor.lock`；sensor_service 的跨 exec 采集锁在 `ledger/sensor.capture.lock`。采集及 drain 的 stdout/stderr 均追加到 `logs/sensor.stdout.log`、`logs/sensor.stderr.log`（0600）；supervisor 与 observer 的脱敏事件交给 journal，不把凭据写入单元或命令行。日志轮转由后续运维在本项目范围内管理，ledger 上限不包含 logs；磁盘低水位仍会停止采集。

**补传只在两次采集之间执行**：每次启动/重启新采集之前，逐个用旧 boot 的原 `config.json` 调用 `guardlive -drain -drain-timeout 60s`，失败保留，下次再试；采集期间每 5 分钟仅清理已确认且超过七天的旧 boot，只留下 report.json。未确认批次不删除。运行中当前 boot 的网络重试由 Go 上传器完成；约 4096 个每秒健康窗口（约 68 分钟）只是队列量级，不是断线续传保证，健康数据也不等同于可落盘的观察批次。

## 6. 停止与卸载步骤

有 NewAPI 可见影响时立即停止本项目 sensor、observer，并停止配套 recovery；报告原因，确认前不再启动。其余按第 7 节停止条件处理。

授权卸载时按顺序：

1. 停止并 disable `cyber-sensor`，再 `cyber-observer`，最后 `cyber-observer-recovery`；核对本项目子进程均已退出，不重启主机或业务服务。
2. Mac bootout **仅** `com.xyh.cyber-security.remote-tunnel`，核对其 SSH 进程退出、远端回环 18082 监听消失；移除该 plist 和 cybertunnel 中本项目专用公钥行，不删除整个 authorized_keys 或其他密钥。
3. 按 B1 变更清单移除上面三个新增单元文件，daemon-reload；不删除或修改其他单元。复测 NewAPI、监听和 sshd 基线。
4. 默认保留 config、ledger、logs、release、venv、密钥及构建证据，先归档未确认批次。完整回退如需删除两个新增用户和私有根，必须核对准确路径、备份及删除授权；只移除本次新增内容，不触碰 Mac en0 链路。
5. 如另按 B1 完整回退授权卸载运行库，先模拟卸载并检查进程映射/依赖；仅考虑本次新装的 libpcap0.8t64、libibverbs1、libnl-route-3-200，仍暂停 needrestart，不用 autoremove。libnl-3-200、libnl-genl-3-200 的既有小版本升级不回退；可能影响其他服务则停止。完成后再次复测 NewAPI 基线。

## 7. 与任务单文字的已知差异及验证边界

- A2 第 3 条写有运行中每 5 分钟补传，现有 A2 为避免旧 boot 心跳覆盖后端当前 bootId，**实际只在两次采集之间补传**，运行中五分钟周期仅清理；本卡按用户指定复用，不修改 A2/Go/后端。
- A3 描述容易被理解为所有生成文件都下发；实际 `config/machine-tls.properties` 是 Mac 后端侧文件。B5 的简略 release 清单还需加 `scripts/p7/j1_run.py` 才满足现有 toolkit import；此处已明确。
- A4/B1 预期两个单元，但 A4 明确允许按现有依赖补 recovery，因此新增第三个 `cyber-observer-recovery.service`，verify/安装/启停均须包含它。observer 的 run/recovery 参数与 Mac 原样一致；两个 observer 单元各自受 96M/10% 限额，不合并成共享配额。
- systemd 关键加固及传感器资源值均按 A4；额外的 UMask、禁止写 pyc、SIGTERM 回收时限只作用于本项目。LaunchAgent 额外固定专用身份与已核对 known_hosts，保持 A4 的转发和探活参数。
- 本卡离线校验不证明 Ubuntu 安装、apt 清单、真实容器构建、mTLS、远端捕获能力、资源保护效果或 NewAPI 无影响。`systemd-analyze verify` 留给 B1；B2/B6/C 各自完成现场验证。

离线验证入口（不执行 Docker、systemd、launchd 或 SSH）：

```sh
sh -n scripts/linux/builder/build_guardlive.sh
plutil -lint scripts/linux/com.xyh.cyber-security.remote-tunnel.plist
sh /Users/xyh/Workspace/projects/cyber-security/executor/python.sh -B -m pytest scripts/linux -q
```
