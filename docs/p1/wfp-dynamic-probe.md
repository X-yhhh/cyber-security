# Windows 动态会话恢复探针

日期：2026-10-04。完成最小 WFP 探针、六项非重启实测和一次明确授权的真实重启。重启后无残留，但缺少截止时间内清零观察，自动启动观察任务退出1，**严格跨重启时效仍未验证，P1 整体 blocked**。不授予生产自动资格。[机器报告](wfp-dynamic-probe.json)由原始账本复算；历史 [PersistentStore 超时失败](continuation-report.md)继续保留。

## 实现与边界

- [原生绑定](../../scripts/p1/wfp_native.py)按微软 SDK 声明 x64 WFP 结构，使用 `FWPM_SESSION_FLAG_DYNAMIC`。同一事务在 `INBOUND_TRANSPORT_V4` 和 `ALE_AUTH_RECV_ACCEPT_V4` 添加两个精确过滤器，限定一个授权 IPv4/TCP 入站对端与本机高端口。无 persistent/boot-time 标志，不改变默认策略。
- [独立恢复进程](../../scripts/p1/wfp_probe.py)持有会话，将固定30秒期限换算为单调时间，正常到期主动删除并核验。双向心跳失联阈值0.5秒；恢复循环挂起时独立 supervisor 通过已持有的子进程对象终止所有者，supervisor 丢失时恢复循环关闭会话。到期后0.25秒触发兜底终止，验收仍要求到期后 **1秒内实际核验不存在**。
- 启动先核验隔离及旧持久阻断，再枚举项目子层/命名空间；残留存在时不发布 ready。每次产生新 executorId；旧 boot、旧 executor、越界、迟到、过期或超过授权的命令均拒绝。旧账本不重放，重试不续租。
- 每场景只接受一个不可覆盖命令；状态原子发布，账本追加刷新。目录 ACL 只允许操作者、Administrators、SYSTEM。这只是本地有界探针，未实现生产命令签名、策略及审批。
- canary 的外联阻断、入站 peer/端口限制与允许规则独立于动态会话，保护 SSH/Tailscale 管理路径。本轮重启窗口保留隔离跨启动，仅保留独立定时清理，避免旧的15秒启动清理提前撤销隔离。

依据：[Microsoft WFP Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)。动态对象随会话结束删除，不等于系统提供原生30秒TTL或已证明关机期间时效。

## 六项非重启实测

每项均验证阻断前后目标/控制连接，阻断中既有和新目标连接失败、既有和新控制连接正常，以及隔离第三端口不可访问、管理服务正常。以下均为外部观察者实际清零时间相对原定到期；负数代表提前清零。

| 场景 | 结果 | 外部核验相对到期 |
|---|---|---|
| 正常30秒到期 | 通过 | +0.204615秒 |
| 主动关闭会话 | 通过 | -19.286691秒 |
| 强制结束所有者 | 通过 | -18.639127秒 |
| 恢复循环挂起 | 通过，健康监视器发现失联并终止所有者 | -18.857740秒 |
| 检测进程退出 | 通过，使用专用无害替身，非生产集成验收 | +0.181126秒 |
| 控制连接断开 | 通过，关闭专用SSH通道，保留管理恢复通道 | +0.204926秒 |

保留早期失败：启动器继承SSH句柄超时、非原子命令读取竞争，均未安装阻断；请求到期晚于隔离授权期限则拒绝。分别修复独立WMI启动、同卷原子发布，并另建有界授权窗口，未延长旧租约。

## 一次真实重启

用户明确允许后，本轮只执行了一次重启。时间均为 UTC：阻断签发18:28:22.129996，原定到期18:28:52.129996，重启请求18:28:34.902079。请求前再次枚举确认两个过滤器仍存在，距原定到期约17.228秒。新OS boot为18:28:54.500000，SSH及Tailscale恢复。

重启后直接枚举、手动观察均确认过滤器和子层不存在。新执行器先核对清零，再实际提交原boot的旧命令，得到 `STALE_BOOT`，未安装过滤器。首次拒绝缺少外部最终账本；补充 Windows 管道 `poll()` 关闭异常保护后复试，得到完整拒绝和零残留记录。六项非重启场景保留各自实际执行版本的哈希，不冒充全部由最终修订执行。

仍未通过的边界：

- 关机观察器只留下“两个过滤器仍存在”，没有捕获截止时间内清零。事后观察不能倒推删除时刻，也不能据此判定规则一定超时残留。
- SYSTEM观察任务无额外启动延迟，18:29:05启动后退出1，未留下初始枚举。原任务未重定向标准错误，TaskScheduler Operational日志未启用，原因尚不能确定。未修改系统日志或防护策略；归档原定义和结果后，为本任务增加诊断输出、按需运行成功，不替代自动启动验收。
- 原隔离窗口临近到期的流量复查被拒绝。随后另建同范围6分钟窗口，仅启动普通回显，目标与控制端口正常、第三端口仍被隔离；没有新增阻断或再次重启。

后续须完善启动诊断及关机连续观察，在另行明确的必要窗口验收。本次不追加重启，不放宽30秒TTL和1秒核验门槛。

## 清理与其他范围

最终实查：试验规则0、计划任务0、探针进程0，WFP过滤器和子层均不存在。BFE、MpsSvc、sshd、Tailscale运行；三个防火墙profile启用、默认入站Block/出站Allow，SAC仍为1。四轮私有工具目录与账本保留作为证据，无运行测试资源，无需追加重启。

Mac按用户要求暂缓实测，不创建隔离环境，未修改PF、接口或虚拟机，`macOSAutoSupported=false`。

周五官方MD5入口返回 HTTP 403 `Registration required`。未取得官方校验文件，继续 `checksumSource=mirror`、`officialChecksumVerified=false`；周三已获官方校验原件可支撑后续研究，不重下载大型PCAP。

Windows探针14项单元测试通过，本机P1合计34项通过。训练仓库分支、HEAD和原有未提交文件重新核验一致；未实施P2、训练、数据库、前端或项目运行时变更，未提交/推送。

## 复算和入口

```sh
python3 -m unittest discover -s scripts/p1 -p 'test_*.py'
python3 -m py_compile scripts/p1/*.py
python3 scripts/p1/summarize_wfp.py --check
python3 scripts/p1/summarize_platform.py --check
python3 scripts/p1/summarize_data.py --check
python3 scripts/p1/adjudicate_stage.py --check
git diff --check
```

[非重启驱动](../../scripts/p1/run_wfp_probe.py)仅在授权manifest、独立隔离和恢复预检通过后运行；`--help`无副作用。[重启驱动](../../scripts/p1/run_wfp_reboot.py)的 `--execute-one-reboot` 必须对应用户明确验收窗口，不能因blocked自行重跑。[只读观察器](../../scripts/p1/wfp_reboot_observer.py)不恢复旧租约；[重启裁决](../../scripts/p1/summarize_wfp_reboot.py)区分自动启动失败、事后手动清零与严格时效。原始端点、目录和日志只存忽略的私有证据目录。
