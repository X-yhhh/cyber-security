# P1 定向补证的标签与活动策略

日期：2026-10-03。此文件补充 [v1 标签策略](label-policy.md)，不改写历史审计或原始标签；属于 P1 可行性研究，未生成训练集。

## 任务与来源

本轮候选任务限定为 **授权主机单个 HTTP 服务的入站连接/请求滥用**。候选家族为 `connection_abuse`；执行范围为 IPv4 对端、TCP、本机服务端口及入站方向。公开的 DoS/DDoS 名称保留为来源标签，不能据此声称能够保护已饱和的上游链路或提供通用 DDoS 防御。

来源仍只有 IoT-23 和 CICIDS2017。Torii 20-1/21-1 补充的是 IoT-23 同源完整捕获；CIC 的 Kaggle 文件只是原始 PCAP 的传输镜像，只有与官方校验文件相符后才能认定字节一致。镜像自行标记 MIT 不能替代 CIC 官方使用条件。原始数据和第三方标签/代码只保留于忽略目录，不随本项目再分发。

CIC 官方将数据面向研究者公开并要求引用：Sharafaldin、Lashkari、Ghorbani，*Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*，ICISSP 2018。修正数据引用 Liu、Engelen、Lynar、Essam、Joosen，*Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*，IEEE CNS 2022，254–262。

- [CIC 官方说明及入口](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CNS2022 修正说明](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html)
- [修正数据与 Attempted 语义](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html)
- [修正标注逻辑](https://github.com/GintsEngelen/CNS2022_Code/blob/main/Labelling/CICIDS2017_labelling_fixed_CICFlowMeter.ipynb)

## 证据层级与时间

修正表中的非 Attempted 攻击标签、BENIGN 标签保留 `publisher_documented` 层级，不用未匹配标签自行制造正常样本。作者明确说明 Attempted 表示预定攻击但该流未展现恶意行为。本轮单独保留为边界/歧义，不并入攻击正例，也不建立 Attempted 模型类别。是否转为困难良性须逐活动审查原因，不能机械重标。

使用修正表的 UTC 微秒时间。官网日程用于活动说明，不根据网页显示的本地时刻猜测时区。CNS 网页个别可读日期与其 UNIX 数值不一致，须以实际标签表、版本化标注逻辑和原始包三方核对；不能只从攻击日程给全部 prefix 赋标签。

周三包含分开启动的 Slowloris、Slowhttptest、Hulk、GoldenEye 活动，周五另有 DDoS 活动。共享实验环境、攻击端和目标是偏差来源；独立启动不等于独立真实部署。全部已探索活动登记为开发暴露，未分配 final_test，不能在调参后把它们重新称为盲测。

## 确定性抽查与前缀起点

每种 HTTP 攻击标签按连接摘要选 10 条；良性按稳定摘要选 10 条，并补充载荷量最高的 5 条和包数最多的 5 条；额外选择同一攻击目标服务的 10 条良性和 10 条 Attempted 边界，重复连接只保留一次。抽样依据在查看 PCAP 关联结果之前固定。不能删除失败样本提高通过率。

逐条核对 UTC 微秒五元组窗口（±1 μs）、双向包数、双向 TCP 载荷量、相邻标签窗口和可见 SYN epoch。`matched` 只代表该抽查连接的关联，不代表全量正确。无 SYN 的连接中段、多个 SYN 序号、重叠标签、offload 和丢包分别报告，不能静默凑齐特征。

首个实际入站载荷、首个 HTTP 请求报文仅作为起点候选。只有关联通过、活动来源和该连接的攻击归属经审查，并排除 Attempted/人工检查/启动收尾等伪影，才可批准具体场景的 prefix 标注。任何 prefix 必须晚于被审查的起点；此前为 unknown。看到 GET、本身处于攻击时段、或者最终流标签为攻击，都不足以单独批准 prefix。探针默认 `prefixSupervisionApproved=false`，裁决须另留证据。

在完整 PCAP 到达前，按发布者明确描述追加 Slowloris 起点核查：保留原 10 条随机连接，再按稳定摘要选 10 条不重复、表格 SYN 计数大于零的记录。表格 SYN 只用于选择候选，仍须原始报文证明 epoch。审查仅在标签旁路读取最多 32 KiB 初始请求，要求 SYN 起始、序号连续、GET 头尚未结束、后续独立 `X-a` 头片段；普通 GET、重传、缺口、截断、Attempted 或重叠标签不能批准起点。所有失败保留，载荷与该模式不成为模型特征。这是原采样之外的预先登记补证，不能用成功样本替换原失败。

参考值只使用截止点前的头部信息，不把最终时长、标签、原始地址、连接 ID 或起点旁路作为模型输入。乱序 IAT 显式缺失。此工具没有实现 P2 水位、完整 parentConnection 或 1/5/30 秒上下文，不接入活动 v4 运行时。

## 困难良性与能力边界

修正表中攻击目标 HTTP 服务只有周三 12 条、周五 23 条 BENIGN 连接；其他主机的大流量正常下载不能掩盖这个不足。补充的 Windows 任务使用独立隔离程序、固定内存夹具和授权 Mac 对端，执行正常片段下载、四路并发及主动中断后的 Range 恢复。标签依据是受控任务清单及内容哈希，不是“没有检测到攻击”。真实超时仍属于合法任务的失败结果，保留为困难边界，不改标恶意。

这些短时任务不能代表全部桌面更新软件、生产 HTTP 并发和实网误阻断水平。P1 只裁定数据和动作是否值得继续实现；模型相对仅规则的收益、误伤率、时效及置信区间仍由后续独立验收决定。

## 2026-10-04 起点探针修正

完整原件揭示两份 `.pcap` 均为单接口 PCAPNG；已增加容器块、接口、时间精度和完整哈希校验，不转换或覆盖原件。第一次起点审查对既定 20 条样本未发现候选，检查发现探针误用了 CSE-CIC-IDS2018 的数字头值模式。CICIDS2017 发布者描述及本轮载荷形状诊断一致：续传是字面 `X-a: b`，已抽查连接共出现 10 个这样的片段，而非数字值。修正仅作用于来源匹配规则，不改变样本、原标签或连接窗口。

旧审查及其代码、形状诊断、新 `p1-slow-header-onset-review-v2` 报告均保留。新规则只接受连续序号的新 `X-a: b\r\n` 片段，重传不增加证据；未结束 GET、关联、起始 SYN、单 epoch、无时间回退、无卸载嫌疑须同时满足。发布者标签仍为 `publisher_documented`，不伪称人工复核层级。P1 的结构候选不等于全量 prefix 标签批准；更不能将该来源特有载荷特征加入模型输入，或用于宣称模型相对规则的收益。
