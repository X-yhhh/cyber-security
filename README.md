# 基于流量智能分析的内网威胁检测与分级防御平台

本项目是面向授权主机/网络与隔离靶场的持续流量检测和分级防御毕设系统。平台通过安装在现有 Mac 与 Windows 设备上的软件传感器采集其本机可见的流量元数据，结合项目自行训练的流量分类模型、确定性规则和资产策略，完成告警、事件研判及受控主机防火墙响应。不要求新增专用采集硬件；传感器可能需要系统抓包权限或操作系统驱动。也不把两台主机的传感器描述成可见整个交换式内网。系统不攻击第三方、不扫描未授权目标、不生成真实攻击流量。

## 项目目标

- 持续监控两台现有设备各自可见的网络流量，并可扩展到明确授权且部署了软件传感器的主机。
- 使用公开数据/预制回放训练和验证自行实现的机器学习分类器；检测推理不调用外部大模型 API。
- 将流量告警与资产、安全日志及可用终端事件关联，提供有证据、可解释的风险研判。
- 对已登记主机执行限时、可撤销的本机防火墙阻断；DoS 类行为先告警和分级，只有经过验证且操作系统适配器支持的动作才可自动执行。
- 监测数据分布漂移和模型效果反馈；权重在生产检测期间保持冻结，经人工确认标注、Windows 离线再训练、候选评估和审批后才发布新版本。
- 记录传感器、模型、策略、审批、执行、回滚和审计证据，满足运行和毕设评估需要。

## 当前模型边界

训练计划以 UNSW-NB15 流记录为起点，目标是正常/攻击二分类及基于数据标签可验证的攻击类别分类。输入是流级特征，不是原始数据包、终端进程或完整攻击链。实际传感器特征与数据集字段的一致性、域差异和误报表现必须实测后才能启用模型拦截。DoS 类识别仅代表在该数据及评估条件下的分类结果，不等于抵御任意规模 DDoS。模型不能单独决定正常流量放行或自动隔离资产。

首期直接覆盖安装传感器的 Mac 与 Windows 主机。若要单点观察整个内网，必须利用现有交换机/路由器支持的流量镜像或流记录导出配置；不支持或无授权配置权限时，不宣称全网覆盖。无法满足模型输入契约的数据应拒绝推理或转规则/人工研判。在线运行只做冻结模型推理、漂移观测和人工反馈收集，不对生产权重进行自训练或自动替换。攻击阶段预测和大模型训练不属于本项目范围。

## 系统组成

- Vue 3 Web 控制台：资产与数据源、告警与事件、模型、回放、策略、审批、执行记录和审计。
- Mac/Windows 软件传感器：采集本机授权范围内的流量元数据，形成有界流记录/时间窗特征；不要求新增专用硬件。
- Spring Boot 模块化单体：传感器注册与心跳、数据接入、在线特征契约校验、模型路由、检测研判、响应策略、审批和审计。
- MySQL 8：业务对象、事件证据、模型登记、响应和审计的持久化存储。
- Redis：缓存、短期任务状态与幂等辅助；不作为审计或业务事实的唯一存储。
- RabbitMQ：承载异步接入、事件关联和处置任务；任务执行状态仍以数据库为准。
- 模型推理适配器：管理员可在经验证的本机权重推理与远端推理服务间选择；模型制品独立于 Git 分发。
- Windows 离线训练环境：人工/计划触发的候选模型再训练和评估；不由生产告警直接在线更新权重。
- 主机防火墙适配器：仅在资产登记、授权有效、策略命中且动作能力经验证时执行限时阻断；无法安全回滚时转人工处理。

## 仓库与训练职责

| 区域 | 职责 |
| --- | --- |
| `main` | 本地业务系统、架构/接口/数据设计、模型契约和集成 |
| `training/windows-cuda` | Windows CUDA 数据准备、训练、实验、评估和模型导出 |

训练集、权重、缓存、日志和大型生成结果不提交到 Git。训练端交付的模型必须包含 `model_manifest.json`、特征顺序、预处理定义、标签映射、阈值策略、评估与运行时信息、数据/切分指纹及 SHA-256。仅审查通过的制品可登记为可用版本。

## 技术基线

- 后端：Java 25、Spring Boot 模块化单体、MyBatis。
- 前端：Vue 3 稳定版。当前核验 npm 官方 registry 的 `latest` 为 3.5.43，Vue 4.x 尚无可用发行；待正式发布且生态兼容后再评估升级。
- 数据：MySQL 8、Redis、RabbitMQ。
- 初期不引入 Spring Cloud；当服务需要独立扩缩容或独立部署时再评估拆分。

## 数据库构建

MySQL 8 初始化脚本位于 [`database/init.sql`](database/init.sql)，默认创建 `cyber_security` 数据库及首期业务表。脚本仅初始化一个本机测试登录账号：用户名 `admin`、密码 `admin`；密码以 BCrypt 哈希保存。该账号作为本机 `platform_admin` 登录测试用户保留；版本化迁移负责授予内置角色和权限，且不得删除账号或覆盖其密码哈希。该凭据不得作为非本机环境的默认账号。其他内置角色按最小权限区分，详见[功能模块设计](docs/功能模块设计.md)。

在确认目标为本机开发 MySQL 后，可交互输入数据库管理员密码执行：

```sh
mysql --protocol=TCP -h127.0.0.1 -P3306 -uroot -p < database/init.sql
```

所有时间列按 UTC 语义保存；应用连接应设置 UTC 时区。后端上线后以 Flyway 版本化迁移管理 schema。现存库须先完整对照基线、备份并登记版本，不得把 `IF NOT EXISTS` 当成 schema 一致性的证明；脚本不会删除或清空已有对象，也不会重置已存在的 `admin` 密码。

本机已安装 Temurin JDK 25.0.2，位于 `/Users/xyh/Workspace/development/runtimes/java/temurin-25.0.2`；当前 shell 的 `JAVA_HOME` 仍指向 JDK 17，实施时需使用项目级 Java 25 配置并验证实际构建运行时。

### 本机初始化管理员口令

`database/init.sql` 中的 `admin/admin` 仅用于新建的本机开发库，密码哈希由 `BootstrapAdminHashTest` 校验。启动过程不会覆盖既存 `admin` 账号；非 `local` profile 仅在检测到仍使用初始化口令时输出不含哈希的警告。若本机既有库需要改回测试口令，请先确认目标确为本机开发库，再由管理员在受控终端执行：

```sql
UPDATE sys_user SET password_hash = '<使用项目 BCryptPasswordEncoder(12) 离线生成的哈希>'
WHERE username = 'admin';
```

不要把明文口令、哈希或数据库密码写入迁移、日志、提交信息或非本机环境。

后端工程位于 [`backend/`](backend/)，使用 Spring Boot、Spring Security 服务端会话、MyBatis 和 Flyway。数据库连接通过 `DB_URL`、`DB_USERNAME`、`DB_PASSWORD` 配置；应用默认绑定 `127.0.0.1:18080`。当前迁移资源为 V1-V12：V1 保留初始化业务表，V2-V5 增加 IAM/会话、登录限速和 connector 接入结构，V6 增加模型发布审查与响应审批台账字段，V7 增加候选制品校验和本机部署激活权限，V8 增加 sensor 主体绑定、批次配置/序号/契约追溯和 sensor 机器权限，V9 增加审计、接入记录和发件箱查询索引，V10 增加异步消费者幂等/失败台账，V11 增加映射/配置的契约文件哈希绑定，V12 增加推理结果快照列、状态不变量与推理台账/dry-run 权限。迁移不自动 baseline 既有非空 schema；本机现存库只有在完成结构核对与备份并获准后才可迁移。

业务持久化已统一收口到 MyBatis Mapper/XML；生产源码不直接使用 `JdbcTemplate`、`JdbcClient` 或 `java.sql`，Spring Session 的 JDBC 表仍由框架按标准方式管理。`MyBatisMigrationGuardTest` 会阻止业务代码回退到直接 JDBC。

当前已实现认证/CSRF、用户创建与列表、内置角色/权限模板只读、角色范围分配、资产登记/范围内更新/授权申请与独立审批、数据源范围查询/更新及映射版本登记、全关联范围审计，以及 connector 和 sensor 的无状态机器凭据、幂等批次接入。机器凭据只返回一次且数据库仅保存 SHA-256 验证值；接入需显式绑定数据源—资产配对，浏览器 session 不可冒充机器身份。connector 提交的是已规范化 JSON；sensor 批次还会复核配置、序号、批准映射和在线契约声明的 raw feature 字段（v4 为 17 个数值/2 个类别），并将不合格记录留痕为 rejected。

传感器登记、一次性设备凭据、心跳、批准配置读取、健康窗口和流批次路由已实现；Java 侧已有有界双向流状态核心、事件时间 100 流窗口、raw Feature Builder、只读 UNSW CSV 回放适配器和按模板切分的 NetFlow v9/IPFIX 解码器。特征契约由 `classpath:feature-contract/*.json` 启动加载：在线契约为 `unsw-nb15-flow-v4`（17 数值 + 2 类别，golden fixtures 与 UNSW 1 万条回放已逐字段对拍），v3.1 仅用于离线回放、在线批次一律 fail-closed；v4 Feature Builder 在窗口未满、迟到/重复、排除流或逐流值非法时 fail-closed，传感器配置与来源映射按 V11 登记契约文件哈希。M3 本机推理已接入 M2 消费链路（路线 B 阶段 4）：消费事务内经契约一致性门禁、按 manifest 字段顺序构造输入、在激活 ONNX 会话读锁内推理，逐条写 `inference_request`（模型版本、契约哈希、分数、标签、阈值与阈值策略版本快照），与消费台账同一事务提交；无激活模型、契约不一致、字段不合规、单批超时（默认 2000 ms）和会话错误都写显式状态与稳定错误码，不回退、不给默认分数；同一记录只推理一次。`GET /api/v1/inference-requests` 按数据源范围只读查询；`POST /api/v1/inference/dry-run` 仅对回放数据源执行、不落库。`cyber.inference.local.enabled=false` 可关闭本机推理提交端口。outbox relay 默认关闭；显式启用并配置 RabbitMQ 后，会将 outbox 事件以持久化 JSON 消息发布到 durable topic exchange，等待 broker confirm 并拒绝不可路由消息，失败按指数退避、达到上限后进入 dead letter，并记录 publisher Timer histogram。M2 已增加 `q.ingest.batch.received` 手动 ack 消费者、`consumed_message` 幂等台账、5 次 TTL 重试和 `q.ingest.dead` 死信拓扑；推理提交端口不可用时，消费者显式 fail-closed，不产生伪造推理结果。独立 MySQL 测试 schema 的迁移、认证、授权、资产、接入、事件、查询、模型和响应台账集成测试已通过；RabbitMQ 发布器和 M2 消费者集成测试（重复投递去重、重试上限转死信、未 ack 消息重投）已连接专用测试 vhost 并通过。本机应用 relay/consumer 仍未启用。实际抓包、macOS libpcap/Windows Npcap 传感器进程、collector 注册/UDP 服务和影子运行仍未验证。告警与事件范围查询/研判、模型候选登记、ONNX 制品校验、Java 离线回放（门限 1e-5）、独立发布审批和显式本机激活台账已实现；端到端集成测试以真实交付包 `unsw-binary-2026.10.0` 跑通登记→校验→他人批准→激活→推理，概率与训练端误差 ≤ 1e-5。本机开发库尚未迁移 V11/V12，也尚未激活模型；推理结果尚未生成告警（M4）；任意记录的同步推理 API、训练任务执行和远端推理仍未开放。响应策略没有管理 API；没有匹配且已批准的策略或有效资产授权时申请被拒绝。审批不触发执行，执行端点固定返回 `503 ACTION_EXECUTION_UNAVAILABLE`，不调用适配器且不写 `action_execution`。`database/init.sql` 中初始化的本机测试账号 `admin/admin` 已由测试验证；既存 `admin` 密码哈希必须保留且不由启动过程重置，非 `local` profile 只会在识别出初始化口令时写入不含哈希的警告。控制台日志使用 ECS JSON，request ID 通过 MDC 关联且异常日志不写入堆栈或连接详情。

启用 RabbitMQ outbox relay 与 M2 消费者需在应用运行环境提供 `OUTBOX_RELAY_ENABLED=true`、`RABBITMQ_HOST`、`RABBITMQ_PORT`、`RABBITMQ_VHOST`、`RABBITMQ_USERNAME` 和 `RABBITMQ_PASSWORD`；消费者默认跟随 relay，可用 `INGEST_CONSUMER_ENABLED=false` 单独关闭。应用会声明 durable topic exchange `cyber-security.ingest.events`、队列 `q.ingest.batch.received`、DLX `cyber-security.dlx`、死信队列 `q.ingest.dead` 和 1..5 次 TTL 重试队列。exchange 默认为 `cyber-security.ingest.events`，可通过 `RABBITMQ_INGEST_EXCHANGE` 覆盖。密码应由运行环境的受控密钥存储注入，不写入仓库。本机推理提交端口关闭或推理暂不可用（容量耗尽、激活版本切换）时，消息会按上限重试后进入死信；队列消费完成只表示推理结论已落库，不表示已生成告警。

本机验收使用 Temurin JDK 25.0.2、Maven 3.9.13 和指定 Maven 本地仓库。本机 macOS 登录 shell 从 macOS 钥匙串加载 `DB_URL`、`DB_USERNAME`、`DB_PASSWORD`、`DB_TEST_BASE_URL`、`DB_TEST_USERNAME`、`DB_TEST_PASSWORD`、`LOGIN_THROTTLE_HMAC_KEY`、`RABBITMQ_IT_ENABLED`、`RABBITMQ_IT_HOST`、`RABBITMQ_IT_PORT`、`RABBITMQ_IT_VHOST`、`RABBITMQ_IT_USERNAME`、`RABBITMQ_IT_PASSWORD`、`RABBITMQ_HOST`、`RABBITMQ_PORT`、`RABBITMQ_VHOST`、`RABBITMQ_USERNAME`、`RABBITMQ_PASSWORD` 和 `RABBITMQ_INGEST_EXCHANGE`；只保存变量名和加载方式，不把秘密写入仓库。其他环境应从各自受控密钥存储注入运行/测试所需变量。Java 测试应使用项目指定 JDK 与 Maven，集成测试只连接独立测试 schema。

## 文档

- [项目详细设计](docs/项目详细设计.md)
- [功能模块设计](docs/功能模块设计.md)
- [数据库设计](docs/数据库设计.md)
- [接口设计](docs/接口设计.md)
- [接口实现核对矩阵](docs/接口实现核对矩阵.md)
- [模型训练与交付计划](docs/training-plan.md)

首期覆盖边界是部署软件传感器的主机。主机级自动阻断不等同于网络边界防火墙或全网 DDoS 清洗；上游大流量攻击需要网络运营商/云清洗等外部基础设施协同，本项目仅预留受控联动边界，不承诺独立抵御任意规模攻击。主机限速不是所有操作系统防火墙都具备的通用能力，只有适配器实测支持后才能启用；否则提供告警及受控阻断。

前端 UI/视觉规范暂不纳入本轮设计。后端身份授权与数据库实施约束以本 README、《项目详细设计》和《数据库设计》为准；过程性设计记录保存在 `.superpowers/sdd/`，不作为外部引用入口。以上文档是设计基线；真实传感器、同步推理 API、告警生成、训练任务和处置执行器仍未实现，受控模型制品校验、离线回放与测试 schema 中的本机推理不等同于生产上线。

## 安全边界

1. 仅处理公开基准数据、预制回放数据，或有书面/可审计授权的网络与资产遥测。
2. 自有靶场必须与外网隔离；回放是重放数据，不是生成或发起攻击流量。
3. 自动处置只能作用于登记且处于授权范围内的资产和明确允许的动作；目标、动作或权限不确定时拒绝执行并转人工审批。
4. 模型不保存或持有网络设备、终端或云平台凭据。执行凭据由独立适配器的受限身份管理。
5. 禁止扫描、利用、恶意软件、凭据攻击、外部流量注入及任何针对未授权第三方的操作。
