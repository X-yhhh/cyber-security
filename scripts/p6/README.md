# P6 冻结离线评价工具

该目录只做冻结评价与运行时对拍。不会训练、选择阈值、变更 P4 后端/数据库、生成可执行防火墙命令或开启自动能力。依赖见 `requirements.txt`，实际版本写入准入登记；Mac 与 Windows 的 ONNX Runtime 可不同，但必须通过同一权重和全量输入对拍。

## 入口与产物

1. `python3 -B -m unittest discover -s scripts/p6 -p 'test_*.py'`：全部使用合成数据，不打开真实 test。
2. `evaluate.py prepare`：核验候选包、类别/策略/预处理/切分/指标哈希，L1 在完整 validation 上做框架自检；登记评价代码、运行时、观察来源清单和访问日志哈希。此步骤不打开封存 test 或原始观察内容。
3. `evaluate.py run`：从受控入口读 L1 test，在同一评价中核对原始观察的时间/端口旁路，按连接首次过阈值判定，输出模型/规则/OR 并用指标、G1/G2、类别离线资格、质量覆盖/排除和框架对拍。
4. `runtime.py`：在另一平台重放本次已冻结的纯数值张量，输出全量概率与对拍报告；张量包不含标签、标识符、地址或时间。
5. `closeout.py`：直接复算保存的双端输出并绑定 L1/L3 报告，生成独立收口记录。原始登记、候选 manifest 和策略不回写。

以下是 L1 的调用形态，路径由实际冻结 run 提供，产物目录必须不存在且位于忽略的 `.cache` 或 `artifacts` 中：

```sh
python3 -B scripts/p6/evaluate.py prepare \
  --candidate .cache/p3c-20261007/candidate-v2 \
  --frozen .cache/p3-a-20261007/frozen \
  --extract .cache/p3-a-20261007/extract \
  --output .cache/p6-20261007/l1-01 \
  --layer L1 --evaluation-id p6-l1-01
python3 -B scripts/p6/evaluate.py run \
  --registration .cache/p6-20261007/l1-01/registration.json
```

若依赖安装在本次受控目录，调用时通过 `PYTHONPATH` 引用，不能修改全局 Python 或已有环境。Windows L3 使用其已冻结的 `sealed-test/dataset.jsonl`，只报告受控慢速攻击与困难良性；不宣称全新独立 holdout。L2 的可选 A7 未完成时显式记为未准备，不生成占位成绩。

## 冻结与读取边界

- P3-C 候选仍使用 rc.2 manifest，P4 当前为 rc.3。工具从固定 Git 修订 `efcbd12` 读取历史 Schema，并校验其 SHA-256；另行严格校验五类输出顺序。仓库历史必须可读，不能修改 P4 的现行契约来让旧候选通过。P7 接入时另行完成显式版本迁移。注意：工具只校验 manifest；候选 `decision-policy.json` 是 P3 研究格式，对历史 Schema 和当前 rc.3 均不合规（分别 20、21 处），P7 前须另行生成合规的契约策略，见 [P6 诊断](../../docs/p6/README.md)。
- 事件时间、服务端口和标签为评价旁路。原始观察必须逐字段等于冻结模型输入；旁路缺失、文件变动、重复 ID 或同 parent 标签/来源冲突均失败，不按文件顺序猜测时间，不重新生成测试特征。
- L1 从第一次打开（包括哈希核验）即记 `access_started`，失败也消耗一次。最多三次、不能重用 ID；第 2/3 次必须在准入前登记改动与原因，入口持久化后才开放文件。登记后代码、依赖或访问状态改变则拒绝运行。
- 原始 test 读取后恢复目录和文件权限 `000`。解析失败时 runner 排空子进程输出，让入口完成重封存；并发或崩溃残留锁拒绝继续读取，须先核对状态。Windows 只读属性不是对同账户强制隔离。
- 跨平台重放复用本次登记的数值张量，不重新读取原始 test、不重新计算阈值、不新增拟合。报告绑定同一评价 ID 和模型哈希；不能用它另做选型或阈值搜索。
- 所有类别保持 `alert_only`、`candidateOnly=true`。离线资格仍须 G3、平台能力和真实资产授权；高 L1 成绩不消除质量排除、网站视角偏差或跨数据集泛化局限。

本轮 L1 使用读取前登记的 v1 代码，原字节保存在受控 run 的 `code-v1/` 与 Windows 传输包中。Windows 合成回归随后发现零耗时导致吞吐率除零；v2 只改用高分辨率计时并将零耗时吞吐率记为 null，分类/统计/阈值与访问规则不变。修复回归后再登记 L3 的 v2 代码哈希；没有重读 L1，收口证据分别绑定两次登记。

参见 [开发路线](../../docs/开发路线.md#p6-冻结离线评估) 与 [验证与验收](../../docs/验证与验收.md)。
