# 路线 B 阶段 7：v4 训练切分特征基线（unsw-binary-2026.10.1）

- 方法：`train_partition_decile_bins`（schema `baseline-v1`）；分箱：bin = count of edges strictly less than value; edges ascending and unique; bins = len(edges) + 1
- 来源：`split-v4-20260929-1450` 训练分区，种子 20261001，1,378,958 行；范围 viewpoints=['responder']、address_families=['ipv4']；代码提交 `7ea88363cb1e20f47948b1e055dbef126392e777`
- 取值口径：ONNX 输入口径（进入 preprocessing 之前）：float64 原始值；sload/dload 在 dur=0 或该方向包数≤1 时为 0；ct_* 为训练端单主机重算值；service 为端口口径（dsport 缺失时为 -，与训练一致）
- 缺失/异常：数值非有限值 0、类别空值 0；dsport 缺失 6 行（service 记 -）；负值计数 0。训练分区无缺失或非有限值，未丢弃任何行。

## 切分复现核对（绑定项，任一不符即不产出基线）

| 检查项 | 结果 |
|---|---|
| register manifest sha256 (evidence, CRLF) | 一致 |
| split audit sha256 (evidence, CRLF) | 一致 |
| freeze file sha256 (CRLF) | 一致 |
| freeze split record | 一致 |
| archived split fingerprint | 一致 |
| archived register_manifest_sha256 | 一致 |
| raw file NUSW-NB15_features.csv sha256/bytes | 一致 |
| raw file UNSW-NB15_1.csv sha256/bytes | 一致 |
| raw file UNSW-NB15_2.csv sha256/bytes | 一致 |
| raw file UNSW-NB15_3.csv sha256/bytes | 一致 |
| raw file UNSW-NB15_4.csv sha256/bytes | 一致 |
| d1_raw conversions | 一致 |
| d1_raw attack_cat counts | 一致 |
| d1_raw rows/columns | 一致 |
| d1_raw data_fingerprint (in memory) | 一致 |
| d1_raw data_fingerprint (parquet reload) | 一致 |
| recomputed cache rows/columns | 一致 |
| split fingerprint | 一致 |
| selected seed | 一致 |
| split audit d1_raw content | 一致 |
| train rows | 一致 |
| train rows usable (window ready, not excluded) | 一致 |
| train endpoints all valid IPv4 | 一致 |
| manifest scope | 一致 |
| manifest inputs | 一致 |
| ONNX inputs (float32) equal training frame values, per field | 一致 |
| baseline structure (backend parser rules) | 一致 |

参考项（不绑定）：d1_raw.parquet sha256；recomputed cache sha256；split audit float max relative diff；split-d1-raw.npz sha256；d2 split；train missing / abnormal values；float32-cast values vs float64 bin counts (rows moved)。

## 数值字段

| 字段 | edges 数 | 箱数 | 最小 edge | 最大 edge | 最大箱占比 |
|---|---:|---:|---:|---:|---:|
| `dur` | 9 | 10 | 0.001064 | 1.14611 | 0.1007 |
| `sbytes` | 9 | 10 | 146 | 8928 | 0.1515 |
| `dbytes` | 9 | 10 | 178 | 55486 | 0.1658 |
| `sload` | 9 | 10 | 11518.5 | 1.9567e+06 | 0.1000 |
| `dload` | 9 | 10 | 20268.1 | 1.15715e+07 | 0.1001 |
| `tcprtt` | 8 | 9 | 0 | 0.00087 | 0.2500 |
| `ackdat` | 8 | 9 | 0 | 0.000173 | 0.2502 |
| `synack` | 8 | 9 | 0 | 0.000654 | 0.2500 |
| `smean` | 9 | 10 | 56 | 187 | 0.1331 |
| `dmean` | 9 | 10 | 76 | 819 | 0.1669 |
| `spkts` | 9 | 10 | 2 | 78 | 0.1596 |
| `dpkts` | 8 | 9 | 2 | 80 | 0.1982 |
| `ct_srv_src` | 9 | 10 | 1 | 13 | 0.1495 |
| `ct_srv_dst` | 9 | 10 | 7 | 69 | 0.1217 |
| `ct_dst_ltm` | 2 | 3 | 99 | 100 | 0.8942 |
| `ct_src_ltm` | 9 | 10 | 6 | 19 | 0.1534 |
| `ct_src_dport_ltm` | 4 | 5 | 1 | 5 | 0.6031 |

## 类别字段

| 字段 | 单独成键的取值数 | `__other__` 占比 | 取值 |
|---|---:|---:|---|
| `proto` | 3 | 0.003026 | tcp、udp、ospf |
| `service` | 6 | 0.001107 | -、dns、http、smtp、ssh、ftp |

## 交付自校验

- 交付目录：`unsw-binary-2026.10.1`（源 `unsw-binary-2026.10.0`）
- 新 manifest SHA-256：`8c278343551f45efe92df0ab2ee4151ec7a35be37a42dd63c36d72c81e4526fb`；源 manifest：`d2a54814d276d58d88a26ae0e749d65c0b1f68c444e67fa8747b6d153a8196bf`
- model.onnx SHA-256：`c87b883d0ac32b0a827441eb5d97164acaa46e67653fb79cd369b9c794949358`；checksums.json 条目 21
- manifest 差异键：`/model_version`、`/version`、`/created_at`、`/provenance/derived_from`、`/feature_baseline_stats`
- 检查项：checksums_cover_all_files 通过；checksums_match 通过；model_onnx_sha256_expected 通过；artifact_sha256_and_size 通过；manifest_files_hashes 通过；fixtures_checksums 通过；same_file_set 通过；copied_files_byte_identical 通过；manifest_diff_only_allowed 通过；manifest_values 通过；manifest_json_format_crlf 通过；baseline_structure 通过；baseline_split_fingerprint 通过；baseline_no_ipv4_literal 通过；permissions_match_source 通过
