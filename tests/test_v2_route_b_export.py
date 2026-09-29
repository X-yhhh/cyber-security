import numpy as np
import pandas as pd

from cyber_training.v2 import route_b_export as ex
from cyber_training.v2 import route_b_fixtures as fx
from cyber_training.v2.route_b_v4 import CATEGORICAL, CT_V4, NUMERIC

from test_v2_feature_compare import raw_frame


def test_contract_inputs_order_and_boundaries():
    n = 200
    raw = raw_frame(n)
    raw["dur"] = np.where(np.arange(n) % 5 == 0, 0.0, raw["dur"])
    raw["Spkts"] = np.where(np.arange(n) % 7 == 0, 1.0, raw["Spkts"])
    re = pd.DataFrame({f"{c}_v4": np.arange(n, dtype=float) + i for i, c in enumerate(CT_V4)})
    re["service_v4"] = np.where(np.arange(n) % 2, "dns", "-")
    inputs, view = ex.contract_inputs(raw, re)
    num, cat = inputs["flow_numeric"], inputs["flow_categorical"]
    assert num.shape == (n, len(NUMERIC)) and cat.shape == (n, len(CATEGORICAL))
    bad = (raw["dur"].to_numpy() <= 0) | (raw["Spkts"].to_numpy() <= 1)
    assert bad.any() and (num[bad, NUMERIC.index("sload")] == 0).all() and (view.loc[bad, "sload"] == 0).all()
    assert np.array_equal(num[:, NUMERIC.index("ct_srv_src")], re["ct_srv_src_v4"].to_numpy())
    assert np.array_equal(num[:, NUMERIC.index("sbytes")], raw["sbytes"].to_numpy(dtype=np.float64))
    assert cat[:, 1].tolist() == re["service_v4"].tolist() == view["service"].tolist()


def test_select_slice_covers_every_boundary_case():
    n = 600
    raw = pd.DataFrame({"srcip": ["a"] * n, "dstip": ["h"] * n, "Stime": np.arange(n), "Ltime": np.arange(n),
                        "Label": 0, "proto": ["tcp"] * n, "Spkts": 3, "Dpkts": 2, "dur": 1.0, "tcprtt": 0.1})
    raw.loc[50, ["srcip", "dstip"]] = ["h", "b"]  # 出站
    raw.loc[200, ["proto", "Spkts", "Dpkts", "dur"]] = ["udp", 1, 0, 0.0]  # 单包、dur=0、非 TCP、无反向包
    raw.loc[210, "tcprtt"] = 0.0  # 握手不完整
    raw.loc[250, "Label"] = 1
    rows, host = fx.select_slice(raw, np.zeros(n, bool), np.arange(n), np.full(n, 60.0))
    assert host == "h" and len(rows) == fx.SLICE
    assert {50, 200, 210, 250} <= set(rows.tolist())
    assert raw.loc[rows[fx.WINDOW - 1], "dstip"] == "h"


def test_doc_addresses_unique_and_not_network_or_broadcast():
    addrs = [fx.doc_address(i) for i in range(fx.MAX_ADDRESSES)]
    assert len(set(addrs)) == len(addrs)
    assert not any(a.endswith(".0") or a.endswith(".255") for a in addrs)
