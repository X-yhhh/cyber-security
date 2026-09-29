import numpy as np
import pandas as pd

from cyber_training.v2 import feature_ablation as ab
from cyber_training.v2 import route_b_v4 as v4
from cyber_training.v2.export import DERIVED
from cyber_training.v2.features import CATEGORICAL

from test_v2_feature_ablation import V3


def test_contract_fields_match_frozen_view():
    view = [c for c, _ in ab.define_groups(V3)["F5"]]
    numeric = [c for c in view if c not in CATEGORICAL]
    direct = [c for c in numeric if c not in DERIVED]
    deps = [d for c in numeric if c in DERIVED for d in DERIVED[c][0]]
    assert set(direct) | set(deps) == set(v4.NUMERIC)
    assert len(v4.NUMERIC) == 17 and len(set(v4.NUMERIC)) == 17
    assert [c for c in view if c in CATEGORICAL] == list(v4.CATEGORICAL)
    assert not set(v4.REMOVED) & set(view)


def test_apply_boundaries_zeroes_load():
    frame = pd.DataFrame({"dur": [0.0, 1.0, 1.0, 2.0], "spkts": [1, 1, 3, 4], "dpkts": [0, 2, 1, 5],
                          "sload": np.float32([5, 6, 7, 8]), "dload": np.float32([1, 2, 3, 4])})
    out = v4.apply_boundaries(frame)
    assert out["sload"].tolist() == [0, 0, 7, 8]
    assert out["dload"].tolist() == [0, 2, 0, 4]
