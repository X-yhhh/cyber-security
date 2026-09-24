import numpy as np
import pandas as pd

from cyber_training.features import ENGINEERED_FEATURES, engineer_features
from cyber_training.models import model_specs
from cyber_training.preprocessing import STRATEGIES, build_preprocessor, normalize_for_pipeline


def _v0_fixture(rows: int = 6) -> pd.DataFrame:
    base = {
        "dur": [1.0, 2.0, 0.0, 3.0, 4.0, 5.0],
        "spkts": [2, 4, 2, 8, 10, 12],
        "dpkts": [1, 2, 1, 4, 5, 6],
        "sbytes": [10, 20, 10, 40, 50, 60],
        "dbytes": [5, 10, 5, 20, 25, 30],
        "sload": [1.0, 2.0, 1.0, 4.0, 5.0, 6.0],
        "dload": [0.5, 1.0, 0.5, 2.0, 2.5, 3.0],
        "sttl": [1, 2, 3, 4, 5, 6],
        "dttl": [1, 1, 2, 2, 3, 3],
        "tcprtt": [0.1] * 6,
        "synack": [0.1] * 6,
        "ackdat": [0.1] * 6,
        "sjit": [0.1] * 6,
        "djit": [0.1] * 6,
        "proto": ["tcp", "udp", "tcp", "udp", "tcp", "udp"],
        "service": ["http", "dns", "http", "dns", "http", "dns"],
        "state": ["CON", "FIN", "CON", "FIN", "CON", "FIN"],
        "ct_ftp_cmd": [0, 1, 0, 1, 0, 1],
    }
    return pd.DataFrame(base).iloc[:rows]


def test_feature_engineering_has_expected_derived_columns_without_labels():
    result = engineer_features(_v0_fixture())
    assert set(ENGINEERED_FEATURES).issubset(result.columns)
    assert len(result.columns) == len(_v0_fixture().columns) + len(ENGINEERED_FEATURES)
    assert not bool(np.isnan(result.loc[2, "bytes_per_packet"]))


def test_preprocessing_strategies_are_explicit_and_train_fittable():
    frame = engineer_features(_v0_fixture())
    features = list(frame.columns)
    assert [item.key for item in STRATEGIES] == ["standard", "robust", "unscaled"]
    for item in STRATEGIES:
        transformer = build_preprocessor(frame, features, item.key)
        matrix = transformer.fit_transform(normalize_for_pipeline(frame, features))
        assert matrix.shape[0] == len(frame)
        assert matrix.shape[1] >= len(features)


def test_first_pass_has_more_than_five_model_instances_plus_cuda_mlp():
    assert len(model_specs(7)) == 9
    assert len(model_specs(7)) + 1 == 10
    assert "random_forest" in model_specs(7)
    assert "svm_linear" in model_specs(7)
    assert "passive_aggressive" in model_specs(7)
