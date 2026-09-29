import numpy as np

from cyber_training.v2 import feature_diagnose as fd


def test_shuffle_within_keeps_group_multiset():
    values = np.arange(20, dtype=float).reshape(10, 2)
    groups = np.array([0, 0, 0, 1, 1, 1, 1, 2, 2, 2])
    out = fd.shuffle_within(values, groups, 1)
    for g in np.unique(groups):
        m = groups == g
        assert sorted(map(tuple, out[m])) == sorted(map(tuple, values[m]))
    # 多列一起置换：每行两列仍来自同一原始行
    assert np.all(out[:, 1] - out[:, 0] == 1)


def test_host_mean_uses_train_rows_only():
    values = np.array([[1.0], [3.0], [100.0], [10.0], [7.0]])
    groups = np.array([0, 0, 0, 1, 2])
    out = fd.host_mean(values, groups, np.array([0, 1, 3]))
    assert out[:, 0].tolist() == [2.0, 2.0, 2.0, 10.0, (1 + 3 + 10) / 3]
