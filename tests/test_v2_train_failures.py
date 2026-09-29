import pandas as pd

from cyber_training.v2.train import failures


def test_failures_empty_when_all_ok():
    rows = pd.DataFrame({"model": ["DT", "RF"], "status": ["ok", "ok"], "error": ["", ""]})
    assert failures(rows) == []


def test_failures_skips_models_fixed_by_resume():
    rows = pd.DataFrame({"model": ["DT", "RF", "DT"], "status": ["failed", "failed", "ok"],
                         "error": ["boom", "oom", ""]})
    assert failures(rows) == [{"model": "RF", "error": "oom"}]
