import pandas as pd

from cyber_training.pipeline import _cap_endpoint_split, _normalize_for_pipeline
from cyber_training.export import merge_candidate_index


def test_pipeline_normalizes_mixed_categorical_values_to_strings():
    frame = pd.DataFrame({"proto": [6, "tcp", None], "dur": [1.0, 2.0, 3.0]})
    normalized = _normalize_for_pipeline(frame, ["proto", "dur"])
    assert str(normalized["proto"].dtype) == "string"
    assert normalized["proto"].tolist()[:2] == ["6", "tcp"]
    assert pd.isna(normalized["proto"].iloc[2])


def test_endpoint_evaluation_cap_is_deterministic_and_preserves_classes():
    frame = pd.DataFrame({"Label": [0] * 90 + [1] * 10})
    split = {"train": frame.index.to_numpy(), "validation": frame.index[:20].to_numpy(), "test": frame.index[20:40].to_numpy()}
    capped, report = _cap_endpoint_split(frame, split, seed=17, max_rows=25)
    assert len(capped["train"]) == 25
    assert sorted(frame.iloc[capped["train"]]["Label"].unique()) == [0, 1]
    assert report["train"]["sampled"] is True
    assert report["validation"]["sampled"] is False


def test_candidate_index_merge_preserves_prior_models():
    merged = merge_candidate_index({"candidate_only": True, "models": {"a": {"id": 1}}}, {"b": {"id": 2}})
    assert merged["candidate_only"] is True
    assert set(merged["models"]) == {"a", "b"}
