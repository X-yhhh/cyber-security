from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler, StandardScaler

from .metrics import choose_threshold


@dataclass(frozen=True)
class PreprocessingStrategy:
    key: str
    numeric_scaler: str
    description: str


STRATEGIES = (
    PreprocessingStrategy("standard", "standard", "median imputation plus StandardScaler and one-hot encoding"),
    PreprocessingStrategy("robust", "robust", "median imputation plus RobustScaler and one-hot encoding"),
    PreprocessingStrategy("unscaled", "none", "median imputation plus one-hot encoding without numeric scaling"),
)


def categorical_columns(frame: pd.DataFrame, feature_columns: list[str]) -> list[str]:
    return [
        column for column in feature_columns
        if frame[column].dtype == "object" or str(frame[column].dtype).startswith(("string", "category"))
    ]


def normalize_for_pipeline(frame: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    normalized = frame.loc[:, feature_columns].copy()
    for column in categorical_columns(frame, feature_columns):
        normalized[column] = normalized[column].astype("string")
    return normalized


def build_preprocessor(frame: pd.DataFrame, feature_columns: list[str], strategy: str = "standard") -> ColumnTransformer:
    selected = next((item for item in STRATEGIES if item.key == strategy), None)
    if selected is None:
        raise ValueError(f"unknown preprocessing strategy: {strategy}")
    categorical = categorical_columns(frame, feature_columns)
    numeric = [column for column in feature_columns if column not in categorical]
    if selected.numeric_scaler == "standard":
        scaler = StandardScaler()
    elif selected.numeric_scaler == "robust":
        scaler = RobustScaler(with_centering=False)
    else:
        scaler = "passthrough"
    numeric_steps = [("impute", SimpleImputer(strategy="median", add_indicator=True))]
    if scaler != "passthrough":
        numeric_steps.append(("scale", scaler))
    numeric_pipeline = Pipeline(numeric_steps)
    category_pipeline = Pipeline([
        ("impute", SimpleImputer(strategy="most_frequent")),
        ("encode", OneHotEncoder(handle_unknown="ignore", sparse_output=True, dtype=np.float32)),
    ])
    return ColumnTransformer(
        [("numeric", numeric_pipeline, numeric), ("categorical", category_pipeline, categorical)],
        remainder="drop",
        verbose_feature_names_out=True,
    )


def compare_preprocessing(
    train_frame: pd.DataFrame,
    valid_frame: pd.DataFrame,
    y_train: np.ndarray,
    y_valid: np.ndarray,
    feature_columns: list[str],
    seed: int,
    max_train_rows: int = 100_000,
    max_valid_rows: int = 25_000,
) -> tuple[list[dict], str]:
    """Compare preprocessing only on train/validation; test data is never touched."""
    train_ids = np.arange(len(train_frame))[:max_train_rows]
    valid_ids = np.arange(len(valid_frame))[:max_valid_rows]
    rows = []
    for strategy in STRATEGIES:
        preprocessor = build_preprocessor(train_frame, feature_columns, strategy.key)
        x_train = preprocessor.fit_transform(normalize_for_pipeline(train_frame.iloc[train_ids], feature_columns))
        x_valid = preprocessor.transform(normalize_for_pipeline(valid_frame.iloc[valid_ids], feature_columns))
        probe = LogisticRegression(C=1.0, max_iter=300, class_weight="balanced", random_state=seed, n_jobs=1)
        probe.fit(x_train, y_train[train_ids])
        scores = probe.predict_proba(x_valid)[:, 1]
        threshold, policy = choose_threshold(y_valid[valid_ids], scores)
        rows.append({
            "strategy": strategy.key,
            "description": strategy.description,
            "train_rows": int(len(train_ids)),
            "validation_rows": int(len(valid_ids)),
            "encoded_features": int(x_train.shape[1]),
            "validation_f1": float(f1_score(y_valid[valid_ids], scores >= threshold, zero_division=0)),
            "threshold": float(threshold),
            "threshold_policy": policy,
        })
    selected = max(rows, key=lambda row: row["validation_f1"])["strategy"]
    return rows, selected
