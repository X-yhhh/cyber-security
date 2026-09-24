from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from .data import TARGET, write_json


def summarize_dataset(frame: pd.DataFrame, sample_rows: int = 100_000, seed: int = 20260923) -> dict:
    """Create a bounded, machine-readable EDA summary without fitting anything."""
    sample = frame.sample(n=min(sample_rows, len(frame)), random_state=seed) if len(frame) else frame
    missing = frame.isna().sum().sort_values(ascending=False)
    numeric = frame.select_dtypes(include="number")
    categorical = frame.select_dtypes(exclude="number")
    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "sample_rows": int(len(sample)),
        "target": TARGET,
        "label_counts": {str(k): int(v) for k, v in frame[TARGET].value_counts(dropna=False).sort_index().items()},
        "missing_cells": int(frame.isna().sum().sum()),
        "missing_by_column": {str(k): int(v) for k, v in missing[missing > 0].items()},
        "numeric_summary": {
            str(column): {
                "min": float(numeric[column].min()),
                "median": float(numeric[column].median()),
                "max": float(numeric[column].max()),
                "mean": float(numeric[column].mean()),
            }
            for column in numeric.columns
        },
        "categorical_cardinality": {str(column): int(frame[column].nunique(dropna=False)) for column in categorical.columns},
        "attack_category_counts": (
            {str(k): int(v) for k, v in frame["attack_cat"].astype("string").fillna("<missing>").value_counts().items()}
            if "attack_cat" in frame
            else {}
        ),
    }


def write_eda_artifacts(frame: pd.DataFrame, output: Path, seed: int = 20260923) -> dict:
    """Write EDA JSON/CSV/PNG artifacts; plots use a deterministic bounded sample."""
    output.mkdir(parents=True, exist_ok=True)
    summary = summarize_dataset(frame, seed=seed)
    write_json(output / "eda-summary.json", summary)
    missing = pd.DataFrame(
        [{"feature": key, "missing": value, "missing_rate": value / max(1, len(frame))} for key, value in summary["missing_by_column"].items()]
    ).sort_values("missing", ascending=False)
    missing.to_csv(output / "eda-missingness.csv", index=False)

    sample = frame.sample(n=min(100_000, len(frame)), random_state=seed) if len(frame) else frame
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    frame[TARGET].value_counts().sort_index().plot.bar(ax=axes[0], color=["#64748b", "#dc2626"], title="Label distribution")
    axes[0].set_xlabel("Label")
    axes[0].set_ylabel("Rows")
    if not missing.empty:
        missing.head(12).sort_values("missing").plot.barh(x="feature", y="missing", ax=axes[1], legend=False, color="#0f766e", title="Top missing fields")
        axes[1].set_xlabel("Missing cells")
    else:
        axes[1].text(0.5, 0.5, "No missing values", ha="center", va="center")
        axes[1].set_axis_off()
    fig.tight_layout()
    fig.savefig(output / "eda-overview.png", dpi=160)
    plt.close(fig)
    return summary
