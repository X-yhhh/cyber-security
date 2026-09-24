from __future__ import annotations

import numpy as np
import pandas as pd


ENGINEERED_FEATURES = [
    "log1p_sbytes",
    "log1p_dbytes",
    "log1p_spkts",
    "log1p_dpkts",
    "bytes_per_packet",
    "packet_balance",
    "byte_balance",
    "load_ratio",
    "ttl_delta",
    "latency_sum",
    "jitter_sum",
]


def _numeric(frame: pd.DataFrame, name: str) -> pd.Series:
    return pd.to_numeric(frame[name], errors="coerce")


def _safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    result = numerator.div(denominator.where(denominator != 0))
    return result.replace([np.inf, -np.inf], np.nan)


def engineer_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Add bounded, source-derived traffic features without using labels or IDs."""
    engineered = frame.copy()
    sbytes, dbytes = _numeric(frame, "sbytes"), _numeric(frame, "dbytes")
    spkts, dpkts = _numeric(frame, "spkts"), _numeric(frame, "dpkts")
    sload, dload = _numeric(frame, "sload"), _numeric(frame, "dload")
    sttl, dttl = _numeric(frame, "sttl"), _numeric(frame, "dttl")
    tcprtt, synack, ackdat = _numeric(frame, "tcprtt"), _numeric(frame, "synack"), _numeric(frame, "ackdat")
    sjit, djit = _numeric(frame, "sjit"), _numeric(frame, "djit")
    engineered["log1p_sbytes"] = np.log1p(sbytes.clip(lower=0))
    engineered["log1p_dbytes"] = np.log1p(dbytes.clip(lower=0))
    engineered["log1p_spkts"] = np.log1p(spkts.clip(lower=0))
    engineered["log1p_dpkts"] = np.log1p(dpkts.clip(lower=0))
    engineered["bytes_per_packet"] = _safe_divide(sbytes + dbytes, spkts + dpkts)
    engineered["packet_balance"] = _safe_divide(spkts - dpkts, spkts + dpkts)
    engineered["byte_balance"] = _safe_divide(sbytes - dbytes, sbytes + dbytes)
    engineered["load_ratio"] = _safe_divide(sload, dload)
    engineered["ttl_delta"] = sttl - dttl
    engineered["latency_sum"] = tcprtt + synack + ackdat
    engineered["jitter_sum"] = sjit + djit
    return engineered


def feature_view_manifest(raw_features: pd.DataFrame, engineered_features: pd.DataFrame) -> dict:
    return {
        "views": {
            "v0_raw": {"feature_count": int(raw_features.shape[1]), "features": list(raw_features.columns)},
            "v2_engineered": {"feature_count": int(engineered_features.shape[1]), "features": list(engineered_features.columns)},
        },
        "derived_features": ENGINEERED_FEATURES,
        "label_or_identifier_inputs": False,
    }
