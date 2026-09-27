import json

import numpy as np
import pandas as pd
import pytest
from sklearn.preprocessing import StandardScaler

from cyber_training.v2 import register
from cyber_training.v2.__main__ import main
from cyber_training.v2.guard import HoldoutLockedError, LeakageError, SplitIndex, fit_on_train
from cyber_training.v2.runtime import RunContext


def make_split(tmp_path=None):
    return SplitIndex(np.arange(0, 70), np.arange(70, 85), np.arange(85, 100),
                      audit_log=None if tmp_path is None else tmp_path / "audit.jsonl")


def test_holdout_locked_by_default():
    split = make_split()
    assert split.holdout_size == 15
    with pytest.raises(HoldoutLockedError):
        _ = split.holdout


def test_unlock_requires_reason_and_audit_log(tmp_path):
    with pytest.raises(HoldoutLockedError):
        make_split().unlock_holdout("final eval")
    split = make_split(tmp_path)
    with pytest.raises(ValueError):
        split.unlock_holdout("  ")
    split.unlock_holdout("final eval attempt 1")
    assert split.holdout.size == 15
    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert record["event"] == "holdout_unlocked" and record["split_fingerprint"] == split.fingerprint


def test_overlapping_partitions_rejected():
    with pytest.raises(LeakageError):
        SplitIndex(np.arange(0, 10), np.arange(9, 15), np.arange(15, 20))


def test_split_roundtrip_keeps_lock_and_fingerprint(tmp_path):
    split = make_split()
    split.save(tmp_path / "split.npz")
    loaded = SplitIndex.load(tmp_path / "split.npz")
    assert loaded.fingerprint == split.fingerprint
    with pytest.raises(HoldoutLockedError):
        _ = loaded.holdout


def test_fit_on_train_rejects_non_train_rows():
    frame = pd.DataFrame({"x": np.arange(100, dtype=float)})
    split = make_split()
    scaler = fit_on_train(StandardScaler(), frame, split.train[::2], split)
    assert scaler.mean_[0] == pytest.approx(frame["x"].iloc[split.train[::2]].mean())
    with pytest.raises(LeakageError):
        fit_on_train(StandardScaler(), frame, np.array([1, 2, 90]), split)


def test_run_context_writes_config_and_checksums(tmp_path):
    ctx = RunContext("unit", 7, {"a": 1}, runs_root=tmp_path)
    ctx.path("x.txt").write_text("hello", encoding="utf-8")
    sums = ctx.finish()
    config = json.loads(ctx.path("run-config.json").read_text(encoding="utf-8"))
    assert config["seed"] == 7 and config["params"] == {"a": 1} and "packages" in config
    assert set(sums) == {"run-config.json", "x.txt"}
    with pytest.raises(FileExistsError):
        RunContext("unit", 7, runs_root=tmp_path)


def test_parse_port_handles_hex_dash_and_garbage():
    parsed, stats = register.parse_port(pd.Series(["80", "0x000b", "-", None, "abc", " 443 "]))
    assert parsed.tolist()[:2] == [80, 11] and parsed.iloc[5] == 443
    assert parsed.isna().tolist() == [False, False, True, True, True, False]
    assert stats == {"hex_converted": 1, "dash_or_blank": 2, "unparseable": 1}


def test_attack_cat_normalization_and_conflicts():
    label = pd.Series([0, 1, 1, 0])
    cats, info = register.normalize_attack_cat(pd.Series([None, " Backdoors", "Exploits ", ""]), label)
    assert cats.tolist() == ["Normal", "Backdoor", "Exploits", "Normal"]
    assert info == {"normal_filled_from_blank": 2}
    with pytest.raises(register.RegistrationError):
        register.normalize_attack_cat(pd.Series(["Normal"]), pd.Series([1]))
    with pytest.raises(register.RegistrationError):
        register.normalize_attack_cat(pd.Series(["Unknown"]), pd.Series([1]))


def test_feature_dictionary_strips_whitespace(tmp_path):
    names = [f"f{i}" for i in range(47)] + ["ct_src_ ltm", "Label"]
    pd.DataFrame({"No.": range(1, 50), "Name": names}).to_csv(tmp_path / "d.csv", index=False, encoding="cp1252")
    parsed = register.d1_feature_names(tmp_path / "d.csv")
    assert "ct_src_ltm" in parsed and len(parsed) == 49


def test_verify_hashes_fails_closed(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"data")
    with pytest.raises(register.RegistrationError):
        register.verify_hashes(tmp_path, {"a.bin": "0" * 64})
    with pytest.raises(register.RegistrationError):
        register.verify_hashes(tmp_path, {"missing.bin": "0" * 64})


def test_audited_expectations_match_plan():
    assert register.EXPECTED["d1_raw_label_counts"] == {0: 2_218_764, 1: 321_283}
    assert sum(register.EXPECTED["d1_raw_label_counts"].values()) == register.EXPECTED["d1_raw_rows"]
    assert register.D1_SUBSET_TRAIN == "UNSW_NB15_testing-set.csv"


def test_d1_raw_blank_numeric_cells_become_missing(tmp_path, monkeypatch):
    names = ["srcip", "sport", "dstip", "dsport", "proto", "state", "service", "dur", "attack_cat", "Label"]
    monkeypatch.setattr(register, "d1_feature_names", lambda _: names)
    monkeypatch.setattr(register, "D1_RAW_FILES", ("a.csv",))
    monkeypatch.setitem(register.EXPECTED, "d1_raw_rows", 3)
    monkeypatch.setitem(register.EXPECTED, "d1_raw_label_counts", {0: 2, 1: 1})
    rows = ["1.1.1.1,80,2.2.2.2,53,UDP,CON,dns,0.5,,0",
            "1.1.1.1,0x10,2.2.2.2,-,tcp,FIN,-, ,,0",
            "1.1.1.1,1,2.2.2.2,2,tcp,FIN,http,1.0,Exploits,1"]
    (tmp_path / "a.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    data, conv = register.load_d1_raw(tmp_path)
    assert data["dur"].isna().tolist() == [False, True, False]
    assert conv["numeric_blank_to_missing"] == {"dur": 1}
    assert data["proto"].tolist() == ["udp", "tcp", "tcp"]
    assert data["sport"].tolist()[:2] == [80, 16] and pd.isna(data["dsport"].iloc[1])
    assert data["attack_cat"].tolist() == ["Normal", "Normal", "Exploits"]


def test_unimplemented_step_fails_explicitly():
    assert main(["final-eval"]) == 2


def test_train_requires_stage():
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["train"])
    assert exc.value.code == 2
