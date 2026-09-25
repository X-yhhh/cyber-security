from cyber_training.stage6_preflight import check_model_manifest, check_stage5_status


def test_stage5_status_requires_candidate_release_boundary():
    result = check_stage5_status({
        "status": "completed",
        "stage": 5,
        "delivery_ready": True,
        "candidate_only": True,
        "production_approved": False,
        "release_ready": False,
        "new_locked_test_evaluations": 0,
        "preprocessing_refit": False,
    })
    assert result["passed"] is True


def test_model_manifest_requires_train_preprocessing_and_validation_threshold():
    manifest = {
        "candidate_only": True,
        "production_approved": False,
        "artifact": {"status": "exported", "format": "onnx", "prediction_parity": {"status": "passed"}},
        "preprocessing": {"fit_partition": "train"},
        "source_feature_order": ["x", "y"],
        "label_mapping": {"0": "Normal", "1": "Attack"},
        "threshold_policy": {"selected_on": "validation"},
        "inference_runtime": {"format": "ONNX", "provider": "CPUExecutionProvider"},
    }
    assert check_model_manifest("demo", manifest, ["x", "y"])["passed"] is True
