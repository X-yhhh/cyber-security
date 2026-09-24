import pytest
import torch
from scipy.sparse import csr_matrix

from cyber_training.config import ExperimentConfig
from cyber_training.models import fit_mlp, predict_mlp


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA GPU unavailable")
def test_mlp_runs_training_step_on_cuda():
    x = torch.randn(64, 8).cpu().numpy()
    y = (x[:, 0] > 0).astype("float32")
    model, metadata = fit_mlp(x, y, x, y, ExperimentConfig(batch_size=32, mlp_epochs=2, mlp_patience=1), 7, torch.device("cuda:0"))
    assert next(model.parameters()).device.type == "cuda"
    assert metadata["device"] == "cuda:0"
    assert predict_mlp(model, x).shape == (64,)


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA GPU unavailable")
def test_mlp_predicts_from_sparse_features_in_batches():
    x = csr_matrix([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]], dtype="float32")
    model = torch.nn.Sequential(torch.nn.Linear(2, 1)).cuda()
    from cyber_training.models import predict_mlp

    assert predict_mlp(model, x, batch_size=2).shape == (3,)
