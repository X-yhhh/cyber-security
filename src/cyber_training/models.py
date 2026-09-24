from __future__ import annotations

import copy
import random
import time

import numpy as np
import torch
from scipy import sparse
from torch import nn
from torch.utils.data import DataLoader

from .config import ExperimentConfig


class BinaryMLP(nn.Module):
    def __init__(self, n_features: int):
        super().__init__()
        self.layers = nn.Sequential(
            nn.Linear(n_features, 128), nn.ReLU(), nn.Dropout(0.20),
            nn.Linear(128, 64), nn.ReLU(), nn.Dropout(0.10),
            nn.Linear(64, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.layers(x).squeeze(-1)


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def fit_mlp(x_train, y_train, x_valid, y_valid, cfg: ExperimentConfig, seed: int, device: torch.device):
    seed_everything(seed)
    model = BinaryMLP(x_train.shape[1]).to(device)
    train_labels = torch.from_numpy(np.asarray(y_train, dtype=np.float32))
    generator = torch.Generator().manual_seed(seed)
    loader = DataLoader(torch.arange(len(train_labels)), batch_size=cfg.batch_size, shuffle=True, generator=generator)
    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg.learning_rate, weight_decay=cfg.weight_decay)
    criterion = nn.BCEWithLogitsLoss()
    best_state = copy.deepcopy(model.state_dict())
    best_loss = float("inf")
    best_epoch = 0
    patience = 0
    started = time.perf_counter()
    for epoch in range(cfg.mlp_epochs):
        model.train()
        for batch_ids in loader:
            xb = _dense_batch(x_train, batch_ids.numpy())
            yb = train_labels[batch_ids]
            xb, yb = xb.to(device, non_blocking=True), yb.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.no_grad():
            total_loss = 0.0
            total_rows = 0
            for start in range(0, len(y_valid), cfg.batch_size):
                stop = min(start + cfg.batch_size, len(y_valid))
                xb = _dense_batch(x_valid, slice(start, stop)).to(device)
                yb = torch.from_numpy(np.asarray(y_valid[start:stop], dtype=np.float32)).to(device)
                total_loss += criterion(model(xb), yb).item() * (stop - start)
                total_rows += stop - start
            valid_loss = total_loss / total_rows
        if valid_loss < best_loss - 1e-5:
            best_loss = valid_loss
            best_state = copy.deepcopy(model.state_dict())
            best_epoch = epoch + 1
            patience = 0
        else:
            patience += 1
            if patience >= cfg.mlp_patience:
                break
    model.load_state_dict(best_state)
    elapsed = time.perf_counter() - started
    return model, {"epochs": epoch + 1, "best_epoch": best_epoch, "best_validation_loss": best_loss, "training_seconds": elapsed, "device": str(device)}


def predict_mlp(model: BinaryMLP, features, batch_size: int = 8192) -> np.ndarray:
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    model.eval()
    device = next(model.parameters()).device
    results = []
    with torch.no_grad():
        for start in range(0, features.shape[0], batch_size):
            tensor = _dense_batch(features, slice(start, start + batch_size)).to(device)
            results.append(torch.sigmoid(model(tensor)).detach().cpu().numpy())
    return np.concatenate(results).reshape(-1) if results else np.empty(0, dtype=np.float32)


def _dense_batch(features, rows) -> torch.Tensor:
    selected = features[rows]
    if sparse.issparse(selected):
        selected = selected.toarray()
    return torch.from_numpy(np.asarray(selected, dtype=np.float32))


def model_specs(seed: int, cfg: ExperimentConfig | None = None):
    """Return ten concrete model instances for the first comparison table.

    The registry exposes distinct model families so the comparison count is not
    inflated by silently repeating one algorithm with different parameters.
    """
    from sklearn.ensemble import AdaBoostClassifier, ExtraTreesClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression, PassiveAggressiveClassifier, SGDClassifier
    from sklearn.naive_bayes import GaussianNB
    from sklearn.svm import LinearSVC
    from sklearn.tree import DecisionTreeClassifier

    cfg = cfg or ExperimentConfig()
    return {
        "svm_linear": LinearSVC(C=1.0, class_weight="balanced", max_iter=3000, random_state=seed),
        "gaussian_nb": GaussianNB(),
        "logistic_regression_c01": LogisticRegression(C=0.1, max_iter=1000, class_weight="balanced", random_state=seed, n_jobs=1),
        "passive_aggressive": PassiveAggressiveClassifier(C=0.1, max_iter=1000, class_weight="balanced", random_state=seed, n_jobs=cfg.tree_n_jobs),
        "ada_boost": AdaBoostClassifier(n_estimators=50, learning_rate=0.5, random_state=seed),
        "decision_tree": DecisionTreeClassifier(max_depth=cfg.tree_max_depth, min_samples_leaf=2, class_weight="balanced", random_state=seed),
        "random_forest": RandomForestClassifier(n_estimators=cfg.tree_n_estimators, max_depth=cfg.tree_max_depth, min_samples_leaf=2, class_weight="balanced_subsample", random_state=seed, n_jobs=cfg.tree_n_jobs),
        "extra_trees": ExtraTreesClassifier(n_estimators=cfg.tree_n_estimators, max_depth=cfg.tree_max_depth, min_samples_leaf=2, class_weight="balanced", random_state=seed, n_jobs=cfg.tree_n_jobs),
        "sgd_log_loss": SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=30, tol=1e-3, class_weight="balanced", random_state=seed, n_jobs=cfg.tree_n_jobs),
    }


def requires_dense(model_name: str) -> bool:
    return model_name == "gaussian_nb"


def _model_input(model_name: str, features):
    if requires_dense(model_name) and sparse.issparse(features):
        return features.toarray()
    return features


def fit_sklearn_model(model_name: str, model, features, labels):
    model.fit(_model_input(model_name, features), labels)
    return model


def predict_scores(model_name: str, model, features) -> np.ndarray:
    """Return a continuous attack score for probability or margin models."""
    values = _model_input(model_name, features)
    if hasattr(model, "predict_proba"):
        return np.asarray(model.predict_proba(values)[:, 1], dtype=float)
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(values), dtype=float).reshape(-1)
    return np.asarray(model.predict(values), dtype=float).reshape(-1)
