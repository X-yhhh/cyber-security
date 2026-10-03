"""三个有界基线与独立Platt校准。权重总量按parent，模型拟合不能接触校准角色。"""
from __future__ import annotations

import time
import random

import numpy as np
import torch
from scipy.optimize import minimize
from scipy.special import expit
from torch import nn


class MLP(nn.Module):
    def __init__(self, columns):
        super().__init__()
        self.layers = nn.Sequential(nn.Linear(columns, 64), nn.ReLU(), nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, 1))

    def forward(self, x):
        return self.layers(x)


def predict(algorithm, model, x):
    if algorithm == "mlp":
        model.eval()
        with torch.no_grad():
            device = next(model.parameters()).device
            return np.concatenate([torch.sigmoid(model(torch.from_numpy(x[i:i + 4096]).to(device))).cpu().numpy().reshape(-1)
                                   for i in range(0, len(x), 4096)])
    return np.asarray(model.predict_proba(x)[:, 1], dtype=np.float32)


def fit(algorithm, train, preprocessing, plan, seed, smoke=False):
    if train.role != "train":
        raise ValueError("模型只能拟合train")
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed); torch.cuda.manual_seed_all(seed)
    torch.set_num_threads(plan["budget"]["threads"])
    torch.backends.cudnn.deterministic = True; torch.backends.cudnn.benchmark = False
    x, y = preprocessing.transform(train), train.y
    weights = train.weights / train.weights.mean()
    start = time.perf_counter()
    rounds = 3 if smoke else plan["budget"]["treeRounds"]
    if algorithm == "xgboost":
        from xgboost import XGBClassifier
        model = XGBClassifier(n_estimators=rounds, max_depth=3, learning_rate=0.06, min_child_weight=5,
                              subsample=0.9, colsample_bytree=0.9, reg_lambda=2.0, tree_method="hist", device="cuda",
                              n_jobs=plan["budget"]["threads"], random_state=seed, base_score=0.5, eval_metric="logloss")
        model.fit(x, y, sample_weight=weights)
        device = "cuda"
    elif algorithm == "lightgbm":
        from lightgbm import LGBMClassifier
        model = LGBMClassifier(n_estimators=rounds, max_depth=3, num_leaves=7, learning_rate=0.06,
                               min_child_samples=20, reg_lambda=2.0, subsample=0.9, subsample_freq=1,
                               colsample_bytree=0.9, n_jobs=plan["budget"]["threads"], random_state=seed,
                               verbosity=-1, deterministic=True, force_col_wise=True)
        model.fit(x, y, sample_weight=weights)
        device = "cpu"
    elif algorithm == "mlp":
        if not torch.cuda.is_available():
            raise RuntimeError("未检测到授权CUDA运行时")
        torch.cuda.set_per_process_memory_fraction(plan["budget"]["gpuMemoryFraction"])
        model = MLP(x.shape[1]).to("cuda")
        optimizer = torch.optim.AdamW(model.parameters(), lr=0.002, weight_decay=0.001)
        xt = torch.from_numpy(x).to("cuda"); yt = torch.from_numpy(y.astype(np.float32)).to("cuda")[:, None]
        wt = torch.from_numpy(weights.astype(np.float32)).to("cuda")[:, None]
        generator = torch.Generator().manual_seed(seed)
        for epoch in range(2 if smoke else plan["budget"]["mlpEpochs"]):
            model.train()
            for ids in torch.randperm(len(x), generator=generator).split(256):
                ids = ids.to("cuda")
                optimizer.zero_grad(set_to_none=True)
                loss = (nn.functional.binary_cross_entropy_with_logits(model(xt[ids]), yt[ids], reduction="none") * wt[ids]).mean()
                loss.backward(); optimizer.step()
            if time.perf_counter() - start > plan["budget"]["maxSecondsPerFit"]:
                raise TimeoutError("MLP达到单次预算，保留失败而不静默早停为成功")
        torch.cuda.synchronize()
        device = "cuda"
    else:
        raise ValueError("未登记模型")
    elapsed = time.perf_counter() - start
    if elapsed > plan["budget"]["maxSecondsPerFit"]:
        raise TimeoutError("模型拟合超出登记预算")
    return model, {"device": device, "seed": seed, "fitSeconds": elapsed, "trainingRows": len(x),
                   "trainingParents": len({r["parentConnectionId"] for r in train.rows}),
                   "fitRole": "train", "calibrationAccess": False,
                   "cudaPeakAllocatedBytes": torch.cuda.max_memory_allocated() if torch.cuda.is_available() else 0}


def calibrate(raw_scores, batch):
    if batch.role != "validation_calibration":
        raise ValueError("校准只允许独立validation_calibration")
    raw = np.clip(np.asarray(raw_scores, dtype=np.float64), 1e-6, 1 - 1e-6)
    logits = np.log(raw / (1 - raw)); y = batch.y; weights = batch.weights / batch.weights.sum()

    def objective(ab):
        z = ab[0] * logits + ab[1]
        loss = np.sum(weights * (np.logaddexp(0, z) - y * z)) + 1e-6 * np.dot(ab, ab)
        error = weights * (expit(z) - y)
        gradient = np.array([np.sum(error * logits), np.sum(error)]) + 2e-6 * ab
        return float(loss), gradient

    fitted = minimize(objective, [1.0, 0.0], jac=True, method="L-BFGS-B", bounds=[(1e-4, 100.0), (-100.0, 100.0)])
    if not fitted.success:
        raise RuntimeError("Platt校准优化未收敛")
    return {"method": "platt", "fitRole": "validation_calibration", "slope": float(np.float32(fitted.x[0])),
            "intercept": float(np.float32(fitted.x[1])), "clip": [1e-6, 1 - 1e-6],
            "parentWeighted": True, "independentUnbiasedEvaluation": False}


def calibrated(scores, calibration):
    if calibration["method"] == "none":
        return np.asarray(scores, dtype=np.float32)
    p = np.clip(np.asarray(scores, dtype=np.float32), np.float32(1e-6), np.float32(1 - 1e-6))
    return expit(np.float32(calibration["slope"]) * np.log(p / (np.float32(1) - p)) +
                 np.float32(calibration["intercept"])).astype(np.float32)
