# Cyber Security Detection Demo

This repository contains the graduation-project demonstration system for offline network intrusion detection. It is a defensive, local-only project: it does not perform scanning, exploitation, attack traffic generation, or external traffic injection.

## Repository Responsibilities

The repository has two deliberately separated workspaces:

| Workspace | Branch | Responsibility |
| --- | --- | --- |
| macOS local project | `main` | Frontend, backend, database, inference API, business workflows, model input/output contract, and local demonstration integration |
| Windows CUDA training project | `training/windows-cuda` | Dataset preparation, offline training, experiment tracking, model iteration, training environment notes, and export manifests |

The Windows directory is dedicated to this repository and must not be confused with any other training project under `E:\Workspace\ai\experiments`. Existing projects remain untouched.

## Data and Artifacts

The UNSW-NB15 dataset is stored only on the Windows training host under `data/raw/unsw-nb15/`. Raw data, caches, generated reports, logs, checkpoints, and model weights are excluded from Git. The dataset is used for academic demonstration and must be cited according to its original publication and applicable license terms.

The existing root `dataset-metadata.json` describes the earlier, undersized `dhoogla/unswnb15` candidate; it is retained for provenance, not used as the selected dataset manifest. The selected `mrwellsdavid/unsw-nb15` manifest lives with the Windows data and its non-sensitive audit summary is maintained on the training branch.

The training parser records both the historical source-audit duplicate count and its exact parsed-row count. The file SHA-256 values match the audited source, but the historical audit used a different duplicate scope (266 versus 480,632 exact parsed duplicates); the run manifest keeps both values and uses the explicit parsed-row count for deduplication. The predefined split overlap remains an audit field and is never mixed into raw training.

Models are delivered to the local application by separate file transfer, never by committing large binaries to Git. Each delivery must include a `model_manifest.json` containing the model version, dataset fingerprint, feature list, preprocessing description, metrics, runtime requirements, and SHA-256 checksums.

## Branch Rules

- `main` is the local application and contract branch.
- `training/windows-cuda` is the long-lived Windows training branch.
- Training implementation and large experiment output stay on `training/windows-cuda`.
- Only reviewed interface contracts and selected result summaries may be merged into `main`.
- Do not force-push, rewrite shared history, or mix unrelated training repositories.

## Safety Boundary

All experiments use downloaded datasets, offline files, or synthetic demonstration inputs. The system produces detection and protection-oriented results only. Do not use this repository for network reconnaissance, exploitation, malware, credential attacks, or real-world attack execution.

## Plan

The complete dataset, feature, model, evaluation, reporting, and acceptance plan is documented in [`docs/training-plan.md`](docs/training-plan.md).

## First-run resource budget

On September 24, 2026 the Windows host measured an Intel i9-12900H (14 cores/20 threads), 16.8 GB physical RAM, RTX 3070 Ti Laptop GPU (8 GiB VRAM), and about 153.6 GiB free on E:. The project environment is Python 3.12.10 with PyTorch 2.7.1+cu126/CUDA 12.6. V0 uses 42 raw flow features and encodes to 214 columns on the audited data; the binary target is Label (0=normal, 1=attack). IPs, ports, timestamps, row IDs, and attack_cat are excluded from model inputs.

The primary split is a fixed-seed, deduplicated, stratified 70/15/15 split; unordered endpoint-pair isolation is a separate stress diagnostic. The first pass produces bounded EDA artifacts, compares standard/robust/unscaled preprocessing on train/validation only, and trains ten concrete model instances from nine traditional model families plus a CUDA MLP: Linear SVM, Gaussian NB, Logistic Regression, Passive-Aggressive, AdaBoost, Decision Tree, Random Forest, Extra Trees, SGD log-loss, and a PyTorch MLP that must train on CUDA. Models run sequentially. CPU work can use all 14 physical cores (20 hardware threads); forest models use 50 trees with maximum depth 24; endpoint stress evaluation is capped at 100,000 rows per partition. The MLP uses batches of 8,192, at most 20 epochs, and validation-loss early stopping with patience 4. Thresholds and top-three model selection use validation only. Each first-pass candidate gets one locked-test evaluation; extra seeds use validation only. The workflow writes `eda/`, `preprocessing-comparison.*`, `feature-view-manifest.json`, `model-comparison.*`, machine-readable metrics, and a `candidates/` directory containing ONNX artifacts, train-fitted preprocessing manifests, checksums, and candidate-only `model_manifest.json` files.

Measured preparation took about 54 seconds; a full-data 20-tree, depth-24 Random Forest took about 126 seconds and about 4 GiB process memory; one MLP epoch took about 10 seconds with low VRAM use. Before launch, close nonessential user applications gracefully and use all 14 physical CPU cores/20 hardware threads for one training process; Windows and essential display, driver, security, and remote-access services remain running. Sequential model fitting and cleanup avoid retaining multiple forests at once. PCA, feature-selection variants, XGBoost, LightGBM, CatBoost, and subset multiclass are deferred follow-up experiments. The comparison table and heatmap follow the supplied reference layout, but all values are generated from the locked test and never copied from the reference image.

## Windows Commands

```text
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m cyber_training.cli verify-data
.venv\Scripts\python.exe -m cyber_training.cli train --epochs 20
```

Runs are written under `runs/` and remain candidate-only artifacts. The MLP refuses CPU fallback; tree baselines are recorded as CPU runs.
