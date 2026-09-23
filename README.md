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
