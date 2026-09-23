# Selected UNSW-NB15 Dataset Audit

Source: `https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15` (retrieved 2026-09-23). Windows data root: `E:\Workspace\ai\experiments\cyber-security-training\data\raw\unsw-nb15\`. The ignored `manifest.json` in that directory records individual file sizes, SHA-256 digests, and quality statistics. The archive is stored one level above the extracted files.

## Verified facts

- Kaggle archive: 156,257,637 bytes; SHA-256 `d923de23e2378ff9e750f37d38fa60828eda33d8a1bd481a752f64930bc4cec6`.
- Four raw CSV files: 586,377,596 bytes, 2,540,047 parsed rows, 49 fields. This is three rows above the source description; keep and report all rows unless a later documented audit explains the discrepancy.
- Raw labels: 2,218,764 normal and 321,283 attack. Full-row hash audit found 266 repeats across the four files; audit is based on row hashes, not a bytewise duplicate proof.
- Raw missing cells: 4,996,788. Normal `attack_cat` entries are empty; `ct_flw_http_mthd` and `is_ftp_login` also have missing entries in files 2-4. Attack categories exist for attack rows, but whitespace and `Backdoor`/`Backdoors` require normalization.
- The 45-column files are misleadingly named in this copy: `UNSW_NB15_testing-set.csv` has 175,341 rows and is the predefined training partition; `UNSW_NB15_training-set.csv` has 82,332 rows and is the predefined holdout partition. First records and label counts were compared with the earlier Parquet copy. Keep filenames unchanged and map their roles explicitly.
- The predefined partitions contain 67,601 and 26,387 within-file duplicates when `id` is excluded, and 4,247 matching rows across partitions without `id`. Report both untouched-source and leakage-controlled evaluations; never tune on the holdout partition.
- Kaggle lists the license as `unknown`. The dataset description states academic research use is granted with attribution; original authors' terms must be checked before redistribution or commercial use.

No training, hyperparameter search, attack traffic generation, or deployment has been performed at this stage.
