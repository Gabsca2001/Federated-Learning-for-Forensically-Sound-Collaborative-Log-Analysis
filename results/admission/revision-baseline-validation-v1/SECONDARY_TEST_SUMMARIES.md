# Secondary conditional test summaries

Previously evaluated IID/non-IID shadow-FedAvg histories; three seeds per cell. These are conditional outputs, not independent active defense trajectories. Same test fold as previous studies. Attacker identities vary across seeds: the final column averages each model's largest component ASR, without aligning different clients as if they were the same component. Raw records preserve component identities.

## iid: clean

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Mean maximum component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | Individual envelope | 97.49 ± 0.05 | 91.97 ± 0.42 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | Individual envelope | 96.80 ± 0.09 | 91.55 ± 0.74 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | FedAvg | 97.49 ± 0.05 | 91.97 ± 0.42 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | FedAvg | 96.80 ± 0.09 | 91.55 ± 0.74 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | FLAME adaptation | 96.93 ± 0.40 | 88.92 ± 1.30 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | FLAME adaptation | 97.03 ± 0.20 | 92.53 ± 1.69 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | Fixed-reference composite | 97.63 ± 0.04 | 92.11 ± 0.43 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | Fixed-reference composite | 96.88 ± 0.11 | 91.50 ± 0.83 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | WeiDetect adaptation | 97.54 ± 0.03 | 92.60 ± 0.57 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | WeiDetect adaptation | 96.76 ± 0.13 | 91.49 ± 0.97 | 0.00 ± 0.00 | 0.00 ± 0.00 |

## iid: distributed

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Mean maximum component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | Individual envelope | 97.50 ± 0.15 | 92.12 ± 0.81 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | Individual envelope | 96.86 ± 0.05 | 91.59 ± 0.99 | 9.32 ± 8.07 | 0.00 ± 0.00 |
| 10 | FedAvg | 97.35 ± 0.39 | 89.97 ± 1.64 | 21.89 ± 24.76 | 0.00 ± 0.00 |
| 15 | FedAvg | 96.94 ± 0.06 | 91.92 ± 0.92 | 35.00 ± 30.39 | 5.11 ± 7.71 |
| 10 | FLAME adaptation | 96.64 ± 0.11 | 87.87 ± 0.09 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | FLAME adaptation | 97.29 ± 0.46 | 93.45 ± 1.66 | 4.75 ± 8.22 | 0.00 ± 0.00 |
| 10 | Fixed-reference composite | 97.54 ± 0.20 | 92.30 ± 0.94 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | Fixed-reference composite | 96.88 ± 0.07 | 91.71 ± 1.05 | 9.32 ± 8.07 | 0.00 ± 0.00 |
| 10 | WeiDetect adaptation | 97.50 ± 0.16 | 92.03 ± 0.95 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | WeiDetect adaptation | 96.81 ± 0.08 | 91.54 ± 0.97 | 9.32 ± 8.07 | 0.00 ± 0.00 |

## non-iid: clean

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Mean maximum component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | Individual envelope | 96.21 ± 0.02 | 94.62 ± 0.02 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | Individual envelope | 96.02 ± 0.05 | 94.45 ± 0.04 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | FedAvg | 96.21 ± 0.02 | 94.62 ± 0.02 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | FedAvg | 96.02 ± 0.05 | 94.45 ± 0.04 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | FLAME adaptation | 95.92 ± 0.87 | 87.37 ± 0.71 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | FLAME adaptation | 95.22 ± 0.29 | 86.82 ± 0.20 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | Fixed-reference composite | 96.06 ± 0.27 | 93.37 ± 2.16 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | Fixed-reference composite | 95.85 ± 0.32 | 92.80 ± 2.90 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 10 | WeiDetect adaptation | 96.06 ± 0.37 | 87.37 ± 0.36 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| 15 | WeiDetect adaptation | 96.41 ± 0.54 | 87.74 ± 0.52 | 0.00 ± 0.00 | 0.00 ± 0.00 |

## non-iid: distributed

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Mean maximum component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | Individual envelope | 96.10 ± 0.41 | 94.88 ± 1.04 | 31.24 ± 54.10 | 24.93 ± 43.17 |
| 15 | Individual envelope | 96.17 ± 0.19 | 94.48 ± 0.06 | 33.30 ± 57.69 | 30.58 ± 52.96 |
| 10 | FedAvg | 96.38 ± 0.14 | 94.76 ± 0.12 | 32.75 ± 56.73 | 25.69 ± 44.49 |
| 15 | FedAvg | 96.26 ± 0.23 | 94.56 ± 0.20 | 38.68 ± 53.64 | 34.17 ± 50.14 |
| 10 | FLAME adaptation | 96.19 ± 0.47 | 87.40 ± 0.46 | 32.40 ± 56.12 | 22.63 ± 39.19 |
| 15 | FLAME adaptation | 96.14 ± 0.94 | 87.39 ± 0.61 | 38.19 ± 53.96 | 31.41 ± 52.07 |
| 10 | Fixed-reference composite | 96.62 ± 0.48 | 94.91 ± 0.31 | 31.43 ± 54.43 | 23.05 ± 39.92 |
| 15 | Fixed-reference composite | 96.16 ± 0.21 | 94.47 ± 0.08 | 33.53 ± 57.54 | 30.91 ± 53.54 |
| 10 | WeiDetect adaptation | 96.17 ± 0.41 | 87.44 ± 0.43 | 32.82 ± 56.84 | 26.83 ± 46.48 |
| 15 | WeiDetect adaptation | 96.77 ± 0.31 | 89.65 ± 3.05 | 37.09 ± 54.73 | 34.10 ± 50.24 |

