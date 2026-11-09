# Fixed test endpoint summaries

Mean ± sample SD across three seeds. Each alternative output is a conditional reaggregation of the same FedAvg-driven incoming history. Component column is the largest of the three component-wise seed means, not a pooled full-trigger result. No hypothesis-test confidence intervals are inferred.

## clean

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Max mean component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | FedAvg | 97.38 ± 0.08 | 91.45 ± 0.79 | 0.00 ± 0.00 | 0.000 |
| 10 | Coordinate median | 97.56 ± 0.16 | 91.51 ± 0.87 | 0.00 ± 0.00 | 0.000 |
| 10 | Trimmed mean | 97.61 ± 0.09 | 91.53 ± 0.69 | 0.00 ± 0.00 | 0.000 |
| 10 | Multi-Krum | 97.49 ± 0.13 | 91.06 ± 0.74 | 0.00 ± 0.00 | 0.000 |
| 10 | Bulyan | 97.27 ± 0.14 | 90.30 ± 0.53 | 0.00 ± 0.00 | 0.000 |
| 10 | FLAME adaptation | 96.87 ± 0.47 | 89.07 ± 2.14 | 0.00 ± 0.00 | 0.000 |
| 10 | WeiDetect adaptation | 97.53 ± 0.21 | 91.76 ± 1.03 | 0.00 ± 0.00 | 0.000 |
| 10 | Original composite | 97.50 ± 0.15 | 91.46 ± 0.68 | 0.00 ± 0.00 | 0.000 |
| 15 | FedAvg | 96.74 ± 0.00 | 91.52 ± 0.00 | 0.00 ± 0.00 | 0.000 |
| 15 | Coordinate median | 97.85 ± 0.02 | 92.69 ± 0.16 | 0.00 ± 0.00 | 0.000 |
| 15 | Trimmed mean | 97.33 ± 0.49 | 92.16 ± 0.61 | 0.00 ± 0.00 | 0.000 |
| 15 | Multi-Krum | 97.78 ± 0.01 | 92.49 ± 0.15 | 0.00 ± 0.00 | 0.000 |
| 15 | Bulyan | 97.92 ± 0.11 | 92.62 ± 0.26 | 0.00 ± 0.00 | 0.000 |
| 15 | FLAME adaptation | 97.02 ± 0.19 | 92.73 ± 2.24 | 0.00 ± 0.00 | 0.000 |
| 15 | WeiDetect adaptation | 96.79 ± 0.08 | 91.52 ± 0.03 | 0.00 ± 0.00 | 0.000 |
| 15 | Original composite | 96.92 ± 0.05 | 91.74 ± 0.08 | 0.00 ± 0.00 | 0.000 |

## distributed

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Max mean component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | FedAvg | 97.77 ± 0.09 | 92.67 ± 1.13 | 44.09 ± 3.75 | 0.000 |
| 10 | Coordinate median | 97.62 ± 0.04 | 91.45 ± 0.27 | 0.02 ± 0.03 | 0.000 |
| 10 | Trimmed mean | 97.62 ± 0.03 | 91.33 ± 0.15 | 0.04 ± 0.03 | 0.000 |
| 10 | Multi-Krum | 97.60 ± 0.04 | 91.74 ± 0.41 | 0.00 ± 0.00 | 0.000 |
| 10 | Bulyan | 97.43 ± 0.02 | 91.00 ± 0.12 | 0.00 ± 0.00 | 0.000 |
| 10 | FLAME adaptation | 97.08 ± 0.53 | 89.70 ± 1.78 | 0.00 ± 0.00 | 0.000 |
| 10 | WeiDetect adaptation | 97.66 ± 0.04 | 92.40 ± 0.31 | 0.00 ± 0.00 | 0.000 |
| 10 | Original composite | 97.65 ± 0.04 | 92.18 ± 0.50 | 0.00 ± 0.00 | 0.000 |
| 15 | FedAvg | 96.78 ± 0.11 | 91.67 ± 0.17 | 0.00 ± 0.00 | 0.000 |
| 15 | Coordinate median | 96.97 ± 0.03 | 91.90 ± 0.17 | 0.00 ± 0.00 | 0.000 |
| 15 | Trimmed mean | 96.96 ± 0.02 | 91.85 ± 0.09 | 0.00 ± 0.00 | 0.000 |
| 15 | Multi-Krum | 97.39 ± 0.44 | 91.97 ± 0.26 | 0.00 ± 0.00 | 0.000 |
| 15 | Bulyan | 97.70 ± 0.17 | 92.07 ± 0.78 | 0.00 ± 0.00 | 0.000 |
| 15 | FLAME adaptation | 96.99 ± 0.20 | 92.71 ± 2.28 | 0.00 ± 0.00 | 0.000 |
| 15 | WeiDetect adaptation | 96.73 ± 0.01 | 91.53 ± 0.15 | 0.00 ± 0.00 | 0.000 |
| 15 | Original composite | 96.90 ± 0.04 | 91.84 ± 0.28 | 0.00 ± 0.00 | 0.000 |

## complete-trigger

| Round | Method | Clean accuracy (%) | Macro-F1 (%) | Complete ASR (%) | Max mean component ASR (%) |
| --- | --- | --- | --- | --- | --- |
| 10 | FedAvg | 97.50 ± 0.23 | 91.57 ± 0.89 | 96.97 ± 0.52 | 0.086 |
| 10 | Coordinate median | 97.49 ± 0.05 | 91.16 ± 0.30 | 86.57 ± 3.18 | 0.010 |
| 10 | Trimmed mean | 97.55 ± 0.05 | 91.13 ± 0.31 | 89.70 ± 2.12 | 0.010 |
| 10 | Multi-Krum | 97.28 ± 0.42 | 90.16 ± 1.86 | 63.69 ± 8.73 | 0.000 |
| 10 | Bulyan | 97.28 ± 0.11 | 90.55 ± 0.70 | 68.05 ± 1.60 | 0.000 |
| 10 | FLAME adaptation | 96.83 ± 0.45 | 89.01 ± 2.05 | 64.15 ± 6.85 | 0.000 |
| 10 | WeiDetect adaptation | 97.72 ± 0.30 | 93.27 ± 2.46 | 95.09 ± 1.84 | 0.029 |
| 10 | Original composite | 97.62 ± 0.09 | 91.90 ± 0.55 | 88.21 ± 0.22 | 0.000 |
| 15 | FedAvg | 96.90 ± 0.04 | 91.61 ± 0.15 | 11.81 ± 12.12 | 0.000 |
| 15 | Coordinate median | 97.33 ± 0.51 | 92.13 ± 1.06 | 4.15 ± 7.11 | 0.000 |
| 15 | Trimmed mean | 96.99 ± 0.04 | 91.74 ± 0.34 | 6.67 ± 10.72 | 0.000 |
| 15 | Multi-Krum | 97.39 ± 0.44 | 91.72 ± 0.11 | 0.04 ± 0.04 | 0.000 |
| 15 | Bulyan | 97.53 ± 0.51 | 92.12 ± 0.75 | 0.15 ± 0.26 | 0.000 |
| 15 | FLAME adaptation | 97.04 ± 0.18 | 92.64 ± 2.39 | 2.69 ± 4.66 | 0.000 |
| 15 | WeiDetect adaptation | 96.79 ± 0.12 | 91.50 ± 0.13 | 23.93 ± 19.72 | 0.000 |
| 15 | Original composite | 96.89 ± 0.01 | 91.69 ± 0.16 | 11.37 ± 12.09 | 0.000 |

