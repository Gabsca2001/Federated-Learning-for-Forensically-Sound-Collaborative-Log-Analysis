# Post-selection true-pair diagnosis

This labelled diagnosis explains the frozen clique outputs; it does not retune thresholds or add missed clients. A three-member clique requires all three pair edges. Experimental identity is consulted only after selection. Strong individual departures need not produce all three similarity exceedances.

| Partition / seed | Experimental true pair | Conditioned score | Frozen threshold | Candidate edge? | Strongest channel |
| --- | --- | --- | --- | --- | --- |
| iid / 501593 | 02/06 | 8.96524 | 9.23771 | No | temporal_indicator_correlation |
| iid / 501593 | 02/13 | 6.80514 | 9.23771 | No | temporal_indicator_correlation |
| iid / 501593 | 06/13 | 10.18292 | 9.23771 | Yes | temporal_indicator_correlation |
| iid / 502593 | 03/08 | 15.26271 | 9.23771 | Yes | temporal_indicator_correlation |
| iid / 502593 | 03/14 | 4.56122 | 9.23771 | No | temporal_indicator_correlation |
| iid / 502593 | 08/14 | 19.44143 | 9.23771 | Yes | temporal_indicator_correlation |
| iid / 503593 | 01/09 | 5.87754 | 9.23771 | No | temporal_indicator_correlation |
| iid / 503593 | 01/15 | 11.15789 | 9.23771 | Yes | temporal_indicator_correlation |
| iid / 503593 | 09/15 | 6.52532 | 9.23771 | No | temporal_indicator_correlation |
| non-iid / 511593 | 02/06 | 2.33331 | 6.44186 | No | temporal_indicator_correlation |
| non-iid / 511593 | 02/13 | 10.76437 | 6.44186 | Yes | temporal_indicator_correlation |
| non-iid / 511593 | 06/13 | 4.86322 | 6.44186 | No | median_centered_cosine |
| non-iid / 512593 | 03/08 | 9.49409 | 6.44186 | Yes | temporal_indicator_correlation |
| non-iid / 512593 | 03/14 | 6.09423 | 6.44186 | No | temporal_indicator_correlation |
| non-iid / 512593 | 08/14 | 7.96256 | 6.44186 | Yes | temporal_indicator_correlation |
| non-iid / 513593 | 01/09 | 12.01303 | 6.44186 | Yes | temporal_indicator_correlation |
| non-iid / 513593 | 01/15 | 8.71569 | 6.44186 | Yes | temporal_indicator_correlation |
| non-iid / 513593 | 09/15 | 2.69264 | 6.44186 | No | temporal_indicator_correlation |
