# Regression report 2026-10-04

- commit `d8378fe`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| d1 | 1 | 1/1 | GREEN | 33.4 | 0.3 | 0.0 | 1/1 valid, 1/1 agree |
| d2 | 1 | 1/1 | GREEN | 33.1 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| f1 | 1 | 1/1 | GREEN | 33.1 | 14.2 | 3.2 | 1/1 valid, 1/1 agree |
| f2 | 1 | 1/1 | GREEN | 33.3 | 73.6 | 11.0 | 1/1 valid, 1/1 agree |
| p1 | 1 | 1/1 | GREEN | 33.3 | 2.2 | 4.2 | 1/1 valid, 1/1 agree |
| p2 | 1 | 1/1 | GREEN | 33.2 | 0.4 | 0.0 | 1/1 valid, 1/1 agree |
| p3 | 1 | 1/1 | GREEN | 33.3 | 3.4 | 0.0 | 1/1 valid, 1/1 agree |

**Overall: 7 of 7 scenarios green in every run.**

## Runs

- d1 run 1: GREEN — cases/20261004T153858843946Z-d1-run1
- d2 run 1: GREEN — cases/20261004T154005878523Z-d2-run1
- f1 run 1: GREEN — cases/20261004T154101936921Z-f1-run1
- f2 run 1: GREEN — cases/20261004T154208517186Z-f2-run1
- p1 run 1: GREEN — cases/20261004T154426508793Z-p1-run1
- p2 run 1: GREEN — cases/20261004T154520010540Z-p2-run1
- p3 run 1: GREEN — cases/20261004T154606827388Z-p3-run1
