# Regression report 2026-10-04

- commit `fcbf1c9`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| d1 | 1 | 1/1 | GREEN | 33.2 | 0.3 | 0.0 | 1/1 valid, 1/1 agree |
| d2 | 1 | 1/1 | GREEN | 33.1 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| f1 | 1 | 1/1 | GREEN | 33.3 | 17.2 | 3.3 | 1/1 valid, 1/1 agree |
| f2 | 1 | 1/1 | GREEN | 33.4 | 75.2 | 15.3 | 1/1 valid, 1/1 agree |
| p1 | 1 | 1/1 | GREEN | 33.2 | 2.2 | 4.5 | 1/1 valid, 1/1 agree |
| p2 | 1 | 1/1 | GREEN | 33.5 | 0.4 | 0.0 | 1/1 valid, 1/1 agree |
| p3 | 1 | 1/1 | GREEN | 33.4 | 1.3 | 0.0 | 1/1 valid, 1/1 agree |

**Overall: 7 of 7 scenarios green in every run.**

## Runs

- d1 run 1: GREEN — cases/20261004T142449980120Z-d1-run1
- d2 run 1: GREEN — cases/20261004T142555833045Z-d2-run1
- f1 run 1: GREEN — cases/20261004T142653162221Z-f1-run1
- f2 run 1: GREEN — cases/20261004T142802994096Z-f2-run1
- p1 run 1: GREEN — cases/20261004T143025614614Z-p1-run1
- p2 run 1: GREEN — cases/20261004T143119694733Z-p2-run1
- p3 run 1: GREEN — cases/20261004T143206934933Z-p3-run1
