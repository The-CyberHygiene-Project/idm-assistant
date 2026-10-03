# Regression report 2026-10-03

- commit `27673cb`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| p3 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.3 | 2.3 | 0.0 | 3/3 valid, 3/3 agree |

**Overall: 1 of 1 scenarios green in every run.**

## Runs

- p3 run 1: GREEN — cases/20261003T223225730136Z-p3-run1
- p3 run 2: GREEN — cases/20261003T223311560188Z-p3-run2
- p3 run 3: GREEN — cases/20261003T223357485030Z-p3-run3
