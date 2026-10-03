# Regression report 2026-10-03

- commit `4cbd6e9`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| d1 | 1 | 1/1 | GREEN | 33.1 | 0.3 | 0.0 | 1/1 valid, 1/1 agree |
| d2 | 1 | 1/1 | GREEN | 32.9 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| f1 | 1 | 1/1 | GREEN | 32.6 | 17.0 | 3.2 | 1/1 valid, 1/1 agree |
| f2 | 1 | 1/1 | GREEN | 33.0 | 75.0 | 14.9 | 1/1 valid, 1/1 agree |

**Overall: 4 of 4 scenarios green in every run.**

## Runs

- d1 run 1: GREEN — cases/20261003T234747714413Z-d1-run1
- d2 run 1: GREEN — cases/20261003T234853020997Z-d2-run1
- f1 run 1: GREEN — cases/20261003T234949411860Z-f1-run1
- f2 run 1: GREEN — cases/20261003T235058143059Z-f2-run1
