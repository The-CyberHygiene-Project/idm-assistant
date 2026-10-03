# Regression report 2026-10-03

- commit `6a67c25`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| f1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 16.7 | 2.4 | 3/3 valid, 3/3 agree |
| f2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 72.4 | 14.0 | 3/3 valid, 3/3 agree |

**Overall: 2 of 2 scenarios green in every run.**

## Runs

- f1 run 1: GREEN — cases/20261003T153648235127Z-f1-run1
- f1 run 2: GREEN — cases/20261003T153754252562Z-f1-run2
- f1 run 3: GREEN — cases/20261003T153900647766Z-f1-run3
- f2 run 1: GREEN — cases/20261003T154005512805Z-f2-run1
- f2 run 2: GREEN — cases/20261003T154221437345Z-f2-run2
- f2 run 3: GREEN — cases/20261003T154437864779Z-f2-run3
