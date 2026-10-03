# Regression report 2026-10-03

- commit `57c8959`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| d1 | 1 | 1/1 | GREEN | 33.1 | 0.3 | 0.0 | 1/1 valid, 1/1 agree |
| d2 | 1 | 1/1 | GREEN | 33.2 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| f1 | 1 | 1/1 | GREEN | 33.1 | 16.9 | 2.7 | 1/1 valid, 1/1 agree |
| f2 | 1 | 1/1 | GREEN | 33.2 | 71.8 | 14.2 | 1/1 valid, 1/1 agree |

**Overall: 4 of 4 scenarios green in every run.**

## Runs

- d1 run 1: GREEN — cases/20261003T222610631778Z-d1-run1
- d2 run 1: GREEN — cases/20261003T222715326825Z-d2-run1
- f1 run 1: GREEN — cases/20261003T222810442703Z-f1-run1
- f2 run 1: GREEN — cases/20261003T222918963729Z-f2-run1
