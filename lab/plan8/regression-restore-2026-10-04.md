# Regression report 2026-10-04

- commit `d8378fe`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| r1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 38.1 | 8.2 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 58.0 | 8.2 | 3/3 valid, 3/3 agree |

**Overall: 2 of 2 scenarios green in every run.**

## Runs

- r1 run 1: GREEN — cases/20261004T151209289742Z-r1-run1
- r1 run 2: GREEN — cases/20261004T151348432463Z-r1-run2
- r1 run 3: GREEN — cases/20261004T151525644466Z-r1-run3
- l4 run 1: GREEN — cases/20261004T151702962871Z-l4-run1
- l4 run 2: GREEN — cases/20261004T151856224349Z-l4-run2
- l4 run 3: GREEN — cases/20261004T152049287311Z-l4-run3
