# Regression report 2026-10-03

- commit `d0d1536`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 5.6 | 0.0 | 3/3 valid, 3/3 agree |

**Overall: 1 of 1 scenarios green in every run.**

## Runs

- l5 run 1: GREEN — cases/20261003T132433886272Z-l5-run1
- l5 run 2: GREEN — cases/20261003T132527648347Z-l5-run2
- l5 run 3: GREEN — cases/20261003T132620004339Z-l5-run3
