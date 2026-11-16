# Regression report 2026-11-16

- commit `c26bef5`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 84.8 | 34.6 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 1 of 1 scenarios green in every run.**

## Runs

- c4 run 1: GREEN — cases/20261116T164840321393Z-c4-run1
- c4 run 2: GREEN — cases/20261116T165132023753Z-c4-run2
- c4 run 3: GREEN — cases/20261116T165402045115Z-c4-run3
