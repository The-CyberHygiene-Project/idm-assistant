# Regression report 2026-09-29

- commit `28be1d6`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.1 | 5.3 | 3.7 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 32.9 | 308.4 | 7.7 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 32.9 | 0.4 | 3.0 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.0 | 2.7 | 3.1 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 32.8 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 32.6 | 55.3 | 11.8 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 32.9 | 0.9 | 13.3 | 1/1 valid, 1/1 agree |

**Overall: 7 of 7 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20260929T005208206709Z-l1-run1
- c1 run 1: GREEN — cases/20260929T005301969004Z-c1-run1
- l2 run 1: GREEN — cases/20260929T005907243031Z-l2-run1
- l3 run 1: GREEN — cases/20260929T005956744510Z-l3-run1
- l3n run 1: GREEN — cases/20260929T010047214533Z-l3n-run1
- l4 run 1: GREEN — cases/20260929T010131681445Z-l4-run1
- c2 run 1: GREEN — cases/20260929T010322730056Z-c2-run1
