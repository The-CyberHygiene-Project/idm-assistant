# Regression report 2026-10-03

- commit `4cbd6e9`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.2 | 6.1 | 5.3 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.2 | 311.7 | 8.2 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.2 | 0.4 | 3.6 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.1 | 2.8 | 4.6 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.1 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.2 | 58.0 | 12.2 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.2 | 0.9 | 13.5 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.0 | 3.6 | 0.0 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 33.1 | 0.2 | 5.4 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 33.0 | 0.5 | 2.2 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 32.9 | 1.1 | 4.1 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261003T233124673993Z-l1-run1
- c1 run 1: GREEN — cases/20261003T233223436399Z-c1-run1
- l2 run 1: GREEN — cases/20261003T233835762952Z-l2-run1
- l3 run 1: GREEN — cases/20261003T233929756872Z-l3-run1
- l3n run 1: GREEN — cases/20261003T234027312367Z-l3n-run1
- l4 run 1: GREEN — cases/20261003T234113926831Z-l4-run1
- c2 run 1: GREEN — cases/20261003T234309757237Z-c2-run1
- l5 run 1: GREEN — cases/20261003T234413542352Z-l5-run1
- l6 run 1: GREEN — cases/20261003T234506775371Z-l6-run1
- c3 run 1: GREEN — cases/20261003T234600565667Z-c3-run1
- c4 run 1: GREEN — cases/20261003T234653407536Z-c4-run1
