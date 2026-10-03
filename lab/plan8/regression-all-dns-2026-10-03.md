# Regression report 2026-10-03

- commit `251b4ba`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 32.9 | 6.0 | 4.5 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.1 | 301.7 | 7.5 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.0 | 0.4 | 3.1 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.0 | 2.7 | 3.6 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.1 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.1 | 56.2 | 11.9 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.2 | 0.9 | 13.5 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.1 | 3.7 | 0.0 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 32.9 | 0.2 | 4.3 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 33.1 | 0.5 | 1.9 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 33.1 | 1.2 | 3.5 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261003T175619449958Z-l1-run1
- c1 run 1: GREEN — cases/20261003T175715080142Z-c1-run1
- l2 run 1: GREEN — cases/20261003T180313646521Z-l2-run1
- l3 run 1: GREEN — cases/20261003T180404809944Z-l3-run1
- l3n run 1: GREEN — cases/20261003T180459470816Z-l3n-run1
- l4 run 1: GREEN — cases/20261003T180546267633Z-l4-run1
- c2 run 1: GREEN — cases/20261003T180740805070Z-c2-run1
- l5 run 1: GREEN — cases/20261003T180843155065Z-l5-run1
- l6 run 1: GREEN — cases/20261003T180935521781Z-l6-run1
- c3 run 1: GREEN — cases/20261003T181026964664Z-c3-run1
- c4 run 1: GREEN — cases/20261003T181118529065Z-c4-run1
