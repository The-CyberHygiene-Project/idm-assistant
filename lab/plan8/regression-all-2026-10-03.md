# Regression report 2026-10-03

- commit `840b3e2`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.2 | 8.5 | 4.8 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.2 | 301.5 | 7.4 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.0 | 0.4 | 2.9 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.2 | 2.8 | 3.4 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.1 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.2 | 56.4 | 11.9 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.1 | 0.9 | 13.8 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.1 | 5.8 | 0.0 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 33.2 | 0.2 | 4.1 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 32.6 | 0.4 | 1.9 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 32.7 | 1.1 | 3.3 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261003T152054847871Z-l1-run1
- c1 run 1: GREEN — cases/20261003T152154223703Z-c1-run1
- l2 run 1: GREEN — cases/20261003T152753314925Z-l2-run1
- l3 run 1: GREEN — cases/20261003T152843615591Z-l3-run1
- l3n run 1: GREEN — cases/20261003T152937408048Z-l3n-run1
- l4 run 1: GREEN — cases/20261003T153023641826Z-l4-run1
- c2 run 1: GREEN — cases/20261003T153217193022Z-c2-run1
- l5 run 1: GREEN — cases/20261003T153320577906Z-l5-run1
- l6 run 1: GREEN — cases/20261003T153414465547Z-l6-run1
- c3 run 1: GREEN — cases/20261003T153506500381Z-c3-run1
- c4 run 1: GREEN — cases/20261003T153556856936Z-c4-run1
