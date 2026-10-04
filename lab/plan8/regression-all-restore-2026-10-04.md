# Regression report 2026-10-04

- commit `d8378fe`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.3 | 6.4 | 5.6 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.1 | 301.1 | 8.3 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.2 | 0.5 | 3.7 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.2 | 2.9 | 4.4 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.3 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.2 | 58.1 | 8.1 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.3 | 0.9 | 13.9 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.2 | 3.6 | 0.0 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 33.3 | 0.2 | 5.5 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 33.1 | 0.5 | 2.3 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 33.2 | 1.2 | 4.2 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261004T152240815243Z-l1-run1
- c1 run 1: GREEN — cases/20261004T152342056233Z-c1-run1
- l2 run 1: GREEN — cases/20261004T152944616446Z-l2-run1
- l3 run 1: GREEN — cases/20261004T153038928456Z-l3-run1
- l3n run 1: GREEN — cases/20261004T153135729937Z-l3n-run1
- l4 run 1: GREEN — cases/20261004T153225898672Z-l4-run1
- c2 run 1: GREEN — cases/20261004T153418663003Z-c2-run1
- l5 run 1: GREEN — cases/20261004T153521915262Z-l5-run1
- l6 run 1: GREEN — cases/20261004T153615267258Z-l6-run1
- c3 run 1: GREEN — cases/20261004T153710390422Z-c3-run1
- c4 run 1: GREEN — cases/20261004T153803739739Z-c4-run1
