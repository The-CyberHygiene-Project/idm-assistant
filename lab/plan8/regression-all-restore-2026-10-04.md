# Regression report 2026-10-04

- commit `fcbf1c9`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 32.9 | 6.2 | 5.7 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.0 | 311.7 | 8.1 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.1 | 0.4 | 3.8 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.1 | 2.7 | 4.8 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.0 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.0 | 57.9 | 12.3 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.3 | 0.9 | 13.7 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.2 | 5.7 | 0.0 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 33.0 | 0.2 | 5.7 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 33.1 | 0.5 | 2.4 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 33.2 | 1.2 | 4.2 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261004T140819015668Z-l1-run1
- c1 run 1: GREEN — cases/20261004T140919310001Z-c1-run1
- l2 run 1: GREEN — cases/20261004T141531023550Z-l2-run1
- l3 run 1: GREEN — cases/20261004T141624863641Z-l3-run1
- l3n run 1: GREEN — cases/20261004T141723632543Z-l3n-run1
- l4 run 1: GREEN — cases/20261004T141810417256Z-l4-run1
- c2 run 1: GREEN — cases/20261004T142006365665Z-c2-run1
- l5 run 1: GREEN — cases/20261004T142111097046Z-l5-run1
- l6 run 1: GREEN — cases/20261004T142207114558Z-l6-run1
- c3 run 1: GREEN — cases/20261004T142301137886Z-c3-run1
- c4 run 1: GREEN — cases/20261004T142355138546Z-c4-run1
