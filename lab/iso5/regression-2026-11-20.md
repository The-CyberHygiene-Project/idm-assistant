# Regression report 2026-11-20

- commit `148f2b0`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.6 | 41.0 | 8.9 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.3 | 302.8 | 11.8 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.1 | 1.2 | 6.6 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.9 | 6.3 | 7.4 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 81.1 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.3 | 27.5 | 9.4 | 3/3 valid, 2/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.3 | 1.4 | 10.7 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.3 | 10.1 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.2 | 0.7 | 8.9 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.2 | 8.3 | 3.9 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 81.3 | 38.1 | 6.7 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261120T202855222810Z-l1-run1
- l1 run 2: GREEN — cases/20261120T203131955096Z-l1-run2
- l1 run 3: GREEN — cases/20261120T203401971172Z-l1-run3
- c1 run 1: GREEN — cases/20261120T203631924992Z-c1-run1
- c1 run 2: GREEN — cases/20261120T204332808046Z-c1-run2
- c1 run 3: GREEN — cases/20261120T205032827716Z-c1-run3
- l2 run 1: GREEN — cases/20261120T205735564135Z-l2-run1
- l2 run 2: GREEN — cases/20261120T205927473126Z-l2-run2
- l2 run 3: GREEN — cases/20261120T210116254054Z-l2-run3
- l3 run 1: GREEN — cases/20261120T210305057641Z-l3-run1
- l3 run 2: GREEN — cases/20261120T210459494496Z-l3-run2
- l3 run 3: GREEN — cases/20261120T210653726970Z-l3-run3
- l3n run 1: GREEN — cases/20261120T210848804986Z-l3n-run1
- l3n run 2: GREEN — cases/20261120T211027614751Z-l3n-run2
- l3n run 3: GREEN — cases/20261120T211202903672Z-l3n-run3
- l4 run 1: GREEN — cases/20261120T211338077316Z-l4-run1
- l4 run 2: GREEN — cases/20261120T211553088173Z-l4-run2
- l4 run 3: GREEN — cases/20261120T211803955222Z-l4-run3
- c2 run 1: GREEN — cases/20261120T212017053069Z-c2-run1
- c2 run 2: GREEN — cases/20261120T212209147514Z-c2-run2
- c2 run 3: GREEN — cases/20261120T212358762324Z-c2-run3
- l5 run 1: GREEN — cases/20261120T212547903824Z-l5-run1
- l5 run 2: GREEN — cases/20261120T212801894366Z-l5-run2
- l5 run 3: GREEN — cases/20261120T213001982305Z-l5-run3
- l6 run 1: GREEN — cases/20261120T213201957944Z-l6-run1
- l6 run 2: GREEN — cases/20261120T213401938446Z-l6-run2
- l6 run 3: GREEN — cases/20261120T213601936829Z-l6-run3
- c3 run 1: GREEN — cases/20261120T213801923664Z-c3-run1
- c3 run 2: GREEN — cases/20261120T214001949019Z-c3-run2
- c3 run 3: GREEN — cases/20261120T214201946766Z-c3-run3
- c4 run 1: GREEN — cases/20261120T214401990892Z-c4-run1
- c4 run 2: GREEN — cases/20261120T214631916844Z-c4-run2
- c4 run 3: GREEN — cases/20261120T214901948422Z-c4-run3
