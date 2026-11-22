# Regression report 2026-11-22

- commit `6034056`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 92.2 | 29.0 | 8.5 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 92.6 | 310.4 | 11.6 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 90.9 | 1.3 | 7.2 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 90.6 | 6.2 | 8.6 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 91.3 | 0.9 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 90.8 | 30.9 | 10.2 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 92.0 | 2.1 | 14.0 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 93.3 | 29.7 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 90.0 | 1.0 | 13.6 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 91.4 | 28.0 | 4.5 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 91.3 | 58.1 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261122T182303216804Z-l1-run1
- l1 run 2: GREEN — cases/20261122T182601946769Z-l1-run2
- l1 run 3: GREEN — cases/20261122T182832084896Z-l1-run3
- c1 run 1: GREEN — cases/20261122T183102089030Z-c1-run1
- c1 run 2: GREEN — cases/20261122T183826130648Z-c1-run2
- c1 run 3: GREEN — cases/20261122T184545776382Z-c1-run3
- l2 run 1: GREEN — cases/20261122T185306248779Z-l2-run1
- l2 run 2: GREEN — cases/20261122T185509741996Z-l2-run2
- l2 run 3: GREEN — cases/20261122T185710852574Z-l2-run3
- l3 run 1: GREEN — cases/20261122T185914020366Z-l3-run1
- l3 run 2: GREEN — cases/20261122T190121263597Z-l3-run2
- l3 run 3: GREEN — cases/20261122T190329982822Z-l3-run3
- l3n run 1: GREEN — cases/20261122T190536805784Z-l3n-run1
- l3n run 2: GREEN — cases/20261122T190728255203Z-l3n-run2
- l3n run 3: GREEN — cases/20261122T190919063383Z-l3n-run3
- l4 run 1: GREEN — cases/20261122T191110308867Z-l4-run1
- l4 run 2: GREEN — cases/20261122T191338362902Z-l4-run2
- l4 run 3: GREEN — cases/20261122T191605996890Z-l4-run3
- c2 run 1: GREEN — cases/20261122T191833796865Z-c2-run1
- c2 run 2: GREEN — cases/20261122T192041864138Z-c2-run2
- c2 run 3: GREEN — cases/20261122T192252243033Z-c2-run3
- l5 run 1: GREEN — cases/20261122T192500324116Z-l5-run1
- l5 run 2: GREEN — cases/20261122T192732050084Z-l5-run2
- l5 run 3: GREEN — cases/20261122T193002041310Z-l5-run3
- l6 run 1: GREEN — cases/20261122T193232091315Z-l6-run1
- l6 run 2: GREEN — cases/20261122T193502036865Z-l6-run2
- l6 run 3: GREEN — cases/20261122T193732055660Z-l6-run3
- c3 run 1: GREEN — cases/20261122T194001990616Z-c3-run1
- c3 run 2: GREEN — cases/20261122T194231985161Z-c3-run2
- c3 run 3: GREEN — cases/20261122T194531994611Z-c3-run3
- c4 run 1: GREEN — cases/20261122T194801987387Z-c4-run1
- c4 run 2: GREEN — cases/20261122T195101843429Z-c4-run2
- c4 run 3: GREEN — cases/20261122T195401891325Z-c4-run3
