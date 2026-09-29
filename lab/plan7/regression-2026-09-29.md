# Regression report 2026-09-29

- commit `724041b`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.3 | 5.4 | 3.8 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 310.9 | 7.7 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 0.4 | 3.0 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 2.8 | 3.3 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 0.2 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 66.2 | 11.8 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 0.9 | 13.4 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 5.7 | 4.2 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 0.2 | 3.9 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 0.5 | 2.1 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 1.2 | 3.5 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20260929T113541121417Z-l1-run1
- l1 run 2: GREEN — cases/20260929T113634591243Z-l1-run2
- l1 run 3: GREEN — cases/20260929T113728194944Z-l1-run3
- c1 run 1: GREEN — cases/20260929T113822699122Z-c1-run1
- c1 run 2: GREEN — cases/20260929T114432539100Z-c1-run2
- c1 run 3: GREEN — cases/20260929T115040176385Z-c1-run3
- l2 run 1: GREEN — cases/20260929T115639097330Z-l2-run1
- l2 run 2: GREEN — cases/20260929T115728358185Z-l2-run2
- l2 run 3: GREEN — cases/20260929T115817154287Z-l2-run3
- l3 run 1: GREEN — cases/20260929T115905903644Z-l3-run1
- l3 run 2: GREEN — cases/20260929T115957870061Z-l3-run2
- l3 run 3: GREEN — cases/20260929T120048852037Z-l3-run3
- l3n run 1: GREEN — cases/20260929T120140331977Z-l3n-run1
- l3n run 2: GREEN — cases/20260929T120225615171Z-l3n-run2
- l3n run 3: GREEN — cases/20260929T120307907041Z-l3n-run3
- l4 run 1: GREEN — cases/20260929T120351160181Z-l4-run1
- l4 run 2: GREEN — cases/20260929T120553141358Z-l4-run2
- l4 run 3: GREEN — cases/20260929T120754667758Z-l4-run3
- c2 run 1: GREEN — cases/20260929T120945070602Z-c2-run1
- c2 run 2: GREEN — cases/20260929T121046338485Z-c2-run2
- c2 run 3: GREEN — cases/20260929T121147146930Z-c2-run3
- l5 run 1: GREEN — cases/20260929T121245913700Z-l5-run1
- l5 run 2: GREEN — cases/20260929T121339656124Z-l5-run2
- l5 run 3: GREEN — cases/20260929T121435082175Z-l5-run3
- l6 run 1: GREEN — cases/20260929T121531761162Z-l6-run1
- l6 run 2: GREEN — cases/20260929T121621110579Z-l6-run2
- l6 run 3: GREEN — cases/20260929T121712082084Z-l6-run3
- c3 run 1: GREEN — cases/20260929T121801625079Z-c3-run1
- c3 run 2: GREEN — cases/20260929T121851661971Z-c3-run2
- c3 run 3: GREEN — cases/20260929T121941963948Z-c3-run3
- c4 run 1: GREEN — cases/20260929T122031887781Z-c4-run1
- c4 run 2: GREEN — cases/20260929T122122504105Z-c4-run2
- c4 run 3: GREEN — cases/20260929T122212023284Z-c4-run3
