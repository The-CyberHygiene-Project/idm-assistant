# Regression report 2026-11-09

- commit `9bf07bd`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 67.0 | 24.4 | 8.7 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 68.9 | 310.3 | 11.3 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 67.8 | 1.2 | 6.4 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 67.4 | 6.2 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 67.1 | 0.8 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 27.3 | 9.5 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 67.3 | 1.5 | 10.8 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 25.4 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.4 | 0.7 | 8.9 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.2 | 23.2 | 3.6 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.5 | 52.9 | 6.7 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261108T234412650455Z-l1-run1
- l1 run 2: GREEN — cases/20261108T234632016810Z-l1-run2
- l1 run 3: GREEN — cases/20261108T234831993687Z-l1-run3
- c1 run 1: GREEN — cases/20261108T235031991677Z-c1-run1
- c1 run 2: GREEN — cases/20261108T235727697126Z-c1-run2
- c1 run 3: GREEN — cases/20261109T000419963785Z-c1-run3
- l2 run 1: GREEN — cases/20261109T001113842472Z-l2-run1
- l2 run 2: GREEN — cases/20261109T001250236482Z-l2-run2
- l2 run 3: GREEN — cases/20261109T001425378290Z-l2-run3
- l3 run 1: GREEN — cases/20261109T001600958915Z-l3-run1
- l3 run 2: GREEN — cases/20261109T001742016465Z-l3-run2
- l3 run 3: GREEN — cases/20261109T001922953539Z-l3-run3
- l3n run 1: GREEN — cases/20261109T002103019749Z-l3n-run1
- l3n run 2: GREEN — cases/20261109T002228313253Z-l3n-run2
- l3n run 3: GREEN — cases/20261109T002351006384Z-l3n-run3
- l4 run 1: GREEN — cases/20261109T002512443877Z-l4-run1
- l4 run 2: GREEN — cases/20261109T002710784473Z-l4-run2
- l4 run 3: GREEN — cases/20261109T002909422058Z-l4-run3
- c2 run 1: GREEN — cases/20261109T003106593090Z-c2-run1
- c2 run 2: GREEN — cases/20261109T003245314875Z-c2-run2
- c2 run 3: GREEN — cases/20261109T003422821245Z-c2-run3
- l5 run 1: GREEN — cases/20261109T003558025626Z-l5-run1
- l5 run 2: GREEN — cases/20261109T003801960169Z-l5-run2
- l5 run 3: GREEN — cases/20261109T004001988378Z-l5-run3
- l6 run 1: GREEN — cases/20261109T004201943317Z-l6-run1
- l6 run 2: GREEN — cases/20261109T004401957209Z-l6-run2
- l6 run 3: GREEN — cases/20261109T004601933339Z-l6-run3
- c3 run 1: GREEN — cases/20261109T004801974130Z-c3-run1
- c3 run 2: GREEN — cases/20261109T005001915355Z-c3-run2
- c3 run 3: GREEN — cases/20261109T005201896939Z-c3-run3
- c4 run 1: GREEN — cases/20261109T005401927577Z-c4-run1
- c4 run 2: GREEN — cases/20261109T005631978638Z-c4-run2
- c4 run 3: GREEN — cases/20261109T005901977118Z-c4-run3
