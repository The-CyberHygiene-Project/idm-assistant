# Regression report 2026-11-03

- commit `f6bd6e2`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 26.0 | 8.8 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 310.3 | 11.3 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 1.2 | 6.3 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.8 | 6.4 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.5 | 27.3 | 9.3 | 3/3 valid, 2/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 1.5 | 15.7 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 25.3 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 22.6 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 52.6 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261103T183043357686Z-l1-run1
- l1 run 2: GREEN — cases/20261103T183332012505Z-l1-run2
- l1 run 3: GREEN — cases/20261103T183602020545Z-l1-run3
- c1 run 1: GREEN — cases/20261103T183802030161Z-c1-run1
- c1 run 2: GREEN — cases/20261103T184453599245Z-c1-run2
- c1 run 3: GREEN — cases/20261103T185149175874Z-c1-run3
- l2 run 1: GREEN — cases/20261103T185844733042Z-l2-run1
- l2 run 2: GREEN — cases/20261103T190019789566Z-l2-run2
- l2 run 3: GREEN — cases/20261103T190153474789Z-l2-run3
- l3 run 1: GREEN — cases/20261103T190326650033Z-l3-run1
- l3 run 2: GREEN — cases/20261103T190506351717Z-l3-run2
- l3 run 3: GREEN — cases/20261103T190645213647Z-l3-run3
- l3n run 1: GREEN — cases/20261103T190824134452Z-l3n-run1
- l3n run 2: GREEN — cases/20261103T190948431196Z-l3n-run2
- l3n run 3: GREEN — cases/20261103T191109087997Z-l3n-run3
- l4 run 1: GREEN — cases/20261103T191231982615Z-l4-run1
- l4 run 2: GREEN — cases/20261103T191430855595Z-l4-run2
- l4 run 3: GREEN — cases/20261103T191629495414Z-l4-run3
- c2 run 1: GREEN — cases/20261103T191825443683Z-c2-run1
- c2 run 2: GREEN — cases/20261103T192006290822Z-c2-run2
- c2 run 3: GREEN — cases/20261103T192146940168Z-c2-run3
- l5 run 1: GREEN — cases/20261103T192326765603Z-l5-run1
- l5 run 2: GREEN — cases/20261103T192531975509Z-l5-run2
- l5 run 3: GREEN — cases/20261103T192732010723Z-l5-run3
- l6 run 1: GREEN — cases/20261103T192932044897Z-l6-run1
- l6 run 2: GREEN — cases/20261103T193132120276Z-l6-run2
- l6 run 3: GREEN — cases/20261103T193332114128Z-l6-run3
- c3 run 1: GREEN — cases/20261103T193532089992Z-c3-run1
- c3 run 2: GREEN — cases/20261103T193732055332Z-c3-run2
- c3 run 3: GREEN — cases/20261103T193932045573Z-c3-run3
- c4 run 1: GREEN — cases/20261103T194132065428Z-c4-run1
- c4 run 2: GREEN — cases/20261103T194402091358Z-c4-run2
- c4 run 3: GREEN — cases/20261103T194632104589Z-c4-run3
