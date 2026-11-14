# Regression report 2026-11-14

- commit `b07e187`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.5 | 41.7 | 9.1 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.5 | 303.1 | 11.7 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.5 | 1.2 | 6.6 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.1 | 6.5 | 7.3 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 79.6 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.4 | 27.4 | 9.4 | 3/3 valid, 2/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.3 | 1.5 | 10.9 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.6 | 11.9 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.7 | 0.7 | 8.9 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.4 | 9.8 | 3.9 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.3 | 40.0 | 6.8 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261114T175154138173Z-l1-run1
- l1 run 2: GREEN — cases/20261114T175432124543Z-l1-run2
- l1 run 3: GREEN — cases/20261114T175702116952Z-l1-run3
- c1 run 1: GREEN — cases/20261114T175932087349Z-c1-run1
- c1 run 2: GREEN — cases/20261114T180630513450Z-c1-run2
- c1 run 3: GREEN — cases/20261114T181329679349Z-c1-run3
- l2 run 1: GREEN — cases/20261114T182028185742Z-l2-run1
- l2 run 2: GREEN — cases/20261114T182215856229Z-l2-run2
- l2 run 3: GREEN — cases/20261114T182402777240Z-l2-run3
- l3 run 1: GREEN — cases/20261114T182550410580Z-l3-run1
- l3 run 2: GREEN — cases/20261114T182745253626Z-l3-run2
- l3 run 3: GREEN — cases/20261114T182936906196Z-l3-run3
- l3n run 1: GREEN — cases/20261114T183128273700Z-l3n-run1
- l3n run 2: GREEN — cases/20261114T183304246837Z-l3n-run2
- l3n run 3: GREEN — cases/20261114T183437080335Z-l3n-run3
- l4 run 1: GREEN — cases/20261114T183612102321Z-l4-run1
- l4 run 2: GREEN — cases/20261114T183822968999Z-l4-run2
- l4 run 3: GREEN — cases/20261114T184033837754Z-l4-run3
- c2 run 1: GREEN — cases/20261114T184243651601Z-c2-run1
- c2 run 2: GREEN — cases/20261114T184432213685Z-c2-run2
- c2 run 3: GREEN — cases/20261114T184626449580Z-c2-run3
- l5 run 1: GREEN — cases/20261114T184814637011Z-l5-run1
- l5 run 2: GREEN — cases/20261114T185032108764Z-l5-run2
- l5 run 3: GREEN — cases/20261114T185232081846Z-l5-run3
- l6 run 1: GREEN — cases/20261114T185432075060Z-l6-run1
- l6 run 2: GREEN — cases/20261114T185632092302Z-l6-run2
- l6 run 3: GREEN — cases/20261114T185832119278Z-l6-run3
- c3 run 1: GREEN — cases/20261114T190032119882Z-c3-run1
- c3 run 2: GREEN — cases/20261114T190232109850Z-c3-run2
- c3 run 3: GREEN — cases/20261114T190432062551Z-c3-run3
- c4 run 1: GREEN — cases/20261114T190632048601Z-c4-run1
- c4 run 2: GREEN — cases/20261114T190902044470Z-c4-run2
- c4 run 3: GREEN — cases/20261114T191132054563Z-c4-run3
