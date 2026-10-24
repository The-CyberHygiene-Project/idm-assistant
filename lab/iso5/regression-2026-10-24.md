# Regression report 2026-10-24

- commit `42c26b3`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.3 | 28.1 | 8.1 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 306.7 | 11.1 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 1.1 | 6.3 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 6.1 | 7.0 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 27.4 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 1.5 | 17.8 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 27.8 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 25.8 | 3.6 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 55.8 | 6.4 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261024T164112139777Z-l1-run1
- l1 run 2: GREEN — cases/20261024T164332059276Z-l1-run2
- l1 run 3: GREEN — cases/20261024T164532134664Z-l1-run3
- c1 run 1: GREEN — cases/20261024T164732122119Z-c1-run1
- c1 run 2: GREEN — cases/20261024T165417706978Z-c1-run2
- c1 run 3: GREEN — cases/20261024T170101223977Z-c1-run3
- l2 run 1: GREEN — cases/20261024T170745754260Z-l2-run1
- l2 run 2: GREEN — cases/20261024T170917410057Z-l2-run2
- l2 run 3: GREEN — cases/20261024T171046866719Z-l2-run3
- l3 run 1: GREEN — cases/20261024T171216197856Z-l3-run1
- l3 run 2: GREEN — cases/20261024T171352752901Z-l3-run2
- l3 run 3: GREEN — cases/20261024T171527729943Z-l3-run3
- l3n run 1: GREEN — cases/20261024T171704754661Z-l3n-run1
- l3n run 2: GREEN — cases/20261024T171824224950Z-l3n-run2
- l3n run 3: GREEN — cases/20261024T171942636932Z-l3n-run3
- l4 run 1: GREEN — cases/20261024T172100811832Z-l4-run1
- l4 run 2: GREEN — cases/20261024T172256459739Z-l4-run2
- l4 run 3: GREEN — cases/20261024T172450570418Z-l4-run3
- c2 run 1: GREEN — cases/20261024T172644422670Z-c2-run1
- c2 run 2: GREEN — cases/20261024T172827626550Z-c2-run2
- c2 run 3: GREEN — cases/20261024T173006734643Z-c2-run3
- l5 run 1: GREEN — cases/20261024T173145823250Z-l5-run1
- l5 run 2: GREEN — cases/20261024T173332110314Z-l5-run2
- l5 run 3: GREEN — cases/20261024T173532117827Z-l5-run3
- l6 run 1: GREEN — cases/20261024T173732101642Z-l6-run1
- l6 run 2: GREEN — cases/20261024T173932125357Z-l6-run2
- l6 run 3: GREEN — cases/20261024T174132098611Z-l6-run3
- c3 run 1: GREEN — cases/20261024T174332125110Z-c3-run1
- c3 run 2: GREEN — cases/20261024T174532137958Z-c3-run2
- c3 run 3: GREEN — cases/20261024T174732153953Z-c3-run3
- c4 run 1: GREEN — cases/20261024T174932103607Z-c4-run1
- c4 run 2: GREEN — cases/20261024T175202115166Z-c4-run2
- c4 run 3: GREEN — cases/20261024T175432120632Z-c4-run3
