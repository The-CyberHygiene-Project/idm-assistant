# Regression report 2026-11-06

- commit `4254a4c`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 25.0 | 8.7 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.5 | 310.2 | 11.3 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.7 | 1.2 | 6.3 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 6.3 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 66.5 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.5 | 27.4 | 9.4 | 3/3 valid, 2/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 1.4 | 10.8 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 24.5 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.5 | 22.8 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.6 | 52.7 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261106T180250979123Z-l1-run1
- l1 run 2: GREEN — cases/20261106T180532078742Z-l1-run2
- l1 run 3: GREEN — cases/20261106T180732042303Z-l1-run3
- c1 run 1: GREEN — cases/20261106T180932091311Z-c1-run1
- c1 run 2: GREEN — cases/20261106T181623941075Z-c1-run2
- c1 run 3: GREEN — cases/20261106T182316943394Z-c1-run3
- l2 run 1: GREEN — cases/20261106T183009740447Z-l2-run1
- l2 run 2: GREEN — cases/20261106T183144427822Z-l2-run2
- l2 run 3: GREEN — cases/20261106T183318749207Z-l2-run3
- l3 run 1: GREEN — cases/20261106T183453138873Z-l3-run1
- l3 run 2: GREEN — cases/20261106T183634978025Z-l3-run2
- l3 run 3: GREEN — cases/20261106T183813664790Z-l3-run3
- l3n run 1: GREEN — cases/20261106T183951886672Z-l3n-run1
- l3n run 2: GREEN — cases/20261106T184114268700Z-l3n-run2
- l3n run 3: GREEN — cases/20261106T184234955761Z-l3n-run3
- l4 run 1: GREEN — cases/20261106T184357517544Z-l4-run1
- l4 run 2: GREEN — cases/20261106T184556345539Z-l4-run2
- l4 run 3: GREEN — cases/20261106T184754727304Z-l4-run3
- c2 run 1: GREEN — cases/20261106T184952067571Z-c2-run1
- c2 run 2: GREEN — cases/20261106T185130749983Z-c2-run2
- c2 run 3: GREEN — cases/20261106T185308352987Z-c2-run3
- l5 run 1: GREEN — cases/20261106T185443518018Z-l5-run1
- l5 run 2: GREEN — cases/20261106T185632061533Z-l5-run2
- l5 run 3: GREEN — cases/20261106T185831989052Z-l5-run3
- l6 run 1: GREEN — cases/20261106T190032022935Z-l6-run1
- l6 run 2: GREEN — cases/20261106T190232062542Z-l6-run2
- l6 run 3: GREEN — cases/20261106T190432075833Z-l6-run3
- c3 run 1: GREEN — cases/20261106T190632050620Z-c3-run1
- c3 run 2: GREEN — cases/20261106T190832060350Z-c3-run2
- c3 run 3: GREEN — cases/20261106T191032101077Z-c3-run3
- c4 run 1: GREEN — cases/20261106T191232065954Z-c4-run1
- c4 run 2: GREEN — cases/20261106T191502012513Z-c4-run2
- c4 run 3: GREEN — cases/20261106T191732027716Z-c4-run3
