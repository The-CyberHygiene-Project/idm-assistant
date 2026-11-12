# Regression report 2026-11-10

- commit `33223ef`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 79.5 | 42.1 | 8.8 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.8 | 310.6 | 11.3 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.3 | 1.2 | 6.3 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 6.4 | 7.2 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 78.0 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.3 | 27.4 | 9.4 | 3/3 valid, 2/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.5 | 1.5 | 17.8 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 13.1 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.1 | 0.7 | 9.1 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.1 | 11.3 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 41.1 | 6.7 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261110T002640220312Z-l1-run1
- l1 run 2: GREEN — cases/20261110T002932040184Z-l1-run2
- l1 run 3: GREEN — cases/20261110T003202078034Z-l1-run3
- c1 run 1: GREEN — cases/20261110T003432052854Z-c1-run1
- c1 run 2: GREEN — cases/20261110T004135790845Z-c1-run2
- c1 run 3: GREEN — cases/20261110T004840853211Z-c1-run3
- l2 run 1: GREEN — cases/20261110T005545751434Z-l2-run1
- l2 run 2: GREEN — cases/20261110T005732566538Z-l2-run2
- l2 run 3: GREEN — cases/20261110T005917644755Z-l2-run3
- l3 run 1: GREEN — cases/20261110T010103087546Z-l3-run1
- l3 run 2: GREEN — cases/20261110T010256663233Z-l3-run2
- l3 run 3: GREEN — cases/20261110T010446930681Z-l3-run3
- l3n run 1: GREEN — cases/20261110T010637054422Z-l3n-run1
- l3n run 2: GREEN — cases/20261110T010811813222Z-l3n-run2
- l3n run 3: GREEN — cases/20261110T010945948893Z-l3n-run3
- l4 run 1: GREEN — cases/20261110T011120412993Z-l4-run1
- l4 run 2: GREEN — cases/20261110T011331406228Z-l4-run2
- l4 run 3: GREEN — cases/20261110T011539413975Z-l4-run3
- c2 run 1: GREEN — cases/20261110T011749820111Z-c2-run1
- c2 run 2: GREEN — cases/20261110T011946437558Z-c2-run2
- c2 run 3: GREEN — cases/20261110T012139955518Z-c2-run3
- l5 run 1: GREEN — cases/20261110T012335044609Z-l5-run1
- l5 run 2: GREEN — cases/20261110T012532006011Z-l5-run2
- l5 run 3: GREEN — cases/20261110T012732047389Z-l5-run3
- l6 run 1: GREEN — cases/20261110T012931958358Z-l6-run1
- l6 run 2: GREEN — cases/20261110T013132062241Z-l6-run2
- l6 run 3: GREEN — cases/20261110T013332047240Z-l6-run3
- c3 run 1: GREEN — cases/20261110T013532040190Z-c3-run1
- c3 run 2: GREEN — cases/20261110T013732011319Z-c3-run2
- c3 run 3: GREEN — cases/20261110T013932014007Z-c3-run3
- c4 run 1: GREEN — cases/20261110T014132020110Z-c4-run1
- c4 run 2: GREEN — cases/20261110T014401990304Z-c4-run2
- c4 run 3: GREEN — cases/20261110T014632002250Z-c4-run3
