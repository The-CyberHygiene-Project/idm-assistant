# Regression report 2026-11-25

- commit `7ab08a6`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.4 | 40.7 | 8.8 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.6 | 303.0 | 11.5 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.2 | 1.2 | 7.1 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.5 | 6.1 | 7.3 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 80.1 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.3 | 27.5 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.3 | 1.4 | 9.5 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.6 | 11.0 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.4 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.3 | 9.0 | 3.8 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 80.3 | 39.0 | 6.8 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261125T002852703161Z-l1-run1
- l1 run 2: GREEN — cases/20261125T003132106672Z-l1-run2
- l1 run 3: GREEN — cases/20261125T003402091928Z-l1-run3
- c1 run 1: GREEN — cases/20261125T003632051629Z-c1-run1
- c1 run 2: GREEN — cases/20261125T004334223729Z-c1-run2
- c1 run 3: GREEN — cases/20261125T005032862424Z-c1-run3
- l2 run 1: GREEN — cases/20261125T005731805366Z-l2-run1
- l2 run 2: GREEN — cases/20261125T005921606892Z-l2-run2
- l2 run 3: GREEN — cases/20261125T010109920450Z-l2-run3
- l3 run 1: GREEN — cases/20261125T010258998144Z-l3-run1
- l3 run 2: GREEN — cases/20261125T010453567564Z-l3-run2
- l3 run 3: GREEN — cases/20261125T010647055609Z-l3-run3
- l3n run 1: GREEN — cases/20261125T010839578129Z-l3n-run1
- l3n run 2: GREEN — cases/20261125T011017864733Z-l3n-run2
- l3n run 3: GREEN — cases/20261125T011154185286Z-l3n-run3
- l4 run 1: GREEN — cases/20261125T011331180705Z-l4-run1
- l4 run 2: GREEN — cases/20261125T011544548814Z-l4-run2
- l4 run 3: GREEN — cases/20261125T011755892759Z-l4-run3
- c2 run 1: GREEN — cases/20261125T012007179735Z-c2-run1
- c2 run 2: GREEN — cases/20261125T012156098681Z-c2-run2
- c2 run 3: GREEN — cases/20261125T012345758753Z-c2-run3
- l5 run 1: GREEN — cases/20261125T012535611865Z-l5-run1
- l5 run 2: GREEN — cases/20261125T012802056041Z-l5-run2
- l5 run 3: GREEN — cases/20261125T013002068184Z-l5-run3
- l6 run 1: GREEN — cases/20261125T013202052268Z-l6-run1
- l6 run 2: GREEN — cases/20261125T013402046428Z-l6-run2
- l6 run 3: GREEN — cases/20261125T013602036198Z-l6-run3
- c3 run 1: GREEN — cases/20261125T013802075505Z-c3-run1
- c3 run 2: GREEN — cases/20261125T014002078788Z-c3-run2
- c3 run 3: GREEN — cases/20261125T014202088551Z-c3-run3
- c4 run 1: GREEN — cases/20261125T014402072785Z-c4-run1
- c4 run 2: GREEN — cases/20261125T014632065811Z-c4-run2
- c4 run 3: GREEN — cases/20261125T014902019643Z-c4-run3
