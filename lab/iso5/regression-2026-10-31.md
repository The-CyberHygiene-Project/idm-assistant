# Regression report 2026-11-01

- commit `e863ff2`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 27.1 | 8.7 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.6 | 309.6 | 11.2 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.6 | 1.2 | 6.2 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.3 | 6.4 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 64.5 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.4 | 27.4 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.3 | 1.5 | 15.6 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.4 | 27.0 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.6 | 0.7 | 9.6 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.3 | 24.9 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.6 | 54.7 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261101T182813178883Z-l1-run1
- l1 run 2: GREEN — cases/20261101T183102106916Z-l1-run2
- l1 run 3: GREEN — cases/20261101T183302092700Z-l1-run3
- c1 run 1: GREEN — cases/20261101T183502062337Z-c1-run1
- c1 run 2: GREEN — cases/20261101T184151821008Z-c1-run2
- c1 run 3: GREEN — cases/20261101T184839872005Z-c1-run3
- l2 run 1: GREEN — cases/20261101T185530048829Z-l2-run1
- l2 run 2: GREEN — cases/20261101T185702301667Z-l2-run2
- l2 run 3: GREEN — cases/20261101T185833443384Z-l2-run3
- l3 run 1: GREEN — cases/20261101T190004709191Z-l3-run1
- l3 run 2: GREEN — cases/20261101T190142374140Z-l3-run2
- l3 run 3: GREEN — cases/20261101T190318948994Z-l3-run3
- l3n run 1: GREEN — cases/20261101T190455082918Z-l3n-run1
- l3n run 2: GREEN — cases/20261101T190617331919Z-l3n-run2
- l3n run 3: GREEN — cases/20261101T190738801046Z-l3n-run3
- l4 run 1: GREEN — cases/20261101T190859305229Z-l4-run1
- l4 run 2: GREEN — cases/20261101T191058752958Z-l4-run2
- l4 run 3: GREEN — cases/20261101T191253901000Z-l4-run3
- c2 run 1: GREEN — cases/20261101T191450002080Z-c2-run1
- c2 run 2: GREEN — cases/20261101T191632469178Z-c2-run2
- c2 run 3: GREEN — cases/20261101T191810018151Z-c2-run3
- l5 run 1: GREEN — cases/20261101T191948760419Z-l5-run1
- l5 run 2: GREEN — cases/20261101T192132119685Z-l5-run2
- l5 run 3: GREEN — cases/20261101T192332107380Z-l5-run3
- l6 run 1: GREEN — cases/20261101T192532118133Z-l6-run1
- l6 run 2: GREEN — cases/20261101T192732077560Z-l6-run2
- l6 run 3: GREEN — cases/20261101T192932082648Z-l6-run3
- c3 run 1: GREEN — cases/20261101T193132095144Z-c3-run1
- c3 run 2: GREEN — cases/20261101T193332134640Z-c3-run2
- c3 run 3: GREEN — cases/20261101T193532121662Z-c3-run3
- c4 run 1: GREEN — cases/20261101T193732134045Z-c4-run1
- c4 run 2: GREEN — cases/20261101T194002066604Z-c4-run2
- c4 run 3: GREEN — cases/20261101T194232087089Z-c4-run3
