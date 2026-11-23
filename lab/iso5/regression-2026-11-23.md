# Regression report 2026-11-23

- commit `319e3e1`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.8 | 35.6 | 8.9 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.1 | 303.8 | 11.7 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 86.0 | 1.1 | 6.4 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.8 | 6.1 | 7.4 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 85.6 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.5 | 27.5 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.7 | 1.6 | 10.8 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 86.1 | 35.8 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.8 | 0.8 | 9.2 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 86.1 | 3.4 | 3.9 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.9 | 33.5 | 6.8 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261123T185353057847Z-l1-run1
- l1 run 2: GREEN — cases/20261123T185632017551Z-l1-run2
- l1 run 3: GREEN — cases/20261123T185901965502Z-l1-run3
- c1 run 1: GREEN — cases/20261123T190131977635Z-c1-run1
- c1 run 2: GREEN — cases/20261123T190839492735Z-c1-run2
- c1 run 3: GREEN — cases/20261123T191545689052Z-c1-run3
- l2 run 1: GREEN — cases/20261123T192249929587Z-l2-run1
- l2 run 2: GREEN — cases/20261123T192444766746Z-l2-run2
- l2 run 3: GREEN — cases/20261123T192638193296Z-l2-run3
- l3 run 1: GREEN — cases/20261123T192831769473Z-l3-run1
- l3 run 2: GREEN — cases/20261123T193032253013Z-l3-run2
- l3 run 3: GREEN — cases/20261123T193230752548Z-l3-run3
- l3n run 1: GREEN — cases/20261123T193430307680Z-l3n-run1
- l3n run 2: GREEN — cases/20261123T193613944907Z-l3n-run2
- l3n run 3: GREEN — cases/20261123T193753744678Z-l3n-run3
- l4 run 1: GREEN — cases/20261123T193935222803Z-l4-run1
- l4 run 2: GREEN — cases/20261123T194154404432Z-l4-run2
- l4 run 3: GREEN — cases/20261123T194410460540Z-l4-run3
- c2 run 1: GREEN — cases/20261123T194627261552Z-c2-run1
- c2 run 2: GREEN — cases/20261123T194825159303Z-c2-run2
- c2 run 3: GREEN — cases/20261123T195020538150Z-c2-run3
- l5 run 1: GREEN — cases/20261123T195218810432Z-l5-run1
- l5 run 2: GREEN — cases/20261123T195432006248Z-l5-run2
- l5 run 3: GREEN — cases/20261123T195701936018Z-l5-run3
- l6 run 1: GREEN — cases/20261123T195931955468Z-l6-run1
- l6 run 2: GREEN — cases/20261123T200131901491Z-l6-run2
- l6 run 3: GREEN — cases/20261123T200331941920Z-l6-run3
- c3 run 1: GREEN — cases/20261123T200531949739Z-c3-run1
- c3 run 2: GREEN — cases/20261123T200731946918Z-c3-run2
- c3 run 3: GREEN — cases/20261123T200931931416Z-c3-run3
- c4 run 1: GREEN — cases/20261123T201132102215Z-c4-run1
- c4 run 2: GREEN — cases/20261123T201401963583Z-c4-run2
- c4 run 3: GREEN — cases/20261123T201631943725Z-c4-run3
