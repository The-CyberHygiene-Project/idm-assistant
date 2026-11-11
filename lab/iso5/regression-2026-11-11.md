# Regression report 2026-11-11

- commit `3e72f90`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 42.9 | 8.7 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 310.1 | 11.3 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.1 | 1.2 | 6.4 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.1 | 6.4 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.3 | 27.3 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.5 | 1.5 | 8.3 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.5 | 13.2 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.4 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 78.2 | 11.1 | 3.8 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 77.9 | 41.4 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261111T161901398578Z-l1-run1
- l1 run 2: GREEN — cases/20261111T162132129407Z-l1-run2
- l1 run 3: GREEN — cases/20261111T162402087815Z-l1-run3
- c1 run 1: GREEN — cases/20261111T162632099139Z-c1-run1
- c1 run 2: GREEN — cases/20261111T163336918819Z-c1-run2
- c1 run 3: GREEN — cases/20261111T164041866533Z-c1-run3
- l2 run 1: GREEN — cases/20261111T164744332403Z-l2-run1
- l2 run 2: GREEN — cases/20261111T164930948989Z-l2-run2
- l2 run 3: GREEN — cases/20261111T165116074226Z-l2-run3
- l3 run 1: GREEN — cases/20261111T165301756755Z-l3-run1
- l3 run 2: GREEN — cases/20261111T165453136064Z-l3-run2
- l3 run 3: GREEN — cases/20261111T165645716246Z-l3-run3
- l3n run 1: GREEN — cases/20261111T165835736850Z-l3n-run1
- l3n run 2: GREEN — cases/20261111T170010535111Z-l3n-run2
- l3n run 3: GREEN — cases/20261111T170145216024Z-l3n-run3
- l4 run 1: GREEN — cases/20261111T170317866530Z-l4-run1
- l4 run 2: GREEN — cases/20261111T170529111164Z-l4-run2
- l4 run 3: GREEN — cases/20261111T170737120547Z-l4-run3
- c2 run 1: GREEN — cases/20261111T170947150486Z-c2-run1
- c2 run 2: GREEN — cases/20261111T171135501881Z-c2-run2
- c2 run 3: GREEN — cases/20261111T171329864786Z-c2-run3
- l5 run 1: GREEN — cases/20261111T171515234763Z-l5-run1
- l5 run 2: GREEN — cases/20261111T171732139072Z-l5-run2
- l5 run 3: GREEN — cases/20261111T171932131968Z-l5-run3
- l6 run 1: GREEN — cases/20261111T172132119593Z-l6-run1
- l6 run 2: GREEN — cases/20261111T172332069713Z-l6-run2
- l6 run 3: GREEN — cases/20261111T172532113926Z-l6-run3
- c3 run 1: GREEN — cases/20261111T172732133914Z-c3-run1
- c3 run 2: GREEN — cases/20261111T172932071074Z-c3-run2
- c3 run 3: GREEN — cases/20261111T173132111103Z-c3-run3
- c4 run 1: GREEN — cases/20261111T173332115361Z-c4-run1
- c4 run 2: GREEN — cases/20261111T173602065722Z-c4-run2
- c4 run 3: GREEN — cases/20261111T173832074899Z-c4-run3
