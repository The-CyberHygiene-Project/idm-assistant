# Regression report 2026-11-04

- commit `51a14aa`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.9 | 25.9 | 8.9 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.5 | 310.1 | 11.2 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.0 | 1.2 | 6.3 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.9 | 6.4 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 65.8 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 66.0 | 27.4 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.7 | 1.4 | 10.9 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.7 | 26.2 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.8 | 0.7 | 8.9 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.6 | 23.6 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.7 | 53.7 | 6.6 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261104T163922981471Z-l1-run1
- l1 run 2: GREEN — cases/20261104T164202017555Z-l1-run2
- l1 run 3: GREEN — cases/20261104T164402051422Z-l1-run3
- c1 run 1: GREEN — cases/20261104T164602011441Z-c1-run1
- c1 run 2: GREEN — cases/20261104T165253072324Z-c1-run2
- c1 run 3: GREEN — cases/20261104T165942120928Z-c1-run3
- l2 run 1: GREEN — cases/20261104T170633548608Z-l2-run1
- l2 run 2: GREEN — cases/20261104T170807787324Z-l2-run2
- l2 run 3: GREEN — cases/20261104T170940889998Z-l2-run3
- l3 run 1: GREEN — cases/20261104T171113080633Z-l3-run1
- l3 run 2: GREEN — cases/20261104T171253131576Z-l3-run2
- l3 run 3: GREEN — cases/20261104T171431360756Z-l3-run3
- l3n run 1: GREEN — cases/20261104T171609431888Z-l3n-run1
- l3n run 2: GREEN — cases/20261104T171732092157Z-l3n-run2
- l3n run 3: GREEN — cases/20261104T171854087472Z-l3n-run3
- l4 run 1: GREEN — cases/20261104T172016741190Z-l4-run1
- l4 run 2: GREEN — cases/20261104T172215568768Z-l4-run2
- l4 run 3: GREEN — cases/20261104T172412529050Z-l4-run3
- c2 run 1: GREEN — cases/20261104T172609184716Z-c2-run1
- c2 run 2: GREEN — cases/20261104T172746091633Z-c2-run2
- c2 run 3: GREEN — cases/20261104T172920886411Z-c2-run3
- l5 run 1: GREEN — cases/20261104T173101203500Z-l5-run1
- l5 run 2: GREEN — cases/20261104T173301992301Z-l5-run2
- l5 run 3: GREEN — cases/20261104T173502001746Z-l5-run3
- l6 run 1: GREEN — cases/20261104T173702022713Z-l6-run1
- l6 run 2: GREEN — cases/20261104T173902048960Z-l6-run2
- l6 run 3: GREEN — cases/20261104T174102073328Z-l6-run3
- c3 run 1: GREEN — cases/20261104T174302026736Z-c3-run1
- c3 run 2: GREEN — cases/20261104T174502082146Z-c3-run2
- c3 run 3: GREEN — cases/20261104T174702041868Z-c3-run3
- c4 run 1: GREEN — cases/20261104T174902035116Z-c4-run1
- c4 run 2: GREEN — cases/20261104T175132026016Z-c4-run2
- c4 run 3: GREEN — cases/20261104T175402010932Z-c4-run3
