# Regression report 2026-10-03

- commit `4cbd6e9`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| p1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 2.2 | 4.3 | 3/3 valid, 3/3 agree |
| p2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 0.4 | 0.0 | 3/3 valid, 3/3 agree |
| p3 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 1.5 | 0.0 | 3/3 valid, 3/3 agree |

**Overall: 3 of 3 scenarios green in every run.**

## Runs

- p1 run 1: GREEN — cases/20261003T232410982179Z-p1-run1
- p1 run 2: GREEN — cases/20261003T232506677870Z-p1-run2
- p1 run 3: GREEN — cases/20261003T232600187912Z-p1-run3
- p2 run 1: GREEN — cases/20261003T232654619156Z-p2-run1
- p2 run 2: GREEN — cases/20261003T232741067661Z-p2-run2
- p2 run 3: GREEN — cases/20261003T232823854755Z-p2-run3
- p3 run 1: GREEN — cases/20261003T232908953453Z-p3-run1
- p3 run 2: GREEN — cases/20261003T232954141400Z-p3-run2
- p3 run 3: GREEN — cases/20261003T233039298265Z-p3-run3
