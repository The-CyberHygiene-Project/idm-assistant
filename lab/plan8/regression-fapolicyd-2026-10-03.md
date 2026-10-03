# Regression report 2026-10-03

- commit `57c8959`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| p1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 1.9 | 2.3 | 3/3 valid, 3/3 agree |
| p2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.3 | 0.4 | 0.0 | 3/3 valid, 3/3 agree |
| p3 | 3 | 0/3 | NOT-CLEARED, NOT-CLEARED, NOT-CLEARED | 33.2 | 2.3 | 0.0 | 3/3 valid, 3/3 agree |

**Overall: 2 of 3 scenarios green in every run.**

## Runs

- p1 run 1: GREEN — cases/20261003T220303780781Z-p1-run1
- p1 run 2: GREEN — cases/20261003T220356348585Z-p1-run2
- p1 run 3: GREEN — cases/20261003T220446322464Z-p1-run3
- p2 run 1: GREEN — cases/20261003T220535691055Z-p2-run1
- p2 run 2: GREEN — cases/20261003T220622557069Z-p2-run2
- p2 run 3: GREEN — cases/20261003T220706947905Z-p2-run3
- p3 run 1: NOT-CLEARED — cases/20261003T220751724452Z-p3-run1
- p3 run 2: NOT-CLEARED — cases/20261003T220840871553Z-p3-run2
- p3 run 3: NOT-CLEARED — cases/20261003T220926625260Z-p3-run3
