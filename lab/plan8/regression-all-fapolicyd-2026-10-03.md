# Regression report 2026-10-03

- commit `57c8959`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.0 | 6.1 | 4.8 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.2 | 303.1 | 7.8 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.3 | 0.4 | 3.2 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.1 | 2.8 | 3.6 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.3 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.3 | 56.6 | 12.0 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.3 | 0.9 | 13.6 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.3 | 3.7 | 0.0 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 33.1 | 0.2 | 4.5 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 33.1 | 0.5 | 2.1 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 33.3 | 1.2 | 3.7 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261003T221012728780Z-l1-run1
- c1 run 1: GREEN — cases/20261003T221109968228Z-c1-run1
- l2 run 1: GREEN — cases/20261003T221712031224Z-l2-run1
- l3 run 1: GREEN — cases/20261003T221803466838Z-l3-run1
- l3n run 1: GREEN — cases/20261003T221857443214Z-l3n-run1
- l4 run 1: GREEN — cases/20261003T221943685000Z-l4-run1
- c2 run 1: GREEN — cases/20261003T222137950080Z-c2-run1
- l5 run 1: GREEN — cases/20261003T222239860520Z-l5-run1
- l6 run 1: GREEN — cases/20261003T222332674705Z-l6-run1
- c3 run 1: GREEN — cases/20261003T222425268907Z-c3-run1
- c4 run 1: GREEN — cases/20261003T222517227250Z-c4-run1
