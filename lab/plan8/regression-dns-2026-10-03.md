# Regression report 2026-10-03

- commit `251b4ba`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| d1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 0.3 | 0.0 | 3/3 valid, 3/3 agree |
| d2 | 3 | 3/3 | GREEN, GREEN, GREEN | 32.8 | 0.2 | 0.0 | 3/3 valid, 3/3 agree |
| f1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 16.8 | 2.4 | 3/3 valid, 3/3 agree |
| f2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 73.1 | 14.0 | 3/3 valid, 2/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.1 | 2.6 | 3.5 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 33.2 | 0.2 | 0.0 | 3/3 valid, 3/3 agree |

**Overall: 6 of 6 scenarios green in every run.**

## Runs

- d1 run 1: GREEN — cases/20261003T181210215666Z-d1-run1
- d1 run 2: GREEN — cases/20261003T181314884542Z-d1-run2
- d1 run 3: GREEN — cases/20261003T181417508510Z-d1-run3
- d2 run 1: GREEN — cases/20261003T181521501087Z-d2-run1
- d2 run 2: GREEN — cases/20261003T181615952671Z-d2-run2
- d2 run 3: GREEN — cases/20261003T181709938356Z-d2-run3
- f1 run 1: GREEN — cases/20261003T181803730666Z-f1-run1
- f1 run 2: GREEN — cases/20261003T181907958481Z-f1-run2
- f1 run 3: GREEN — cases/20261003T182014263788Z-f1-run3
- f2 run 1: GREEN — cases/20261003T182119844253Z-f2-run1
- f2 run 2: GREEN — cases/20261003T182338356254Z-f2-run2
- f2 run 3: GREEN — cases/20261003T182556537432Z-f2-run3
- l3 run 1: GREEN — cases/20261003T182812843628Z-l3-run1
- l3 run 2: GREEN — cases/20261003T182907145100Z-l3-run2
- l3 run 3: GREEN — cases/20261003T182959680777Z-l3-run3
- l3n run 1: GREEN — cases/20261003T183052307979Z-l3n-run1
- l3n run 2: GREEN — cases/20261003T183138055594Z-l3n-run2
- l3n run 3: GREEN — cases/20261003T183223650113Z-l3n-run3
