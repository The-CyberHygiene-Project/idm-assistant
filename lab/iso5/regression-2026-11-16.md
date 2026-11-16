# Regression report 2026-11-16

- commit `c26bef5`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 87.1 | 34.1 | 8.8 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.8 | 302.8 | 11.4 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 86.3 | 1.2 | 6.6 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.8 | 6.2 | 7.3 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 85.4 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.4 | 27.4 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.7 | 1.5 | 15.3 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 86.5 | 34.3 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 86.0 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 85.1 | 4.3 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 2/3 | GREEN, GREEN, NOT-CLEARED | 84.3 | 35.0 | 6.5 | 3/3 valid, 3/3 agree |

**Overall: 10 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261116T151902204190Z-l1-run1
- l1 run 2: GREEN — cases/20261116T152202026657Z-l1-run2
- l1 run 3: GREEN — cases/20261116T152432072816Z-l1-run3
- c1 run 1: GREEN — cases/20261116T152702033504Z-c1-run1
- c1 run 2: GREEN — cases/20261116T153406354833Z-c1-run2
- c1 run 3: GREEN — cases/20261116T154109821519Z-c1-run3
- l2 run 1: GREEN — cases/20261116T154827729531Z-l2-run1
- l2 run 2: GREEN — cases/20261116T155023192098Z-l2-run2
- l2 run 3: GREEN — cases/20261116T155217053641Z-l2-run3
- l3 run 1: GREEN — cases/20261116T155411671662Z-l3-run1
- l3 run 2: GREEN — cases/20261116T155611557641Z-l3-run2
- l3 run 3: GREEN — cases/20261116T155811552446Z-l3-run3
- l3n run 1: GREEN — cases/20261116T160009548327Z-l3n-run1
- l3n run 2: GREEN — cases/20261116T160155697654Z-l3n-run2
- l3n run 3: GREEN — cases/20261116T160338757899Z-l3n-run3
- l4 run 1: GREEN — cases/20261116T160519931686Z-l4-run1
- l4 run 2: GREEN — cases/20261116T160738705038Z-l4-run2
- l4 run 3: GREEN — cases/20261116T160957528453Z-l4-run3
- c2 run 1: GREEN — cases/20261116T161211968361Z-c2-run1
- c2 run 2: GREEN — cases/20261116T161407967517Z-c2-run2
- c2 run 3: GREEN — cases/20261116T161609300718Z-c2-run3
- l5 run 1: GREEN — cases/20261116T161809038599Z-l5-run1
- l5 run 2: GREEN — cases/20261116T162032063935Z-l5-run2
- l5 run 3: GREEN — cases/20261116T162301982607Z-l5-run3
- l6 run 1: GREEN — cases/20261116T162532053162Z-l6-run1
- l6 run 2: GREEN — cases/20261116T162732042930Z-l6-run2
- l6 run 3: GREEN — cases/20261116T162932022841Z-l6-run3
- c3 run 1: GREEN — cases/20261116T163132076528Z-c3-run1
- c3 run 2: GREEN — cases/20261116T163332018068Z-c3-run2
- c3 run 3: GREEN — cases/20261116T163532058276Z-c3-run3
- c4 run 1: GREEN — cases/20261116T163732078198Z-c4-run1
- c4 run 2: GREEN — cases/20261116T164002035947Z-c4-run2
- c4 run 3: NOT-CLEARED — cases/20261116T164231994402Z-c4-run3
