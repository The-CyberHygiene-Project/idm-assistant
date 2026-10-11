# Regression report 2026-10-11

- commit `20255a2`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 27.5 | 8.0 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 306.1 | 10.9 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 1.2 | 6.2 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 6.0 | 6.9 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 63.3 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 27.3 | 9.4 | 3/3 valid, 2/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.4 | 1.4 | 8.2 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 27.4 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.6 | 0.7 | 8.9 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 25.8 | 3.6 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 63.5 | 55.7 | 6.4 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261011T175744669137Z-l1-run1
- l1 run 2: GREEN — cases/20261011T175932107769Z-l1-run2
- l1 run 3: GREEN — cases/20261011T180132095140Z-l1-run3
- c1 run 1: GREEN — cases/20261011T180332109942Z-c1-run1
- c1 run 2: GREEN — cases/20261011T181015149922Z-c1-run2
- c1 run 3: GREEN — cases/20261011T181701464134Z-c1-run3
- l2 run 1: GREEN — cases/20261011T182346213273Z-l2-run1
- l2 run 2: GREEN — cases/20261011T182517035478Z-l2-run2
- l2 run 3: GREEN — cases/20261011T182646793047Z-l2-run3
- l3 run 1: GREEN — cases/20261011T182815494931Z-l3-run1
- l3 run 2: GREEN — cases/20261011T182951265581Z-l3-run2
- l3 run 3: GREEN — cases/20261011T183127158251Z-l3-run3
- l3n run 1: GREEN — cases/20261011T183302407396Z-l3n-run1
- l3n run 2: GREEN — cases/20261011T183423808322Z-l3n-run2
- l3n run 3: GREEN — cases/20261011T183543729938Z-l3n-run3
- l4 run 1: GREEN — cases/20261011T183702652103Z-l4-run1
- l4 run 2: GREEN — cases/20261011T183858531921Z-l4-run2
- l4 run 3: GREEN — cases/20261011T184051938166Z-l4-run3
- c2 run 1: GREEN — cases/20261011T184246990465Z-c2-run1
- c2 run 2: GREEN — cases/20261011T184419667910Z-c2-run2
- c2 run 3: GREEN — cases/20261011T184551164537Z-c2-run3
- l5 run 1: GREEN — cases/20261011T184721055533Z-l5-run1
- l5 run 2: GREEN — cases/20261011T184902106113Z-l5-run2
- l5 run 3: GREEN — cases/20261011T185102083412Z-l5-run3
- l6 run 1: GREEN — cases/20261011T185302095166Z-l6-run1
- l6 run 2: GREEN — cases/20261011T185502103132Z-l6-run2
- l6 run 3: GREEN — cases/20261011T185702129931Z-l6-run3
- c3 run 1: GREEN — cases/20261011T185902137044Z-c3-run1
- c3 run 2: GREEN — cases/20261011T190102077968Z-c3-run2
- c3 run 3: GREEN — cases/20261011T190302068276Z-c3-run3
- c4 run 1: GREEN — cases/20261011T190502132249Z-c4-run1
- c4 run 2: GREEN — cases/20261011T190732121553Z-c4-run2
- c4 run 3: GREEN — cases/20261011T191002105875Z-c4-run3
