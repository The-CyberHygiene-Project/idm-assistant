# Regression report 2026-11-07

- commit `9361a09`; model `mistralai/devstral-small-2-2512`; profile `appliance`: hosts iso5-srv, iso5-cli2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.2 | 26.9 | 8.6 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.3 | 310.0 | 11.2 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 1.2 | 6.3 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 6.4 | 7.1 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 0.7 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 27.3 | 9.4 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 1.4 | 10.8 | 3/3 valid, 3/3 agree |
| l5 | 3 | 3/3 | GREEN, GREEN, GREEN | 64.9 | 26.4 | 0.0 | 3/3 valid, 3/3 agree |
| l6 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 0.7 | 9.0 | 3/3 valid, 3/3 agree |
| c3 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 24.4 | 3.7 | 3/3 valid, 3/3 agree |
| c4 | 3 | 3/3 | GREEN, GREEN, GREEN | 65.0 | 54.3 | 6.5 | 3/3 valid, 3/3 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20261107T152749589666Z-l1-run1
- l1 run 2: GREEN — cases/20261107T153032016214Z-l1-run2
- l1 run 3: GREEN — cases/20261107T153231977042Z-l1-run3
- c1 run 1: GREEN — cases/20261107T153432031857Z-c1-run1
- c1 run 2: GREEN — cases/20261107T154122273480Z-c1-run2
- c1 run 3: GREEN — cases/20261107T154814709795Z-c1-run3
- l2 run 1: GREEN — cases/20261107T155505745798Z-l2-run1
- l2 run 2: GREEN — cases/20261107T155639037491Z-l2-run2
- l2 run 3: GREEN — cases/20261107T155810973407Z-l2-run3
- l3 run 1: GREEN — cases/20261107T155942544981Z-l3-run1
- l3 run 2: GREEN — cases/20261107T160121296462Z-l3-run2
- l3 run 3: GREEN — cases/20261107T160258839088Z-l3-run3
- l3n run 1: GREEN — cases/20261107T160436973954Z-l3n-run1
- l3n run 2: GREEN — cases/20261107T160601270461Z-l3n-run2
- l3n run 3: GREEN — cases/20261107T160724206234Z-l3n-run3
- l4 run 1: GREEN — cases/20261107T160846685921Z-l4-run1
- l4 run 2: GREEN — cases/20261107T161044458310Z-l4-run2
- l4 run 3: GREEN — cases/20261107T161240221213Z-l4-run3
- c2 run 1: GREEN — cases/20261107T161437278416Z-c2-run1
- c2 run 2: GREEN — cases/20261107T161619546921Z-c2-run2
- c2 run 3: GREEN — cases/20261107T161752140701Z-c2-run3
- l5 run 1: GREEN — cases/20261107T161924627717Z-l5-run1
- l5 run 2: GREEN — cases/20261107T162132015980Z-l5-run2
- l5 run 3: GREEN — cases/20261107T162332018997Z-l5-run3
- l6 run 1: GREEN — cases/20261107T162532006367Z-l6-run1
- l6 run 2: GREEN — cases/20261107T162732059058Z-l6-run2
- l6 run 3: GREEN — cases/20261107T162932060145Z-l6-run3
- c3 run 1: GREEN — cases/20261107T163131984425Z-c3-run1
- c3 run 2: GREEN — cases/20261107T163332038007Z-c3-run2
- c3 run 3: GREEN — cases/20261107T163532016223Z-c3-run3
- c4 run 1: GREEN — cases/20261107T163732027704Z-c4-run1
- c4 run 2: GREEN — cases/20261107T164002023866Z-c4-run2
- c4 run 3: GREEN — cases/20261107T164231990209Z-c4-run3
