# Regression report 2026-09-29

- commit `7497d0b`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 3 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 3 | 3/3 | GREEN, GREEN, GREEN | 32.9 | 5.4 | 3.6 | 3/3 valid, 3/3 agree |
| c1 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 308.8 | 7.7 | 3/3 valid, 3/3 agree |
| l2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 0.5 | 2.7 | 3/3 valid, 3/3 agree |
| l3 | 3 | 3/3 | GREEN, GREEN, GREEN | 32.9 | 2.7 | 3.2 | 3/3 valid, 3/3 agree |
| l3n | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 0.2 | 0.0 | 3/3 valid, 3/3 agree |
| l4 | 3 | 3/3 | GREEN, GREEN, GREEN | 32.9 | 66.2 | 11.7 | 3/3 valid, 3/3 agree |
| c2 | 3 | 3/3 | GREEN, GREEN, GREEN | 33.0 | 0.9 | 13.4 | 3/3 valid, 3/3 agree |

**Overall: 7 of 7 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20260929T000828196877Z-l1-run1
- l1 run 2: GREEN — cases/20260929T000922344422Z-l1-run2
- l1 run 3: GREEN — cases/20260929T001016588580Z-l1-run3
- c1 run 1: GREEN — cases/20260929T001109159468Z-c1-run1
- c1 run 2: GREEN — cases/20260929T001712928792Z-c1-run2
- c1 run 3: GREEN — cases/20260929T002317299399Z-c1-run3
- l2 run 1: GREEN — cases/20260929T002921716542Z-l2-run1
- l2 run 2: GREEN — cases/20260929T003011437851Z-l2-run2
- l2 run 3: GREEN — cases/20260929T003100198414Z-l2-run3
- l3 run 1: GREEN — cases/20260929T003148736191Z-l3-run1
- l3 run 2: GREEN — cases/20260929T003240778719Z-l3-run2
- l3 run 3: GREEN — cases/20260929T003331848837Z-l3-run3
- l3n run 1: GREEN — cases/20260929T003423460330Z-l3n-run1
- l3n run 2: GREEN — cases/20260929T003509575804Z-l3n-run2
- l3n run 3: GREEN — cases/20260929T003553754030Z-l3n-run3
- l4 run 1: GREEN — cases/20260929T003636606383Z-l4-run1
- l4 run 2: GREEN — cases/20260929T003839679297Z-l4-run2
- l4 run 3: GREEN — cases/20260929T004040599220Z-l4-run3
- c2 run 1: GREEN — cases/20260929T004240565005Z-c2-run1
- c2 run 2: GREEN — cases/20260929T004341030238Z-c2-run2
- c2 run 3: GREEN — cases/20260929T004440309325Z-c2-run3
