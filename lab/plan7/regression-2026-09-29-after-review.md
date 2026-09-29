# Regression report 2026-09-29

- commit `aae7633`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.2 | 5.6 | 3.7 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.2 | 301.5 | 7.9 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 32.9 | 0.4 | 3.2 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.0 | 2.9 | 3.2 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 33.0 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.0 | 56.2 | 11.8 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.0 | 0.9 | 12.7 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 32.9 | 3.6 | 4.2 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 32.9 | 0.2 | 3.9 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 32.9 | 0.5 | 2.1 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 33.0 | 1.2 | 3.7 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20260929T122848135094Z-l1-run1
- c1 run 1: GREEN — cases/20260929T122942303935Z-c1-run1
- l2 run 1: GREEN — cases/20260929T123541460438Z-l2-run1
- l3 run 1: GREEN — cases/20260929T123630981135Z-l3-run1
- l3n run 1: GREEN — cases/20260929T123723997271Z-l3n-run1
- l4 run 1: GREEN — cases/20260929T123809399363Z-l4-run1
- c2 run 1: GREEN — cases/20260929T124000673262Z-c2-run1
- l5 run 1: GREEN — cases/20260929T124100467209Z-l5-run1
- l6 run 1: GREEN — cases/20260929T124154675611Z-l6-run1
- c3 run 1: GREEN — cases/20260929T124243937821Z-c3-run1
- c4 run 1: GREEN — cases/20260929T124333407807Z-c4-run1
