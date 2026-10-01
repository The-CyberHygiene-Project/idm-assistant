# Regression report 2026-09-29

- commit `44479de`; model `mistralai/devstral-small-2-2512`; hosts srv1, client2 (reset to `golden` before every run)
- 1 run(s) per scenario; approvals by the regression runner (`IDM_TEST_APPROVE=1`)

| scenario | runs | green | statuses | median reset s | median inject s | median repair s | model |
|---|---|---|---|---|---|---|---|
| l1 | 1 | 1/1 | GREEN | 33.0 | 7.8 | 3.8 | 1/1 valid, 1/1 agree |
| c1 | 1 | 1/1 | GREEN | 33.3 | 311.6 | 7.6 | 1/1 valid, 1/1 agree |
| l2 | 1 | 1/1 | GREEN | 33.1 | 0.4 | 3.2 | 1/1 valid, 1/1 agree |
| l3 | 1 | 1/1 | GREEN | 33.1 | 2.6 | 3.3 | 1/1 valid, 1/1 agree |
| l3n | 1 | 1/1 | GREEN | 32.9 | 0.2 | 0.0 | 1/1 valid, 1/1 agree |
| l4 | 1 | 1/1 | GREEN | 33.0 | 65.9 | 11.8 | 1/1 valid, 1/1 agree |
| c2 | 1 | 1/1 | GREEN | 33.2 | 0.9 | 13.5 | 1/1 valid, 1/1 agree |
| l5 | 1 | 1/1 | GREEN | 33.2 | 3.6 | 4.2 | 1/1 valid, 1/1 agree |
| l6 | 1 | 1/1 | GREEN | 33.0 | 0.2 | 4.1 | 1/1 valid, 1/1 agree |
| c3 | 1 | 1/1 | GREEN | 33.1 | 0.9 | 2.1 | 1/1 valid, 1/1 agree |
| c4 | 1 | 1/1 | GREEN | 33.0 | 1.2 | 3.3 | 1/1 valid, 1/1 agree |

**Overall: 11 of 11 scenarios green in every run.**

## Runs

- l1 run 1: GREEN — cases/20260929T184513789901Z-l1-run1
- c1 run 1: GREEN — cases/20260929T184612706535Z-c1-run1
- l2 run 1: GREEN — cases/20260929T185221119233Z-l2-run1
- l3 run 1: GREEN — cases/20260929T185311647360Z-l3-run1
- l3n run 1: GREEN — cases/20260929T185403746284Z-l3n-run1
- l4 run 1: GREEN — cases/20260929T185449619786Z-l4-run1
- c2 run 1: GREEN — cases/20260929T185650894947Z-c2-run1
- l5 run 1: GREEN — cases/20260929T185751741008Z-l5-run1
- l6 run 1: GREEN — cases/20260929T185845512542Z-l6-run1
- c3 run 1: GREEN — cases/20260929T185935652878Z-c3-run1
- c4 run 1: GREEN — cases/20260929T190026176075Z-c4-run1
