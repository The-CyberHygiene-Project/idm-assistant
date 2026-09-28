default_repair: nsswitch-restore
---
Kanidm must come first on passwd, group and initgroups. If initgroups lacks kanidm, users log in without their supplementary groups (sudo and group access fail). authselect reports hand edits; the repair re-selects the pinned profile and features.
