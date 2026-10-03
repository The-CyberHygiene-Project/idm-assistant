default_repair: nsswitch-restore
decisions:
user_sees: Users can log in, but sudo and group-shared folders stop working.
means: People lose everything their directory groups give them: administrator rights, shared folders, group-only services.
evidence: The group-lookup setting (initgroups) does not list Kanidm, and authselect reports the login settings were edited by hand.
repair: Re-apply the approved login settings (the pinned authselect profile and features) to this workstation.
if_wrong: Any deliberate hand edits to this workstation's login settings are replaced by the approved ones.
rollback: The current settings are saved first and put back automatically if the check afterwards fails.
say_no_if: This workstation was deliberately set up with its own login settings, different from the other workstations.
---
Kanidm must come first on passwd, group and initgroups. If initgroups lacks kanidm, users log in without their supplementary groups (sudo and group access fail). authselect reports hand edits; the repair re-selects the pinned profile and features.
