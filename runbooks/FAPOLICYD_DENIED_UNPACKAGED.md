default_repair: none
decisions: 46
user_sees: A program fails to start with "permission denied".
means: Something not installed through a signed package was run on this machine.
evidence: fapolicyd blocked a program that no signed package owns.
repair: No automatic repair. Tell the ISSO; if the program is needed, install it from a signed package instead.
if_wrong: Trusting an unknown program lets it run unchecked.
rollback: Nothing is changed by this tool.
say_no_if: Always the ISSO's decision.
---
fapolicyd denied executing a file that no package owns, or whose package is unsigned or signed by a key that is not pinned. This is what fapolicyd exists to stop. No repair exists (ISSO row 46): the engine never adds a program to the trust list; the ISSO decides whether it belongs on the machine.
