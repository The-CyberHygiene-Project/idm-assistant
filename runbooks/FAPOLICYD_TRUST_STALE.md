default_repair: fapolicyd-trust-refresh
decisions: 46
user_sees: A program from an installed package fails to start with "permission denied".
means: The service or tool that needs it does not work.
evidence: fapolicyd blocked a program that belongs to an installed, signed package: its trust list was never told about the package.
repair: Refresh fapolicyd's trust list from the signed package database.
if_wrong: Little risk: only programs from already-installed packages signed by a pinned key become trusted.
rollback: Cannot be undone, and does not need to be: it only adds what the signed package database already lists.
say_no_if: Nobody installed this package on purpose.
---
fapolicyd denied executing a file that an installed package signed by a pinned key (Rocky, EPEL, the project) owns, and the file is not in fapolicyd's trust database: the package was installed without notifying fapolicyd (e.g. rpm --noplugins). fapolicyd-cli --update re-reads the package database (ISSO row 46). It never trusts unpackaged or unsigned programs.
