default_repair: fapolicyd-trust-refresh
decisions: 46
user_sees: A program from an installed package fails to start with "permission denied".
means: The service or tool that needs it does not work.
evidence: fapolicyd blocked a program from an installed package that carries a pinned signing key: fapolicyd was never told about the package.
repair: Refresh fapolicyd's trust list from the signed package database.
if_wrong: Little risk: the refresh is refused unless everything it would newly trust is a package carrying a pinned signing key, with no trust-file entries waiting.
rollback: Cannot be undone, and does not need to be: it only adds packages that passed that check.
say_no_if: Nobody installed this package on purpose.
---
fapolicyd denied executing a file that an installed package signed by a pinned key (Rocky, EPEL, the project) owns, and the file is not in fapolicyd's trust database: the package was installed without notifying fapolicyd (e.g. rpm --noplugins). fapolicyd-cli --update re-reads the WHOLE package database and the trust files, so the repair refuses unless every package fapolicyd has never loaded carries a pinned key and no trust-file entry is waiting (ISSO row 46). The key is the one the package header claims; it is not re-verified on the host, because only the project key is imported there.
