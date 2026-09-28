# CHP build settings (PLACEHOLDERS.md)

Fill in the middle column of each row. Write the value plainly: no quotes,
no brackets, no | character. If a value does not apply, write the word none.
Do not leave any row blank.

Then run:  ./chp-apply-placeholders.sh PLACEHOLDERS.md chp-build.sh

| Setting | Your value | What it is |
|---|---|---|
| `CHP_SYSTEM_OWNER` | CyberHygiene Project Lab | Legal entity that owns the system, e.g. Example Holdings LLC |
| `CHP_ORG_NAME` | CyberHygiene Lab | Trading name. Printed on the login warning banner, e.g. Example Widgets |
| `CHP_SYSTEM_NAME` | Kanidm Lab client1 | Name of this system, e.g. Example CUI Enclave. Also names the output script |
| `CHP_DOMAIN` | kanidm.lab.test | DNS domain, e.g. example.org, or none for a standalone machine |
| `CHP_WAN_ADDR` | none | Outside (internet) address, or none if it changes or is unknown |
| `CHP_OFFLINE_TARGET` | none | Where the offline backup copy goes, or none if there is none yet |
