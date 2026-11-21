#!/usr/bin/env bash
# cycle.sh TITLE TYPE FLAG [PREFIX]: lab01 doc new -> check -> mark -> hand-off via CUI/Drafts -> lab04 approve -> rename -> publish (plan3.sh helpers; Plan 3 Task 13c)
here="$(cd "$(dirname "$0")" && pwd)"; T=$1 X=$2 FL=$3 PF=${4:-}
F=${PF}${T}_v0.1-DRAFT.$X; P=${PF}${T}_v0.1.$X
bash $here/plan3.sh U lab01 "cd ~/Documents/CHP-Working; chp-site doc new $T $FL --type $X | head -1; chp-site doc check $F; chp-site doc mark $F"
bash $here/plan3.sh U lab01 "cd ~/Documents/CHP-Working; python3 -I - PUT /remote.php/dav/files/lab01/CUI/Drafts/lab01/$F @$F" < $here/doc_api.py | head -1
bash $here/plan3.sh U lab04 "cd ~/Documents/CHP-Working; python3 -I - GET /remote.php/dav/files/lab04/CUI/Drafts/lab01/$F --out $F" < $here/doc_api.py | head -1
bash $here/plan3.sh U lab04 "cd ~/Documents/CHP-Working; chp-site doc approve $F; rm -f $F"
bash $here/plan3.sh U lab01 "cd ~/Documents/CHP-Working; mv $F $P; chp-site doc publish $P; echo publish-rc=\$?"
