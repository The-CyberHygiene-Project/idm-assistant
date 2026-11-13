# proto/flow2-redirect-check.sh (Task 2 SPIKE; RUNS ON THE WORKSTATION via `ssh dcli bash -s < this`): follow Login Flow
# v2 unauthenticated, as a browser's top-level navigation, up to Kanidm; prints each hop with tokens masked.
cd /tmp && rm -f cj
B=https://files.docs.lab.test:8443; H=(-H "Accept: text/html" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document")
mask() { sed -E 's/(stateToken(%3D|=)|state=|nonce=|code_challenge=|client_id=)[A-Za-z0-9_%-]+/\1<x>/g'; }
L=$(curl -s -X POST $B/index.php/login/v2 | python3 -c 'import json,sys; print(json.load(sys.stdin)["login"])')
curl -s -b cj -c cj -o /dev/null "$L"
G=$(curl -s -b cj -c cj "${H[@]}" "$B/index.php/login/v2/flow?user=&direct=0" | grep -oE 'initial-state-core-loginFlowAuth" value="[^"]+' | sed 's/.*value="//' | base64 -d | python3 -c 'import json,sys; print(json.load(sys.stdin)["loginRedirectUrl"])')
u=$G
for i in 1 2 3 4; do
  r=$(curl -s -b cj -c cj "${H[@]}" -o /dev/null -w "%{http_code} %{redirect_url}" "$u")
  echo "hop $i: GET ${u%%\?*}$( [[ $u == *\?* ]] && echo '?…') -> $(echo "$r" | mask | cut -c1-220)"
  u=${r#* }; [[ -z $u || $u == https://idm.* ]] && break
done
rm -f cj
