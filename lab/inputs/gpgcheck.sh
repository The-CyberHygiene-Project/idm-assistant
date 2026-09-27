# GPG helpers for fetch.sh. Source it.
# shellcheck shell=bash
# A throwaway keyring: only keys imported during this run can vouch for anything.
gpg_sandbox() {
  GNUPGHOME=$(mktemp -d); export GNUPGHOME; chmod 700 "$GNUPGHOME"
  trap 'rm -rf "$GNUPGHOME"' EXIT
}
# verify_detached SIG DATA FPR: succeeds only if gpg reports VALIDSIG for exactly that key
# (as signing key or its primary). A good signature from any other key is a failure.
verify_detached() {
  local line
  line=$(gpg --batch --status-fd 1 --verify "$1" "$2" 2>/dev/null | grep '^\[GNUPG:\] VALIDSIG ') || return 1
  local -a f; read -r -a f <<<"$line"
  [[ "${f[2]}" == "$3" || "${f[${#f[@]}-1]}" == "$3" ]]
}
