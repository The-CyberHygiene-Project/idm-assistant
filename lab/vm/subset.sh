# shellcheck shell=bash
# manifest_subset MANIFEST NAME... : print the MANIFEST lines for exactly these input names (literal match).
# Fails if a name has no manifest line, so a typo can't silently skip verification.
manifest_subset() {
  local man=$1 n line; shift
  for n in "$@"; do
    line=$(awk -F'|' -v n="$n" '$1 == n { print; exit }' "$man")
    [[ -n $line ]] || { echo "no manifest line for $n" >&2; return 1; }
    printf '%s\n' "$line"
  done
}
