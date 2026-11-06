#!/usr/bin/env bash
# Sourced by local-gate.sh (tested by test_local_gate_receipt.py): the receipt
# line one gate run appends. Needs $sha, $dirty (true|false) and $receipts.
# shellcheck disable=SC2154 # sha, dirty and receipts are set by the sourcing script

# Area targets that ran, as "name:exit,..." from the log's `area-target:`
# lines (local-gate-area.sh), so a receipt names what it covers.
area_targets() { # log
  sed -n 's/^area-target: \([^ ]*\) exit=\([0-9]*\).*/\1:\2/p' "$1" | paste -sd, -
}

# The area run's own bookkeeping lines (local-gate-area.sh): whether the run
# was narrowed by LOCAL_AREA_ONLY, the list `make local-area-list` expects, and
# the targets that actually ran. `area_complete` is true only for an unnarrowed
# run that executed exactly the expected list and exited 0.
area_line() { # log prefix
  sed -n "s/^$2: //p" "$1" | tail -n 1
}

receipt() { # target exit started log
  local partial expected ran complete=false
  partial="$(area_line "$4" area-partial)"
  expected="$(area_line "$4" area-expected | sed 's/^lane=[a-z]* //')"
  ran="$(sed -n 's/^area-target: \([^ ]*\) exit=.*/\1/p' "$4" | paste -sd' ' -)"
  # A dirty tree is never evidence (ALLOW_DIRTY=1), so it is never complete.
  if [ "$2" = 0 ] && [ "$dirty" = false ] && [ "$partial" = false ] && [ -n "$expected" ] && [ "$ran" = "$expected" ]; then complete=true; fi
  printf '{"sha":"%s","dirty":%s,"target":"%s","exit":%s,"started":"%s","finished":"%s","log":"%s","area_targets":"%s","partial":%s,"area_expected":"%s","area_complete":%s}\n' \
    "$sha" "$dirty" "$1" "$2" "$3" "$(date -u +%FT%TZ)" "$4" "$(area_targets "$4")" \
    "${partial:-false}" "$expected" "$complete" >> "$receipts"
}
