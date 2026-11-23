# Campaign dashboard and health check - window 0 of the tmux session.
#
#   ./fuzz status                 # this campaign, once
#   ./fuzz status --loop          # refresh every $REFRESH seconds (default 600)
#   ./fuzz status --all           # every campaign on this machine
#   ./fuzz status IP...           # every campaign here and on each host
#   ./fuzz status --loop IP...    # ... as a dashboard
#
# COVERAGE is what the lane has reached now, PREV-COV what it had reached at the
# run before this one - the pair is the progress the campaign made in between,
# which a single number never shows. Every run leaves its coverage behind for
# the next one; with --loop that is one refresh, ten minutes by default.
#
# Two views:
#
#   this campaign  ($OUT_DIR) the lane table, the health checks, and the
#                  campaign totals from afl-whatsup -d -s verbatim - the
#                  instances alive, execs, speed, coverage, corpus, crashes,
#                  hangs and cycles without finds are all in its summary, and a
#                  second implementation of the same number is a second thing
#                  to keep correct.
#   many campaigns (--all, IP...) every campaign group under state/ of every
#                  machine named, each with its lane table, its health checks
#                  and a one-line total. afl-whatsup is not run there: a remote
#                  host may have AFL++ only inside docker, and one summary per
#                  campaign per host is a screen of text nobody reads.
#
# Both read every lane's fuzzer_stats directly, through one collector script
# (STATUS_COLLECTOR) that runs as it is on this machine and over ssh on a
# remote one, so a remote lane is judged exactly as a local one - against the
# remote clock, which is the one its fuzzer_stats was written by.


USAGE="usage: $PROG status [--loop] [--all] [IP...]

  (no options)  this campaign (FUZZ_GROUP=${FUZZ_GROUP:-<unset>}: $OUT_DIR)
  --all         every campaign group under $CAMPAIGN_DIR/state
  IP...         every campaign here, plus every campaign on each host, reached
                as root@IP over ssh under \$REMOTE_CAMPAIGN_DIR/state
                ($REMOTE_CAMPAIGN_DIR/state)
  --loop        refresh every \$REFRESH seconds (default 600 - ten minutes);
                press space to refresh immediately

Every lane's row comes from its fuzzer_stats, read directly so it still works
when a lane is wedged. The single-campaign view ends with afl-whatsup -d -s
verbatim; the multi-campaign view with one total line per campaign.
PREV-COV is each lane's COVERAGE as of the run before this one, so the pair
shows how far the edge map moved since - in --loop, over one refresh.
Thresholds: MIN_STABILITY, STALE_INSTANCE, STALE_FIND."
usage_guard "$@"

# Ten minutes: the dashboard is read at a glance, not watched, and PREV-COV is
# the coverage of one refresh ago - over a shorter step the two columns are the
# same number, since a campaign past its first hour moves the edge map slowly.
REFRESH="${REFRESH:-600}"

# Health thresholds - a line is flagged when it crosses one of these.
MIN_STABILITY="${MIN_STABILITY:-85}"     # %, below this the target is non-deterministic
STALE_INSTANCE="${STALE_INSTANCE:-120}"  # s since last fuzzer_stats update = dead
STALE_FIND="${STALE_FIND:-7200}"         # s without a new path = plateau

# The shared palette from common.sh, aliased to the short names this file uses.
c_red="$C_RED"; c_grn="$C_GRN"; c_yel="$C_YEL"; c_dim="$C_DIM"; c_bld="$C_BLD"; c_off="$C_OFF"

num() { local v="${1%%.*}"; v="${v//[^0-9-]/}"; echo "${v:-0}"; }

# ── the collector ─────────────────────────────────────────────────────────────
# A self-contained script, fed to `bash -s` on stdin - here, or on a remote host
# through ssh. On stdin rather than `bash -c`, because a process's command line
# is what pgrep matches: a collector whose own argv held the text "afl-fuzz"
# would count itself as a lane. It needs bash, awk and coreutils, nothing of
# this repo and no AFL++.
#
#   bash -s -- <state root> [<group>]
#
# Output, one record per line:
#
#   H <load> <physical cores> <shm free> <state fs free>   the machine
#   N                                                      no <state root>
#   C <group> <running>                                    one campaign
#   L <group> <lane> <execs_ps> <coverage> <corpus> <crashes> <hangs>
#     <stability> <cycles> <pending> <last_find_age> <last_update_age>
#
# <running> counts the afl-fuzz processes whose -o is that campaign's state
# dir. Matched on the process NAME (pgrep -x) first, so neither the tmux tab's
# `sh -c "... afl_run ... afl-fuzz -o ..."` nor a docker client's argv counts;
# docker lanes are counted too, since a container's processes are visible from
# the host. execs_ps is -1 while a lane is still calibrating (AFL reports a
# nonsense execs_per_sec until the first second of real fuzzing has elapsed,
# and the last-minute average once it exists). bitmap_cvg is AFL's own coverage
# number, per lane: the lanes sync, so they converge, and one lane sitting well
# below the others is the signal.
# shellcheck disable=SC2016 # expanded by the bash that runs it
STATUS_COLLECTOR='
root="$1"; only="${2:-}"
now="$(date +%s)"
df_free() { df -h "$1" --output=avail 2>/dev/null | tail -1 | tr -d " "; }
printf "H %s %s %s %s\n" "$(cut -d" " -f1 /proc/loadavg)" \
  "$(lscpu -p=CORE 2>/dev/null | grep -v "^#" | sort -u | wc -l)" \
  "$(df_free /dev/shm)" "$(df_free "$root")"
[ -d "$root" ] || { echo N; exit 0; }
procs="$(pgrep -a -x afl-fuzz 2>/dev/null || true)"
base="${root%/}"; base="${base##*/}"
for d in "$root"/*/; do
  d="${d%/}"; g="${d##*/}"
  [ -z "$only" ] || [ "$g" = "$only" ] || continue
  set -- "$d"/*/fuzzer_stats
  [ -f "$1" ] || continue
  run="$(grep -cE -- " -o [^ ]*/$base/$g/?( |\$)" <<<"$procs" || true)"
  echo "C $g ${run:-0}"
  awk -v now="$now" -v g="$g" "
    function n(v) { sub(/\\..*/, \"\", v); gsub(/[^0-9-]/, \"\", v); return v == \"\" ? 0 : v + 0 }
    function flush(  e, cov, lf) {
      if (lane == \"\") return
      e = n(s[\"execs_ps_last_min\"])
      if (e <= 0) e = (now - n(s[\"start_time\"]) < 90) ? -1 : n(s[\"execs_per_sec\"])
      cov = s[\"bitmap_cvg\"]; gsub(/[% ]/, \"\", cov); if (cov == \"\") cov = 0
      lf = n(s[\"last_find\"])
      print \"L\", g, lane, e, cov, n(s[\"corpus_count\"]), n(s[\"saved_crashes\"]), \
        n(s[\"saved_hangs\"]), n(s[\"stability\"]), n(s[\"cycles_done\"]), \
        n(s[\"pending_total\"]), (lf > 0 ? now - lf : -1), now - n(s[\"last_update\"])
      split(\"\", s)
    }
    FNR == 1 { flush(); lane = FILENAME; sub(/\\/fuzzer_stats\$/, \"\", lane); sub(/.*\\//, \"\", lane) }
    {
      k = \$0; sub(/[ \\t]*:.*/, \"\", k)
      v = \$0; sub(/^[^:]*:[ \\t]*/, \"\", v)
      if (!(k in s)) s[k] = v
    }
    END { flush() }
  " "$@"
done
'

# ssh to the remote hosts: one master connection per host, kept open between
# refreshes of --loop, and a dead host fails in seconds instead of hanging the
# whole dashboard.
SSH_CTL=""
SSH=()
ssh_init() {
  [ -n "$SSH_CTL" ] && return 0
  SSH_CTL="$(mktemp -d)"
  SSH=(ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5
       -o ServerAliveCountMax=2
       -o ControlMaster=auto -o ControlPath="$SSH_CTL/%C" -o ControlPersist=$((REFRESH + 60)))
}
ssh_done() {
  [ -n "$SSH_CTL" ] || return 0
  local s; for s in "$SSH_CTL"/*; do [ -S "$s" ] && ssh -o ControlPath="$s" -O exit x 2>/dev/null; done
  rm -rf "$SSH_CTL"
  return 0
}

# collect <target> <state root> [<group>] - the collector's output for one
# machine: "local" runs it here, anything else is root@<target>.
collect() {
  local target="$1" root="$2" group="${3:-}"
  if [ "$target" = local ]; then
    bash -s -- "$root" "$group" <<<"$STATUS_COLLECTOR"
  else
    # SC2029: the arguments are meant to expand here, on the client.
    # shellcheck disable=SC2029
    "${SSH[@]}" "root@$target" "bash -s -- $(printf '%q' "$root") $(printf '%q' "$group")" \
      <<<"$STATUS_COLLECTOR"
  fi
}

# ── PREV-COV ──────────────────────────────────────────────────────────────────
# Where the coverage of the last run is kept, so this one can print it beside
# the current one. The single-campaign view keeps it inside $OUT_DIR: the
# numbers describe that state directory and nothing else, and `./fuzz clean
# state` takes them with it. One file per campaign, so a `./fuzz status` run by
# hand while a dashboard loops moves the dashboard's baseline forward by one -
# the columns stay correct, the step just gets shorter for a frame.
# The multi-campaign view keys its lanes <machine>/<group>/<lane> in a file of
# its own, so watching every host never moves a campaign dashboard's baseline.
PREV_FILE="${PREV_FILE:-$OUT_DIR/.status_prev}"
MULTI_PREV_FILE="${MULTI_PREV_FILE:-$CAMPAIGN_DIR/.status_prev_multi}"

declare -A prev_cov=() snapshot=()
load_prev() { # load_prev <file>
  local n c
  prev_cov=(); snapshot=()
  [ -f "$1" ] || return 0
  while read -r n c; do
    case "$n" in '#'|'') ;; *) prev_cov[$n]="$c" ;; esac
  done < "$1"
  return 0
}

# This run's coverage, for the next one to read. Written to .tmp and renamed, so
# a dashboard killed mid-write leaves the last complete snapshot behind rather
# than half a file. Lanes this run did not reach - a host that did not answer -
# keep their old value, so one failed ssh does not reset their baseline.
save_prev() { # save_prev <file>
  local f="$1" k
  [ -d "$(dirname "$f")" ] || return 0
  [ "${#snapshot[@]}" -gt 0 ] || return 0
  for k in "${!prev_cov[@]}"; do [ -n "${snapshot[$k]+x}" ] || snapshot[$k]="${prev_cov[$k]}"; done
  {
    printf '# %s\n' "$(date +%s)"
    for k in "${!snapshot[@]}"; do printf '%s %s\n' "$k" "${snapshot[$k]}"; done
  } >"$f.tmp" 2>/dev/null && mv -- "$f.tmp" "$f" || return 0
}

# The machine's primary IPv4 address: the source address of the default route,
# which is what a remote campaign is reached on. Falls back to the first address
# hostname -I lists, then to "?" - the header must never fail the dashboard.
machine_ip() {
  local ip=""
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)" || true
  [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  echo "${ip:-?}"
}

# ── rendering ─────────────────────────────────────────────────────────────────
# print_lanes <prev key prefix> <L record>... - the lane table of one campaign.
# Leaves the campaign's numbers in t_* and appends its health lines to warn.
t_lanes=0; t_alive=0; t_execs=0; t_cov=0; t_crashes=0; t_hangs=0
warn=()
print_lanes() {
  local key="$1"; shift
  local rec _l _g n e cov c cr h st cy pd lf lu mark color pcov
  t_lanes=0; t_alive=0; t_execs=0; t_cov=0; t_crashes=0; t_hangs=0

  printf '%s%-10s %9s %8s %9s %8s %8s %7s %9s %7s %9s %11s%s\n' "$c_dim" \
    LANE EXEC/S COVERAGE PREV-COV CORPUS CRASHES HANGS STABILITY CYCLES PENDING LAST-FIND "$c_off"

  for rec in "$@"; do
    read -r _l _g n e cov c cr h st cy pd lf lu <<<"$rec"
    t_lanes=$((t_lanes + 1))
    t_crashes=$((t_crashes + cr)); t_hangs=$((t_hangs + h))
    awk -v a="$cov" -v b="$t_cov" 'BEGIN { exit !(a + 0 > b + 0) }' && t_cov="$cov"

    mark=""; color=""
    if [ "$lu" -gt "$STALE_INSTANCE" ]; then
      color="$c_red"; mark=" DEAD"; warn+=("$n: no fuzzer_stats update in $(human_age "$lu") - lane is dead or wedged")
    else
      t_alive=$((t_alive + 1))
      [ "$e" -gt 0 ] && t_execs=$((t_execs + e))
      if [ "$st" -lt "$MIN_STABILITY" ]; then
        color="$c_yel"   # row is flagged yellow; no health line for it
      elif [ "$lf" -gt "$STALE_FIND" ] && [ "$cy" -gt 0 ]; then
        color="$c_dim"; warn+=("$n: no new path in $(human_age "$lf") - plateau, consider new seeds or a dictionary pass")
      fi
    fi
    [ "$cr" -gt 0 ] && color="${color:-$c_grn}"

    # PREV-COV formatted whole, % included: a lane this file has not seen
    # before - the first run, or a lane added since - has no previous coverage
    # and gets a dash, which no %-suffixed number could stand in for.
    if [ -n "${prev_cov[$key$n]:-}" ]; then pcov="${prev_cov[$key$n]}%"; else pcov="-"; fi
    snapshot[$key$n]="$cov"

    printf '%s%-10s %9s %7s%% %9s %8s %8s %7s %8s%% %7s %9s %11s%s%s\n' \
      "$color" "$n" "$([ "$e" -ge 0 ] && echo "$e" || echo warmup)" \
      "$cov" "$pcov" "$c" "$cr" "$h" "$st" "$cy" "$pd" "$(human_age "$lf")" "$mark" "$c_off"
  done
}

print_warn() {
  local w
  for w in ${warn[@]+"${warn[@]}"}; do printf '  %s- %s%s\n' "$c_yel" "$w" "$c_off"; done
  warn=()
}

# parse_records - read collector output from stdin into H_* / CAMPAIGNS /
# RUNNING / LANES_<n>. Records arrive grouped by campaign, lanes sorted here.
parse_records() {
  local tag a b rest
  H_LOAD="?"; H_CORES="?"; H_SHM="?"; H_DISK="?"; H_NOSTATE=0
  CAMPAIGNS=(); declare -gA RUNNING=(); declare -gA LANES=()
  while read -r tag a b rest; do
    case "$tag" in
      H) H_LOAD="$a"; H_CORES="$b"; read -r H_SHM H_DISK <<<"$rest" ;;
      N) H_NOSTATE=1 ;;
      C) CAMPAIGNS+=("$a"); RUNNING[$a]="$b" ;;
      L) LANES[$a]+="$tag $a $b $rest"$'\n' ;;
    esac
  done
}

lanes_of() { # lanes_of <group> - that campaign's L records, sorted by lane, into REC
  mapfile -t REC < <(printf '%s' "${LANES[$1]:-}" | sort -k3,3)
}

# ── the single-campaign view ──────────────────────────────────────────────────
print_report() {
  local root group n_ctr
  root="$(dirname "$OUT_DIR")"; group="$(basename "$OUT_DIR")"
  load_prev "$PREV_FILE"
  parse_records < <(collect local "$root" "$group")
  lanes_of "$group"

  echo "${c_dim}$(date '+%F %T')${c_off}  ip $(machine_ip)  campaign ${TMUX_SESSION}   state: $OUT_DIR   TC: ${TC:-<all test cases>}"
  echo
  print_lanes "" ${REC[@]+"${REC[@]}"}

  # After the table, so a run that dies while collecting leaves the previous
  # run's numbers as the baseline rather than replacing them with half a table.
  save_prev "$PREV_FILE"

  echo
  if [ "$t_lanes" -eq 0 ]; then
    echo; echo "${c_yel}no lanes yet - run ./fuzz run${c_off}"
  fi

  # Containers are the other half of "is it alive": a fuzzer_stats file keeps
  # its last values after the container behind it died.
  n_ctr="$(running_instances)"
  printf 'backend %s: %s lane(s) running\n' "$FUZZ_BACKEND" "$n_ctr"
  if [ "$t_lanes" -gt 0 ] && [ "$n_ctr" -lt "$t_alive" ]; then
    warn+=("$((t_alive - n_ctr)) lane(s) have live stats but no process - a tab exited, check its tmux window")
  fi

  # Box health: the things that silently ruin a campaign.
  echo; echo "${c_yel}health:${c_off}"
  printf '  - load %s (jobs %s)   /dev/shm free %s   state fs free %s\n' \
    "$H_LOAD" "$JOBS" "${H_SHM:-?}" "${H_DISK:-?}"
  print_warn

  if [ "$t_lanes" -gt 0 ]; then
    echo; echo "${c_dim}--- afl-whatsup -d -s ---${c_off}"
    local summary
    # -d (include dead fuzzers) is not optional here: afl-whatsup decides
    # liveness with kill -0 on fuzzer_pid, and in the docker backend every lane
    # is its own container, so a whatsup container sees none of those PIDs and
    # would skip every instance - a summary of zeros. Liveness is answered
    # above instead, by stale stats and running_instances.
    summary="$(afl_run -- "afl-whatsup -d -s $B_OUT_DIR" 2>/dev/null </dev/null | sed -n '/Summary stats/,$p')"
    if [ -n "$summary" ]; then
      printf '%s\n' "$summary"
    else
      echo "${c_yel}afl-whatsup printed no summary - not installed in the backend?${c_off}"
    fi
  fi
}

# ── the multi-campaign view ───────────────────────────────────────────────────
# One block per machine, one table per campaign group on it.
print_machine() { # print_machine <target> <state root>
  local target="$1" root="$2" out rc=0 label g run
  out="$(collect "$target" "$root" 2>&1)" || rc=$?
  if [ "$target" = local ]; then label="local ($(machine_ip))"; else label="$target"; fi

  if [ "$rc" -ne 0 ] || ! grep -q '^H ' <<<"$out"; then
    echo "${c_bld}== $label${c_off}"
    echo "  ${c_red}unreachable (exit $rc): $(tail -1 <<<"$out")${c_off}"
    echo
    return 0
  fi
  parse_records <<<"$out"

  printf '%s== %s%s   %sload %s / %s cores   /dev/shm free %s   state fs free %s   %s%s\n' \
    "$c_bld" "$label" "$c_off" "$c_dim" "$H_LOAD" "$H_CORES" "${H_SHM:-?}" "${H_DISK:-?}" "$root" "$c_off"
  if [ "$H_NOSTATE" = 1 ] || [ "${#CAMPAIGNS[@]}" -eq 0 ]; then
    echo "  ${c_dim}no campaigns${c_off}"; echo
    return 0
  fi

  for g in "${CAMPAIGNS[@]}"; do
    run="${RUNNING[$g]}"
    lanes_of "$g"
    echo
    echo "${c_bld}campaign $g${c_off}"
    print_lanes "$target/$g/" ${REC[@]+"${REC[@]}"}
    if [ "$t_alive" -gt 0 ] && [ "$run" -lt "$t_alive" ]; then
      warn+=("$((t_alive - run)) lane(s) have live stats but no afl-fuzz process - a tab exited, check its tmux window")
    fi
    local color="$c_grn"
    [ "$t_alive" -lt "$t_lanes" ] && color="$c_yel"
    [ "$t_alive" -eq 0 ] && color="$c_red"
    printf '  %s%s/%s lanes alive, %s running%s   %s exec/s   max cov %s%%   crashes %s   hangs %s\n' \
      "$color" "$t_alive" "$t_lanes" "$run" "$c_off" "$t_execs" "$t_cov" "$t_crashes" "$t_hangs"
    print_warn
  done
  echo
}

print_multi() {
  local t
  load_prev "$MULTI_PREV_FILE"
  echo "${c_dim}$(date '+%F %T')${c_off}  ${#TARGETS[@]} machine(s)"
  echo
  print_machine local "$CAMPAIGN_DIR/state"
  for t in ${TARGETS[@]+"${TARGETS[@]:1}"}; do
    print_machine "$t" "$REMOTE_CAMPAIGN_DIR/state"
  done
  mkdir -p "$CAMPAIGN_DIR" 2>/dev/null || true
  save_prev "$MULTI_PREV_FILE"
}

# ── the loop ──────────────────────────────────────────────────────────────────
# Draw a pre-rendered frame. The report is built into a string FIRST and only
# then painted, so the terminal never shows a half-finished screen (collecting
# it takes a second - afl-whatsup runs the backend, ssh reaches the hosts).
# Painting overwrites in place rather than running clear(1): clearing first
# would blank the screen for that second and make the tab flicker on every tick.
#
# Overwriting only replaces as many characters as the new line has, so every
# line ends in erase-to-end-of-line (\033[K) - without it, a line that got
# shorter since the last tick keeps the tail of the old one. \033[J then clears
# the rows below a frame that got shorter.
paint() {
  local frame="$1"
  frame="${frame//$'\n'/$'\033[K\n'}"
  # Cursor home, frame, erase to end - as escapes, so there is no tput to find.
  printf '\033[H%s\033[K\n\033[J' "$frame"
}

# Sleep until the next refresh, or until space is pressed. Other keys are
# ignored and the wait carries on to the original deadline. Without a terminal
# on stdin there is no key to read, so it is a plain sleep.
#
# IFS= is the space key: read strips leading and trailing IFS whitespace from
# what it reads, and a lone space is nothing but - with the default IFS the key
# arrived as an empty string and never matched.
wait_refresh() {
  local deadline=$((SECONDS + REFRESH)) left key
  if [[ ! -t 0 ]]; then sleep "$REFRESH"; return 0; fi
  while ((SECONDS < deadline)); do
    left=$((deadline - SECONDS))
    key=""
    IFS= read -rsn1 -t "$left" key || true
    [[ "$key" == " " ]] && return 0
  done
  return 0
}

# Keys pressed while a frame is being collected: read -s turns echo off only
# while it reads, so without this they land on the screen mid-frame. And they
# are dropped before the wait starts, so a space hit during collection does
# not trigger a second refresh straight away.
drain_keys() { [[ -t 0 ]] || return 0; local k; while IFS= read -rsn1 -t 0.01 k; do :; done; return 0; }

LOOP=0; ALL=0; TARGETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --loop) LOOP=1 ;;
    --all)  ALL=1 ;;
    -*)     usage ;;
    *)      TARGETS+=("$1") ;;
  esac
  shift
done

# TARGETS[0] is this machine; a remote target means ssh.
if [ "${#TARGETS[@]}" -gt 0 ] || [ "$ALL" = 1 ]; then
  TARGETS=(local ${TARGETS[@]+"${TARGETS[@]}"})
  [ "${#TARGETS[@]}" -gt 1 ] && ssh_init
  report=print_multi
else
  report=print_report
fi

if [ "$LOOP" = 1 ]; then
  stty_saved=""
  [[ -t 0 ]] && stty_saved="$(stty -g 2>/dev/null || true)" && stty -echo 2>/dev/null || true
  printf '\033[?25l'                                   # hide the cursor
  # ... and put it all back, whichever way the loop ends.
  trap 'printf "\033[?25h"; [ -n "$stty_saved" ] && stty "$stty_saved" 2>/dev/null; ssh_done' EXIT
  trap 'exit 0' INT TERM
  clear
  while :; do
    frame="$($report; printf '\n%s' "${c_dim}refreshed $(date +%T), every $(human_age "$REFRESH"), space refreshes now - this tab is a dashboard, Ctrl-C here kills no fuzzer${c_off}")"
    paint "$frame"
    drain_keys
    wait_refresh
  done
else
  trap ssh_done EXIT
  $report
fi
