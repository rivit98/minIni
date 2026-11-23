# Move every crash and hang of the remote campaigns here, one flat directory
# per campaign group.
#
#   ./fuzz grab -o DIR IP...
#
# Everything is taken: every group under state/ (whatever FUZZ_GROUP or TC it
# ran with), every instance, and every crashes*/hangs* directory of it - the
# crashes.<date>/ AFL leaves behind on a restart included. The id* files of
# state/<group>/<instance>/crashes*/ land as they are in DIR/artifacts_<group>/.
# Moved, not copied (--remove-source-files): the next grab brings only what is
# new. A file AFL is still writing changes under rsync, which then keeps the
# source for next time.
#
# One rsync per source directory, never one for the whole group: given two
# files of the same name in one transfer, rsync keeps one and still removes
# both sources - one finding gone. Per directory, a name already in DIR is
# handled by --backup: the file there is renamed <name>,dup<ns> and the new one
# takes its place, so a clash costs nothing. All the rsyncs of a host share one
# ssh connection (ControlMaster).
#
# The remote campaign dir mirrors this campaign's layout under the remote root
# account: REMOTE_CAMPAIGN_DIR (common.sh), default /root/fuzz/$PROJECT_NAME. Override it to
# grab from a campaign kept elsewhere on the hosts.

USAGE="usage: $PROG grab -o DIR IP...

  -o DIR   where the artifacts go (created if missing)
  IP...    the hosts, each reached as root@IP over ssh

Every crash and hang under \$REMOTE_CAMPAIGN_DIR/state ($REMOTE_CAMPAIGN_DIR/state),
of every group and instance, is moved into DIR/artifacts_<group>/, flat and
under its own name, with rsync --remove-source-files: gone from the host
afterwards, so the next grab only brings new ones. A name already in
DIR/artifacts_<group> is kept, renamed <name>,dup<ns>.
A host that fails is reported and the rest still run; the exit status is
non-zero if any failed."
usage_guard "$@"

OUT=""; IPS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o) [ $# -ge 2 ] || usage; OUT="$2"; shift ;;
    -*) usage ;;
    *)  IPS+=("$1") ;;
  esac
  shift
done
[ -n "$OUT" ] && [ "${#IPS[@]}" -gt 0 ] || usage

ensure_dirs "$OUT"

# One ssh connection per host, shared by its listing and all its rsyncs.
ctl="$(mktemp -d)"
trap 'rm -rf "$ctl"' EXIT
SSH=(ssh -o ControlMaster=auto -o ControlPath="$ctl/%C" -o ControlPersist=60)

failed=()
for ip in "${IPS[@]}"; do
  log_step "$ip"
  # `|| rc=$?`: these scripts run with set -e, and a failing host must not end
  # the loop.
  rc=0
  # ./<group>/<instance>/{crashes,hangs}* - one line per source directory.
  # SC2029: $REMOTE_CAMPAIGN_DIR is meant to expand here, on the client - it is
  # this campaign's setting, not something the remote host defines.
  # shellcheck disable=SC2029
  dirs="$("${SSH[@]}" "root@$ip" "cd '$REMOTE_CAMPAIGN_DIR/state' && find . -mindepth 3 -maxdepth 3 -type d \\( -name 'crashes*' -o -name 'hangs*' \\) | sort")" \
    || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    while IFS= read -r d; do
      [[ -n "$d" ]] || continue
      d="${d#./}"
      g="${d%%/*}"
      mkdir -p "$OUT/artifacts_$g"
      # -c: a same-named file is compared by content, not size and mtime.
      rsync -az -h -c -e "${SSH[*]}" --info=name1,stats0 --remove-source-files \
        --include='id*' --exclude='*' --backup --suffix=",dup$(date +%s%N)" \
        "root@$ip:$REMOTE_CAMPAIGN_DIR/state/$d/" "$OUT/artifacts_$g/" \
        || rc=$?
    done <<<"$dirs"
  fi
  "${SSH[@]}" -O exit "root@$ip" 2>/dev/null || true
  if [[ "$rc" -eq 0 ]]; then
    log_ok "$ip: done"
  else
    log_err "$ip: failed (exit $rc)"
    failed+=("$ip")
  fi
done

for d in "$OUT"/artifacts_*/; do
  [[ -d "$d" ]] && log_ok "$(count_files "$d") files in $d"
done
[[ "${#failed[@]}" -eq 0 ]] || die "failed: ${failed[*]}"
