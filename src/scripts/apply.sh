#!/bin/bash
# Called by the settings page after saving: rewrites the plugin's cron entry.
CFG_DIR=/boot/config/plugins/sbomgen
CRON=$CFG_DIR/sbomgen.cron
# shellcheck disable=SC1091
source /usr/local/emhttp/plugins/sbomgen/default.cfg
# shellcheck disable=SC1091
[[ -f $CFG_DIR/sbomgen.cfg ]] && source "$CFG_DIR/sbomgen.cfg"

num() { [[ $1 =~ ^[0-9]+$ ]] && echo "$1" || echo "$2"; }
MIN=$(num "$SCHED_MIN" 17); HOUR=$(num "$SCHED_HOUR" 3); DOW=$(num "$SCHED_DOW" 0)
JOB="/usr/local/emhttp/plugins/sbomgen/scripts/sbomgen-scan.sh >/dev/null 2>&1"

case $SCHEDULE in
  daily)  printf '# SBOM Generator\n%s %s * * * %s\n' "$MIN" "$HOUR" "$JOB" >"$CRON" ;;
  weekly) printf '# SBOM Generator\n%s %s * * %s %s\n' "$MIN" "$HOUR" "$DOW" "$JOB" >"$CRON" ;;
  *)      rm -f "$CRON" ;;
esac
/usr/local/sbin/update_cron
