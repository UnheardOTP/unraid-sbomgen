#!/bin/bash
# SBOM Generator for Unraid - main scan.
# Produces CycloneDX SBOMs for the Unraid host OS, host filesystem and every
# container image in use, optionally scans them with Grype, tags CISA KEV
# matches, diffs against the previous run and uploads to Dependency-Track.

set -uo pipefail

PLUGIN=sbomgen
EMHTTP=/usr/local/emhttp/plugins/$PLUGIN
BIN=/usr/local/$PLUGIN/bin
CFG_DEFAULT=$EMHTTP/default.cfg
CFG_USER=/boot/config/plugins/$PLUGIN/$PLUGIN.cfg
NOTIFY_BIN=/usr/local/emhttp/webGui/scripts/notify
LOCK=/var/run/$PLUGIN.lock

# --- config -----------------------------------------------------------------
# shellcheck disable=SC1090
source "$CFG_DEFAULT"
# shellcheck disable=SC1090
[[ -f $CFG_USER ]] && source "$CFG_USER"

export SYFT_CHECK_FOR_APP_UPDATE=false
export GRYPE_CHECK_FOR_APP_UPDATE=false
export GRYPE_DB_CACHE_DIR="$OUTPUT_DIR/grype-db"   # keep DB off the flash drive
export PATH="$BIN:$PATH"

log()    { echo "[$(date '+%F %T')] $*" | tee -a "$RUN_DIR/scan.log" >&2; logger -t "$PLUGIN" -- "$*"; }
notify() { [[ -x $NOTIFY_BIN ]] && "$NOTIFY_BIN" -e "SBOM Generator" -s "$1" -d "$2" -i "$3" >/dev/null 2>&1; true; }
safe()   { tr -c 'A-Za-z0-9._-' '_' <<<"$1" | sed 's/_*$//'; }

# --- single instance --------------------------------------------------------
exec 9>"$LOCK"
if ! flock -n 9; then
  logger -t "$PLUGIN" "scan already running, skipping"
  exit 0
fi

# --- preflight --------------------------------------------------------------
if [[ $OUTPUT_DIR == /mnt/* ]] && ! mountpoint -q "/mnt/$(cut -d/ -f3 <<<"$OUTPUT_DIR")"; then
  logger -t "$PLUGIN" "output location $OUTPUT_DIR is not mounted (array stopped?)"
  notify "Scan skipped" "Output location $OUTPUT_DIR is not available. Is the array started?" warning
  exit 1
fi
for b in syft grype; do
  if [[ ! -x $BIN/$b ]]; then
    logger -t "$PLUGIN" "$b missing from $BIN; reinstall the plugin"
    notify "Scan failed" "$b is not installed. Use 'Update tools' on the settings page." alert
    exit 1
  fi
done

STAMP=$(date +%Y%m%d-%H%M%S)
RUN_DIR="$OUTPUT_DIR/runs/$STAMP"
mkdir -p "$RUN_DIR/sbom" "$RUN_DIR/vulns" "$GRYPE_DB_CACHE_DIR"
echo "running $STAMP" >"$OUTPUT_DIR/status"
log "scan started -> $RUN_DIR"
ERRORS=0

# --- 1. Unraid host OS (Slackware packages, kernel, Unraid release) ----------
if [[ $SCAN_HOST_OS == yes ]]; then
  if php "$EMHTTP/scripts/host-sbom.php" >"$RUN_DIR/sbom/unraid-host-os.cdx.json" 2>>"$RUN_DIR/scan.log"; then
    log "host OS SBOM: $(grep -c '"bom-ref"' "$RUN_DIR/sbom/unraid-host-os.cdx.json") components"
  else
    log "host OS SBOM failed"; rm -f "$RUN_DIR/sbom/unraid-host-os.cdx.json"; ((ERRORS++))
  fi
fi

# --- 2. Host filesystem (language packages, binaries Syft recognises) --------
if [[ $SCAN_HOST_FS == yes ]]; then
  if syft scan dir:/ -q \
       --exclude './mnt/**' --exclude './proc/**' --exclude './sys/**' \
       --exclude './dev/**' --exclude './run/**'  --exclude './tmp/**' \
       --exclude './boot/**' --exclude './var/lib/docker/**' \
       --exclude './var/lib/libvirt/**' --exclude './usr/local/sbomgen/**' \
       --source-name unraid-host-fs \
       -o "cyclonedx-json=$RUN_DIR/sbom/unraid-host-fs.cdx.json" 2>>"$RUN_DIR/scan.log"; then
    log "host filesystem SBOM done"
  else
    log "host filesystem SBOM failed"; ((ERRORS++))
  fi
fi

# --- 3. Containers (one SBOM per image in use, named after its container) -----
if [[ $SCAN_CONTAINERS == yes ]] && command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  declare -A SEEN=()
  while IFS=$'\t' read -r name image imageid; do
    [[ -z $name ]] && continue
    if [[ -n ${SEEN[$imageid]:-} ]]; then
      log "container $name shares image with ${SEEN[$imageid]}, skipping duplicate"
      continue
    fi
    SEEN[$imageid]=$name
    out="$RUN_DIR/sbom/container-$(safe "$name").cdx.json"
    if syft scan "docker:$imageid" -q --source-name "$name" --source-version "$image" \
         -o "cyclonedx-json=$out" 2>>"$RUN_DIR/scan.log"; then
      log "container $name ($image) done"
    else
      log "container $name ($image) failed"; ((ERRORS++))
    fi
  done < <(docker ps -a --format '{{.Names}}' | while read -r c; do
             docker inspect --format '{{.Name}}{{"\t"}}{{.Config.Image}}{{"\t"}}{{.Image}}' "$c" | sed 's#^/##'
           done)
elif [[ $SCAN_CONTAINERS == yes ]]; then
  log "Docker is not running; container SBOMs skipped"
fi

# --- 4. Vulnerability scan ---------------------------------------------------
if [[ $VULN_SCAN == yes ]]; then
  if grype db update -q 2>>"$RUN_DIR/scan.log"; then
    log "grype database updated"
  else
    log "grype database update failed; using cached database if present"
  fi
  if curl -fsSL --max-time 60 -o "$RUN_DIR/kev.json.tmp" \
       https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json; then
    mv "$RUN_DIR/kev.json.tmp" "$OUTPUT_DIR/kev.json"
  else
    rm -f "$RUN_DIR/kev.json.tmp"
    log "CISA KEV download failed; using cached copy if present"
  fi
  for sbom in "$RUN_DIR"/sbom/*.cdx.json; do
    [[ -e $sbom ]] || continue
    base=$(basename "$sbom" .cdx.json)
    if ! grype "sbom:$sbom" -q -o "json=$RUN_DIR/vulns/$base.json" 2>>"$RUN_DIR/scan.log"; then
      log "grype failed on $base"; ((ERRORS++))
    fi
  done
  PREV=$(readlink -f "$OUTPUT_DIR/latest" 2>/dev/null || true)
  SUMMARY_LINE=$(php "$EMHTTP/scripts/summarize.php" "$RUN_DIR" "$OUTPUT_DIR/kev.json" "${PREV:-}" 2>>"$RUN_DIR/scan.log")
  log "summary: $SUMMARY_LINE"
fi

# --- 5. Dependency-Track upload -----------------------------------------------
if [[ -n ${DT_URL:-} && -n ${DT_API_KEY:-} ]]; then
  for sbom in "$RUN_DIR"/sbom/*.cdx.json; do
    [[ -e $sbom ]] || continue
    project=$(basename "$sbom" .cdx.json)
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 120 \
             -X POST "${DT_URL%/}/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
             -F autoCreate=true -F "projectName=$project" -F projectVersion=current \
             -F "bom=@$sbom" 2>>"$RUN_DIR/scan.log")
    if [[ $code == 200 ]]; then log "uploaded $project to Dependency-Track"
    else log "Dependency-Track upload of $project failed (HTTP $code)"; ((ERRORS++)); fi
  done
fi

# --- 6. Finish: latest link, retention, notification -------------------------
ln -sfn "$RUN_DIR" "$OUTPUT_DIR/latest"
if [[ ${KEEP_RUNS:-0} =~ ^[0-9]+$ && $KEEP_RUNS -gt 0 ]]; then
  find "$OUTPUT_DIR/runs" -mindepth 1 -maxdepth 1 -type d | sort -r | tail -n +$((KEEP_RUNS + 1)) | xargs -r rm -rf
fi
echo "finished $STAMP errors=$ERRORS ${SUMMARY_LINE:-}" >"$OUTPUT_DIR/status"
log "scan finished with $ERRORS error(s)"

if [[ -n ${SUMMARY_LINE:-} ]]; then
  # summarize.php line format: "new=N new_kev=N new_crit=N critical=N high=N kev=N"
  declare -A S=()
  for kv in $SUMMARY_LINE; do S[${kv%%=*}]=${kv#*=}; done
  level=normal
  (( ${S[new_kev]:-0} > 0 || ${S[new_crit]:-0} > 0 )) && level=alert
  msg="New: ${S[new]:-0} (KEV ${S[new_kev]:-0}, critical ${S[new_crit]:-0}). Totals: critical ${S[critical]:-0}, high ${S[high]:-0}, KEV ${S[kev]:-0}. Report: $RUN_DIR/summary.md"
  case $NOTIFY in
    always) notify "Scan complete" "$msg" "$level" ;;
    new)    (( ${S[new]:-0} > 0 )) && notify "New vulnerabilities found" "$msg" "$level" ;;
  esac
fi
(( ERRORS > 0 )) && [[ $NOTIFY != off ]] && notify "Scan finished with errors" "$ERRORS step(s) failed. See $RUN_DIR/scan.log" warning
exit 0
