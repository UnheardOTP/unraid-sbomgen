#!/bin/bash
# Buttons on the settings page: run a scan or update Syft/Grype in the background.
S=/usr/local/emhttp/plugins/sbomgen/scripts
case ${1:-} in
  scan)   nohup "$S/sbomgen-scan.sh" >/dev/null 2>&1 & ;;
  update) nohup "$S/install-tools.sh" --update >/var/log/sbomgen-tools.log 2>&1 & ;;
  *)      echo "usage: $0 scan|update" >&2; exit 1 ;;
esac
