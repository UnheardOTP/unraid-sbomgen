#!/bin/bash
# Installs Syft and Grype for the plugin.
#   install-tools.sh           use the cached release on the flash drive; download latest only if none is cached
#   install-tools.sh --update  resolve the latest GitHub release and replace the cache if it's newer
# Downloads are verified against each release's published SHA-256 checksums.
# Tarballs are cached on the flash drive so the tools come back after a reboot
# without network access; the binaries themselves run from RAM.

set -uo pipefail
CACHE=/boot/config/plugins/sbomgen/bin
BIN=/usr/local/sbomgen/bin
UPDATE=${1:-}
mkdir -p "$CACHE" "$BIN"

say() { echo "$*"; logger -t sbomgen -- "$*"; }

latest_version() {   # follows the /releases/latest redirect; avoids GitHub API rate limits
  curl -fsSLI --max-time 30 -o /dev/null -w '%{url_effective}' "https://github.com/anchore/$1/releases/latest" \
    | sed -n 's#.*/tag/v\([0-9][0-9.]*\)$#\1#p'
}

install_one() {
  local tool=$1 cached ver tgz sums tmp
  cached=$(ls "$CACHE/${tool}_"*_linux_amd64.tar.gz 2>/dev/null | sort -V | tail -n1)

  if [[ -z $cached || $UPDATE == --update ]]; then
    ver=$(latest_version "$tool")
    if [[ -z $ver ]]; then
      say "$tool: could not resolve latest release (offline?)"
    elif [[ $cached == *"_${ver}_linux_amd64.tar.gz" ]]; then
      say "$tool $ver already cached"
    else
      tgz="${tool}_${ver}_linux_amd64.tar.gz"
      sums="${tool}_${ver}_checksums.txt"
      tmp=$(mktemp -d)
      say "$tool: downloading $ver"
      if curl -fsSL --max-time 300 -o "$tmp/$tgz"  "https://github.com/anchore/$tool/releases/download/v$ver/$tgz" &&
         curl -fsSL --max-time 60  -o "$tmp/$sums" "https://github.com/anchore/$tool/releases/download/v$ver/$sums" &&
         (cd "$tmp" && grep " ${tgz}\$" "$sums" | sha256sum -c --status -); then
        rm -f "$CACHE/${tool}_"*_linux_amd64.tar.gz
        mv "$tmp/$tgz" "$CACHE/"
        cached="$CACHE/$tgz"
        say "$tool $ver verified and cached"
      else
        say "$tool $ver download or checksum verification FAILED; keeping previous version"
      fi
      rm -rf "$tmp"
    fi
  fi

  if [[ -n $cached && -f $cached ]]; then
    tar -xzf "$cached" -C "$BIN" "$tool" && chmod 755 "$BIN/$tool"
    say "$tool installed: $("$BIN/$tool" version 2>/dev/null | awk '/^Version:/{print $2}')"
  else
    say "$tool is NOT installed"
    return 1
  fi
}

rc=0
install_one syft  || rc=1
install_one grype || rc=1
exit $rc
