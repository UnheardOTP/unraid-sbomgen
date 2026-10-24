#!/bin/bash
# Builds sbomgen.plg by inlining everything under src/ into one installer file.
#   ./build.sh                     version = today's date (Unraid convention)
#   VERSION=2026.10.23a ./build.sh
#   PLUGIN_URL=https://.../sbomgen.plg AUTHOR=you ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

NAME=sbomgen
VERSION=${VERSION:-$(date +%Y.%m.%d)}
AUTHOR=${AUTHOR:-UnheardOTP}
PLUGIN_URL=${PLUGIN_URL:-https://raw.githubusercontent.com/UnheardOTP/unraid-sbomgen/main/sbomgen.plg}
OUT=$NAME.plg
EMHTTP=/usr/local/emhttp/plugins/\&name\;

if grep -rl ']]>' src/ >/dev/null; then echo "a source file contains ]]> which would break CDATA" >&2; exit 1; fi

inline() {   # $1 = destination path in plg, $2 = source file, $3 = mode
  printf '<FILE Name="%s" Mode="%s">\n<INLINE><![CDATA[\n' "$1" "$3"
  cat "$2"
  printf ']]></INLINE>\n</FILE>\n\n'
}

{
cat <<EOF
<?xml version='1.0' standalone='yes'?>
<!DOCTYPE PLUGIN [
<!ENTITY name      "$NAME">
<!ENTITY author    "$AUTHOR">
<!ENTITY version   "$VERSION">
<!ENTITY pluginURL "$PLUGIN_URL">
]>
<PLUGIN name="&name;" author="&author;" version="&version;" pluginURL="&pluginURL;" min="6.12.0" icon="list-alt" support="https://github.com/$AUTHOR/unraid-sbomgen/issues">

<CHANGES>
###&version;
- CycloneDX SBOMs for the Unraid OS (Slackware packages, kernel, release), host filesystem and containers
- Grype vulnerability scan, CISA KEV tagging, new-since-last-run diff, Unraid notifications
- Optional Dependency-Track upload
</CHANGES>

<!-- Pre-install: clear the previous version's runtime files -->
<FILE Run="/bin/bash">
<INLINE>
rm -rf /usr/local/emhttp/plugins/&name;
mkdir -p /usr/local/emhttp/plugins/&name;/scripts /boot/config/plugins/&name;/bin
</INLINE>
</FILE>

EOF

inline "$EMHTTP/default.cfg"                   src/default.cfg                  0644
inline "$EMHTTP/SBOMGen.page"                  src/SBOMGen.page                 0644
inline "$EMHTTP/download.php"                  src/download.php                 0644
for s in src/scripts/*; do
  mode=0644; [[ $s == *.sh ]] && mode=0755
  inline "$EMHTTP/scripts/$(basename "$s")" "$s" "$mode"
done

cat <<'EOF'
<!-- Install: fetch/verify Syft and Grype (cached on flash), set up the schedule -->
<FILE Run="/bin/bash">
<INLINE>
/usr/local/emhttp/plugins/&name;/scripts/install-tools.sh || echo "WARNING: tools missing. Check network, then use 'Update tools' in Settings > SBOM Generator."
/usr/local/emhttp/plugins/&name;/scripts/apply.sh
echo ""
echo "SBOM Generator &version; installed. Configure it under Settings > Utilities > SBOM Generator."
</INLINE>
</FILE>

<!-- Remove: drop schedule, runtime files and config. Reports on your share are kept. -->
<FILE Run="/bin/bash" Method="remove">
<INLINE>
rm -f /boot/config/plugins/&name;/&name;.cron
/usr/local/sbin/update_cron
rm -rf /usr/local/emhttp/plugins/&name; /usr/local/&name; /boot/config/plugins/&name;
echo "SBOM Generator removed. Existing SBOMs and reports were left in place."
</INLINE>
</FILE>

</PLUGIN>
EOF
} >"$OUT"

echo "built $OUT ($VERSION)"
