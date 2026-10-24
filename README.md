# SBOM Generator for Unraid

Generates CycloneDX SBOMs for the whole Unraid server on a schedule, scans them for known vulnerabilities, and tells you when something new shows up.

**What gets inventoried**

| SBOM | Source | Why |
|---|---|---|
| `unraid-host-os` | `/var/log/packages`, kernel, `/etc/unraid-version` | Syft and Trivy don't catalog Slackware packages, so the plugin builds this one itself. Well-known packages (OpenSSL, OpenSSH, Samba, glibc, curl, QEMU, libvirt…) get NVD CPEs so CVE matching works. |
| `unraid-host-fs` | Syft scan of `/` | Language packages and binaries outside the package database. Skips `/mnt`, `/boot`, Docker and VM storage. |
| `container-<name>` | Syft scan of each image in use | One SBOM per distinct image, stopped containers included. |

**Each run** writes to `<output>/runs/<timestamp>/` and points `<output>/latest` at it:

- `sbom/*.cdx.json`: CycloneDX 1.5 SBOMs
- `vulns/*.json`: Grype results
- `summary.md` / `summary.json`: findings tagged with CISA KEV, and marked new if they weren't in the previous run
- `scan.log`

Unraid notifications fire on new findings (alert level when a new one is critical or in KEV). With a Dependency-Track URL and API key set, every SBOM is uploaded too. Each becomes a project versioned `current`, and Dependency-Track re-evaluates it as new CVEs are published.

## Install

1. Push this repo to GitHub as `UnheardOTP/unraid-sbomgen` (or rebuild with your own URL: `PLUGIN_URL=... AUTHOR=... ./build.sh`).
2. In Unraid: **Plugins → Install Plugin**, paste the raw URL of `sbomgen.plg`.
   To test without GitHub, copy `sbomgen.plg` to the flash drive and run `plugin install /boot/config/plugins/sbomgen.plg`.
3. Configure under **Settings → Utilities → SBOM Generator**, then press **Scan now**.

The installer downloads the latest Syft and Grype releases from GitHub and verifies them against each release's SHA-256 checksums. It then caches the tarballs on the flash drive, so the tools come back after a reboot without network access. **Update tools** on the settings page checks for newer releases. The Grype database lives in the output folder, never on the flash drive.

Run a scan from a terminal with `/usr/local/emhttp/plugins/sbomgen/scripts/sbomgen-scan.sh`.

## Development

Edit files under `src/`, then run `./build.sh` to regenerate `sbomgen.plg`. The build inlines every source file, so the `.plg` is the only file Unraid needs. Bump `VERSION` (for example `2026.10.23a`) when re-releasing on the same day, so Unraid offers the update.

## Limits

- **Host OS matching is CPE-based and best-effort.** Slackware has no purl type, so only packages in the CPE map in `host-sbom.php` can match. Grype's CPE matching for generic packages is limited. Dependency-Track matches the host SBOM against NVD more thoroughly. Extend the map for anything else you care about.
- The Unraid CPE (`lime-technology:unraid`) and kernel version are matched as reported. Unraid backports some kernel fixes, so kernel findings need a glance at Unraid's release notes before you act on them.
- VMs aren't scanned. Run Syft inside them, or point Dependency-Track at SBOMs they produce.
- x86_64 only, Unraid 6.12+.
