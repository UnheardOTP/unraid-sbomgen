<?php
// Builds a CycloneDX 1.5 SBOM for the Unraid host OS.
// Common SBOM tools don't catalog Slackware packages, so this reads them
// directly from /var/log/packages, adds the kernel and Unraid release, and
// attaches CPEs for well-known packages so CPE-based matchers
// (Dependency-Track, Grype where enabled) can find CVEs.
//
// Usage: php host-sbom.php [packages_dir] [unraid_version_file]

$pkgDir     = $argv[1] ?? '/var/log/packages';
$verFile    = $argv[2] ?? '/etc/unraid-version';
$hostname   = trim(@file_get_contents('/etc/hostname') ?: php_uname('n'));
$kernel     = php_uname('r');

// Best-effort NVD vendor:product for packages that matter most on a NAS.
// Anything not listed still appears in the SBOM, just without a CPE.
$cpeMap = [
  'openssl' => 'openssl:openssl',      'openssl-solibs' => 'openssl:openssl',
  'openssh' => 'openbsd:openssh',      'curl' => 'haxx:curl',
  'samba' => 'samba:samba',            'rsync' => 'samba:rsync',
  'php' => 'php:php',                  'glibc' => 'gnu:glibc',
  'aaa_glibc-solibs' => 'gnu:glibc',   'bash' => 'gnu:bash',
  'sudo' => 'sudo_project:sudo',       'zlib' => 'zlib:zlib',
  'xz' => 'tukaani:xz',                'sqlite' => 'sqlite:sqlite',
  'libxml2' => 'xmlsoft:libxml2',      'expat' => 'libexpat_project:libexpat',
  'qemu' => 'qemu:qemu',               'libvirt' => 'redhat:libvirt',
  'containerd' => 'linuxfoundation:containerd', 'runc' => 'linuxfoundation:runc',
  'avahi' => 'avahi:avahi',            'dnsmasq' => 'thekelleys:dnsmasq',
  'gnutls' => 'gnu:gnutls',            'libssh2' => 'libssh2:libssh2',
  'nfs-utils' => 'linux-nfs:nfs-utils', 'wget' => 'gnu:wget',
  'git' => 'git-scm:git',              'python3' => 'python:python',
  'perl' => 'perl:perl',               'busybox' => 'busybox:busybox',
];

function cpe(string $vp, string $version, string $part = 'a'): string {
  $v = preg_replace('/[^A-Za-z0-9._\-]/', '_', $version);
  return "cpe:2.3:$part:$vp:$v:*:*:*:*:*:*:*";
}

function uuid4(): string {
  $d = random_bytes(16);
  $d[6] = chr((ord($d[6]) & 0x0f) | 0x40);
  $d[8] = chr((ord($d[8]) & 0x3f) | 0x80);
  return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($d), 4));
}

// Unraid release: /etc/unraid-version contains: version="7.1.4"
$unraid = 'unknown';
if (is_readable($verFile) && preg_match('/version="?([^"\s]+)"?/', file_get_contents($verFile), $m)) {
  $unraid = $m[1];
}

$components = [];

$components[] = [
  'type' => 'operating-system', 'bom-ref' => "unraid@$unraid",
  'name' => 'unraid', 'version' => $unraid, 'supplier' => ['name' => 'Lime Technology'],
  'purl' => "pkg:generic/lime-technology/unraid@$unraid",
  'cpe' => cpe('lime-technology:unraid', $unraid, 'o'),
];

// Kernel: strip Unraid's local suffix (e.g. 6.12.24-Unraid -> 6.12.24) for matching.
$kver = preg_replace('/-.*$/', '', $kernel);
$components[] = [
  'type' => 'operating-system', 'bom-ref' => "linux-kernel@$kernel",
  'name' => 'linux-kernel', 'version' => $kver,
  'purl' => "pkg:generic/kernel.org/linux@$kver",
  'cpe' => cpe('linux:linux_kernel', $kver, 'o'),
  'properties' => [['name' => 'unraid:kernel-release', 'value' => $kernel]],
];

// Slackware packages: filename is name-version-arch-build (name may contain dashes).
$seen = [];
foreach (glob(rtrim($pkgDir, '/') . '/*') ?: [] as $f) {
  $parts = explode('-', basename($f));
  if (count($parts) < 4) continue;
  $build   = array_pop($parts);
  $arch    = array_pop($parts);
  $version = array_pop($parts);
  $name    = implode('-', $parts);
  $ref = "slackware/$name@$version";
  if (isset($seen[$ref])) continue;
  $seen[$ref] = true;

  $c = [
    'type' => 'library', 'bom-ref' => $ref, 'name' => $name, 'version' => $version,
    'purl' => 'pkg:generic/slackware/' . rawurlencode($name) . '@' . rawurlencode($version)
              . '?arch=' . rawurlencode($arch),
    'properties' => [
      ['name' => 'slackware:arch',  'value' => $arch],
      ['name' => 'slackware:build', 'value' => $build],
    ],
  ];
  if (isset($cpeMap[$name])) $c['cpe'] = cpe($cpeMap[$name], $version);
  $components[] = $c;
}

$bom = [
  'bomFormat' => 'CycloneDX',
  'specVersion' => '1.5',
  'serialNumber' => 'urn:uuid:' . uuid4(),
  'version' => 1,
  'metadata' => [
    'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
    'tools' => ['components' => [['type' => 'application', 'name' => 'unraid-sbomgen']]],
    'component' => [
      'type' => 'device', 'bom-ref' => "host:$hostname", 'name' => $hostname,
      'version' => $unraid, 'description' => "Unraid $unraid server, kernel $kernel",
    ],
  ],
  'components' => $components,
  'dependencies' => [[
    'ref' => "host:$hostname",
    'dependsOn' => array_column($components, 'bom-ref'),
  ]],
];

echo json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
