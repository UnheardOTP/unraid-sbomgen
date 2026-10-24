<?php
// Serves files from the latest scan run to the settings page.
//   ?f=md   summary.md
//   ?f=csv  every finding as CSV (built from summary.json)
//   ?f=tgz  the whole run folder: SBOMs, Grype results, summary, log
// Only these fixed outputs are served, and only from inside <output>/runs/.

$cfg = [];
foreach (['/usr/local/emhttp/plugins/sbomgen/default.cfg', '/boot/config/plugins/sbomgen/sbomgen.cfg'] as $f) {
  if (is_readable($f)) $cfg = array_merge($cfg, parse_ini_file($f, false, INI_SCANNER_RAW) ?: []);
}
$out  = rtrim($cfg['OUTPUT_DIR'] ?? '', '/');
$runs = realpath("$out/runs");
$run  = realpath("$out/latest");

function fail(int $code, string $msg) {
  http_response_code($code);
  header('Content-Type: text/plain');
  exit($msg);
}

if (!$runs || !$run || !is_dir($run) || dirname($run) !== $runs) fail(404, 'No completed scan found.');
$name = 'sbom-' . basename($run);   // e.g. sbom-20261023-170950
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

switch ($_GET['f'] ?? '') {
  case 'md':
    if (!is_readable("$run/summary.md")) fail(404, 'This run has no report (vulnerability scanning was off).');
    header('Content-Type: text/markdown; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"$name-report.md\"");
    readfile("$run/summary.md");
    break;

  case 'csv':
    $data = json_decode((string)@file_get_contents("$run/summary.json"), true);
    if (!$data) fail(404, 'This run has no findings file (vulnerability scanning was off).');
    header('Content-Type: text/csv; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"$name-findings.csv\"");
    $o = fopen('php://output', 'w');
    fputcsv($o, ['kev', 'new', 'severity', 'id', 'package', 'version', 'fixed_in', 'target']);
    foreach ($data['findings'] ?? [] as $f) {
      fputcsv($o, [$f['kev'] ? 'yes' : '', $f['new'] ? 'yes' : '', $f['severity'], $f['id'],
                   $f['package'], $f['version'], $f['fixed_in'], $f['target']]);
    }
    fclose($o);
    break;

  case 'tgz':
    header('Content-Type: application/gzip');
    header("Content-Disposition: attachment; filename=\"$name.tar.gz\"");
    passthru('tar -czf - -C ' . escapeshellarg(dirname($run)) . ' ' . escapeshellarg(basename($run)));
    break;

  default:
    fail(400, 'Unknown download.');
}
