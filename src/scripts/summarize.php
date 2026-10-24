<?php
// Summarizes Grype results for one run: tags CISA KEV entries, flags findings
// that weren't in the previous run, writes summary.json + summary.md, and
// prints one line of counts for the notification.
//
// Usage: php summarize.php <run_dir> <kev.json> [previous_run_dir]

[$_, $runDir, $kevFile] = $argv + [null, null, null];
$prevDir = $argv[3] ?? '';
if (!$runDir || !is_dir($runDir)) { fwrite(STDERR, "run dir missing\n"); exit(1); }

$kev = [];
if ($kevFile && is_readable($kevFile)) {
  foreach (json_decode(file_get_contents($kevFile), true)['vulnerabilities'] ?? [] as $v) {
    $kev[$v['cveID']] = $v['dueDate'] ?? '';
  }
}

$rank = ['Critical' => 0, 'High' => 1, 'Medium' => 2, 'Low' => 3, 'Negligible' => 4, 'Unknown' => 5];
$findings = [];
foreach (glob("$runDir/vulns/*.json") ?: [] as $f) {
  $target = basename($f, '.json');
  foreach (json_decode(file_get_contents($f), true)['matches'] ?? [] as $m) {
    $v   = $m['vulnerability'];
    $ids = array_merge([$v['id']], array_column($m['relatedVulnerabilities'] ?? [], 'id'));
    $cve = current(array_filter($ids, fn($i) => str_starts_with($i, 'CVE-'))) ?: $v['id'];
    $key = "$target|{$m['artifact']['name']}|{$m['artifact']['version']}|$cve";
    if (isset($findings[$key])) continue;
    $findings[$key] = [
      'target'   => $target,
      'id'       => $cve,
      'severity' => $v['severity'] ?? 'Unknown',
      'package'  => $m['artifact']['name'],
      'version'  => $m['artifact']['version'],
      'fixed_in' => implode(', ', $v['fix']['versions'] ?? []),
      'kev'      => isset($kev[$cve]),
      'new'      => true,
    ];
  }
}

// Mark which findings existed last run.
$prevKeys = [];
if ($prevDir && is_readable("$prevDir/summary.json")) {
  foreach (json_decode(file_get_contents("$prevDir/summary.json"), true)['findings'] ?? [] as $p) {
    $prevKeys["{$p['target']}|{$p['package']}|{$p['version']}|{$p['id']}"] = true;
  }
  foreach ($findings as $k => &$fd) $fd['new'] = !isset($prevKeys[$k]);
  unset($fd);
}

$list = array_values($findings);
usort($list, fn($a, $b) =>
  [$b['kev'], $b['new'], $rank[$a['severity']] ?? 9, $a['target']] <=>
  [$a['kev'], $a['new'], $rank[$b['severity']] ?? 9, $b['target']]);

$count = fn($pred) => count(array_filter($list, $pred));
$stats = [
  'new'      => $count(fn($f) => $f['new']),
  'new_kev'  => $count(fn($f) => $f['new'] && $f['kev']),
  'new_crit' => $count(fn($f) => $f['new'] && $f['severity'] === 'Critical'),
  'critical' => $count(fn($f) => $f['severity'] === 'Critical'),
  'high'     => $count(fn($f) => $f['severity'] === 'High'),
  'kev'      => $count(fn($f) => $f['kev']),
  'total'    => count($list),
];

file_put_contents("$runDir/summary.json", json_encode(
  ['generated' => gmdate('c'), 'baseline' => $prevDir ?: null, 'stats' => $stats, 'findings' => $list],
  JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

// Markdown report: KEV and new findings first, then everything Critical/High.
$row = fn($f) => sprintf("| %s | %s | %s | %s %s | %s | %s |\n",
  $f['kev'] ? '**KEV**' : '', $f['severity'], $f['id'], $f['package'], $f['version'],
  $f['fixed_in'] ?: '-', $f['target']);
$head = "| | Severity | ID | Package | Fixed in | Target |\n|---|---|---|---|---|---|\n";

$md  = "# SBOM scan " . basename($runDir) . "\n\n";
$md .= $prevDir ? "Compared with " . basename($prevDir) . ".\n\n" : "First run, so everything counts as new.\n\n";
$md .= "New: {$stats['new']} (KEV {$stats['new_kev']}, critical {$stats['new_crit']}). ";
$md .= "Totals: {$stats['total']} findings, {$stats['critical']} critical, {$stats['high']} high, {$stats['kev']} in CISA KEV.\n\n";
$sections = [
  'Known exploited (CISA KEV)' => fn($f) => $f['kev'],
  'New since last run'         => fn($f) => $f['new'] && !$f['kev'],
  'All critical and high'      => fn($f) => !$f['new'] && !$f['kev'] && in_array($f['severity'], ['Critical', 'High']),
];
foreach ($sections as $title => $pred) {
  $rows = array_filter($list, $pred);
  $md .= "## $title (" . count($rows) . ")\n\n";
  $md .= $rows ? $head . implode('', array_map($row, $rows)) . "\n" : "None.\n\n";
}
file_put_contents("$runDir/summary.md", $md);

echo implode(' ', array_map(fn($k, $v) => "$k=$v", array_keys($stats), $stats)), "\n";
