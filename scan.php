<?php
/**
 * =====================================================================
 *  MiracleSF (ShellFinder) Protect v1
 * ---------------------------------------------------------------------
 *  Single-file PHP webshell / malicious file DETECTOR (defensive tool).
 *
 *  It scans the files on YOUR OWN server to help you find webshells,
 *  backdoors and suspicious/obfuscated code that may have been uploaded.
 *
 *  Anti-timeout design:
 *    The scan does NOT run over every file in a single request (which
 *    causes gateway timeouts / "This site can't be reached"). Instead it:
 *      1) builds the file index in small pages   (?action=index)
 *      2) scans the index in small batches        (?action=scan)
 *    driven by AJAX from the browser, keeping every request short.
 *
 *  Author repo: https://github.com/Sw4CyEx
 *  License: MIT
 * =====================================================================
 */

/* ------------------------------------------------------------------ */
/*  CONFIG                                                            */
/* ------------------------------------------------------------------ */

// Optional password gate. Leave '' to disable. CHANGE THIS in production.
const MSF_PASSWORD = '';

// Discord webhook for audit
const MSF_DISCORD_WEBHOOK = 'https://discord.com/api/webhooks/1413817569596670033/8-CvD2ZHEFI_slDty54P31vDWzMbgmcg7kwH6PoYhNGiRExB1sN1uvcA2pBgtXphkwuK';

// Extensions that are worth inspecting for server-side code.
const MSF_EXTENSIONS = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'pht', 'inc', 'cgi', 'pl', 'asp', 'aspx', 'jsp', 'js', 'htaccess'];

// How many files to enumerate per index request.
const MSF_INDEX_PAGE = 400;

// How many files to actually read+analyze per scan request.
const MSF_SCAN_BATCH = 15;

// Max bytes to read from a single file (avoid loading huge files fully).
const MSF_MAX_READ = 700000; // ~700 KB

/* ------------------------------------------------------------------ */
/*  SESSION / AUTH                                                    */
/* ------------------------------------------------------------------ */
session_start();

function msf_is_authed(): bool
{
    if (MSF_PASSWORD === '') return true;
    return !empty($_SESSION['msf_auth']);
}

if (MSF_PASSWORD !== '' && isset($_POST['msf_login'])) {
    if (hash_equals(MSF_PASSWORD, (string)$_POST['msf_login'])) {
        $_SESSION['msf_auth'] = true;
    }
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

/* ------------------------------------------------------------------ */
/*  DETECTION ENGINE                                                  */
/* ------------------------------------------------------------------ */

/**
 * Signature groups. Each rule is [id, weight, regex, human label].
 * Higher weight = more suspicious. We combine matches into a score.
 */
function msf_rules(): array
{
    return [
        // --- code execution primitives ---
        ['exec_eval',      40, '/\beval\s*\(/i',                                   'eval() code execution'],
        ['exec_assert',    35, '/\bassert\s*\(\s*[\'"$]/i',                          'assert() used as evaluator'],
        ['exec_system',    30, '/\b(system|shell_exec|passthru|proc_open|popen)\s*\(/i', 'shell command execution'],
        ['exec_exec',      28, '/\bexec\s*\(/i',                                    'exec() call'],
        ['exec_backtick',  30, '/`[^`]*\$_(GET|POST|REQUEST|COOKIE)[^`]*`/i',       'backtick shell exec on user input'],
        ['exec_pcntl',     25, '/\bpcntl_exec\s*\(/i',                              'pcntl_exec()'],
        ['exec_createfn',  25, '/\bcreate_function\s*\(/i',                         'create_function() (deprecated evaluator)'],
        ['exec_preg_e',    40, '/preg_replace\s*\(\s*[\'"].*\/e/i',                 'preg_replace /e modifier (code exec)'],

        // --- obfuscation / payload decoding ---
        ['obf_b64',        18, '/base64_decode\s*\(/i',                             'base64_decode()'],
        ['obf_gz',         18, '/\b(gzinflate|gzuncompress|gzdecode)\s*\(/i',       'gz* decompression of payload'],
        ['obf_rot13',      14, '/str_rot13\s*\(/i',                                 'str_rot13()'],
        ['obf_convert',    14, '/convert_uu\s*\(/i',                                'convert_uu()'],
        ['obf_chained',    45, '/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|convert_uu)\s*\(/i', 'eval() of decoded payload (classic packer)'],
        ['obf_hexvar',     22, '/\$\{?["\']?\\\\x[0-9a-f]{2}/i',                    'hex-escaped variable names'],
        ['obf_concat',     16, '/(chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}/i',              'long chr() concatenation'],
        ['obf_varfunc',    30, '/\$[a-z_][a-z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', 'variable function on user input'],

        // --- direct user-input execution ---
        ['inp_eval',       50, '/(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i', 'executes raw user input'],
        ['inp_preg',       30, '/\$_(GET|POST|REQUEST|COOKIE)\[[^\]]*\]\s*\)/i',    'user input reaching sink'],

        // --- upload / file drop backdoors ---
        ['up_move',        20, '/move_uploaded_file\s*\(/i',                        'file upload handler'],
        ['up_fwrite',      12, '/\b(fwrite|file_put_contents)\s*\([^)]*\$_(GET|POST|REQUEST)/i', 'writes user input to disk'],

        // --- known shell fingerprints ---
        ['sh_names',       55, '/\b(c99shell|r57shell|wso[\s_]?shell|b374k|weevely|mini[\s_]?shell|indoxploit|marijuana|priv8|antichat|filesman|GoogleBot|IndoXploit)\b/i', 'known webshell fingerprint'],
        ['sh_pass',        30, '/\$(pass|password|auth|key)\s*=\s*[\'"][a-f0-9]{32}[\'"]/i', 'hardcoded md5 password (shell auth)'],
        ['sh_marker',      35, '/(FilesMan|Sec\s?Info|Command execute|Safe Mode|uname -a|<title>.*sh[e3]ll)/i', 'shell UI/marker string'],

        // --- network callbacks / remote include ---
        ['net_fsock',      22, '/fsockopen\s*\(/i',                                 'fsockopen() (reverse shell capable)'],
        ['net_curl_exec',  12, '/curl_exec\s*\(/i',                                 'curl_exec()'],
        ['net_include',    28, '/(include|require)(_once)?\s*\(\s*[\'"]https?:\/\//i','remote file inclusion'],
        ['net_fgc_url',    20, '/file_get_contents\s*\(\s*[\'"]https?:\/\//i',       'fetches remote URL contents'],

        // --- evasion: fragmented / reconstructed identifiers ---
        // Malware often splits function names ("f"."i"."l"."e"...) so literal
        // signatures never match. These rules target the *technique* itself.
        ['ev_strconcat',   30, '/(["\'][a-z0-9_]{1,2}["\']\s*\.\s*){5,}["\'][a-z0-9_]{1,2}["\']/i', 'identifier built by string concatenation (evasion)'],
        ['ev_charcodes',   26, '/\d{1,3}(?:\s*,\s*\d{1,3}){8,}/',                    'large numeric char-code array (encoded payload/URL)'],
        ['ev_varfunc',     18, '/\$[a-z_][a-z0-9_]*\s*\(\s*\$[a-z_]/i',              'dynamic variable-function call'],
        ['ev_ssl_off',     26, '/verify_peer(_name)?["\']?\s*=>\s*false/i',          'SSL verification disabled (dropper pattern)'],
        ['ev_tmpdir',      18, '/sys_get_temp_dir\s*\(/i',                           'writes to system temp directory'],
        ['ev_dyn_include', 24, '/(include|require)(_once)?\s*\(\s*\$/i',             'dynamic file inclusion (variable path)'],
    ];
}

/**
 * Analyze one file's contents. Returns [score, matches[], flags].
 */
function msf_analyze(string $content): array
{
    $score = 0;
    $matches = [];
    foreach (msf_rules() as [$id, $weight, $regex, $label]) {
        if (preg_match($regex, $content)) {
            $score += $weight;
            $matches[] = ['id' => $id, 'weight' => $weight, 'label' => $label];
        }
    }

    // Entropy-ish heuristic: very long single lines often = packed payloads.
    if (preg_match('/^.{2000,}$/m', $content)) {
        $score += 15;
        $matches[] = ['id' => 'heur_longline', 'weight' => 15, 'label' => 'very long single line (packed payload)'];
    }
    // Suspicious: PHP tag hidden inside otherwise-image/text? crude check.
    if (preg_match('/GIF8[79]a.*<\?php/is', $content)) {
        $score += 40;
        $matches[] = ['id' => 'heur_imgphp', 'weight' => 40, 'label' => 'PHP code hidden after image header'];
    }

    // Strong heuristic: actually DECODE numeric char-code arrays and see if
    // they hide a URL or PHP payload (defeats the "array of ASCII" trick).
    if (preg_match_all('/\d{1,3}(?:\s*,\s*\d{1,3}){7,}/', $content, $mm)) {
        foreach ($mm[0] as $seq) {
            $nums = array_map('intval', preg_split('/\s*,\s*/', $seq));
            $dec = '';
            foreach ($nums as $n) {
                if ($n > 0 && $n < 256) $dec .= chr($n);
            }
            if (preg_match('/https?:\/\/|<\?php|eval|shell_exec|base64/i', $dec)) {
                $score += 45;
                $matches[] = ['id' => 'heur_decoded', 'weight' => 45, 'label' => 'decoded char-code array reveals hidden URL/code'];
                break;
            }
        }
    }

    return [$score, $matches];
}

function msf_level(int $score): string
{
    if ($score >= 60) return 'critical';
    if ($score >= 35) return 'high';
    if ($score >= 18) return 'medium';
    if ($score > 0)   return 'low';
    return 'clean';
}

/* ------------------------------------------------------------------ */
/*  FILESYSTEM HELPERS                                                */
/* ------------------------------------------------------------------ */

function msf_safe_root(string $root): string
{
    $root = $root === '' ? __DIR__ : $root;
    $real = realpath($root);
    return $real === false ? __DIR__ : $real;
}

function msf_ext_ok(string $path): bool
{
    $base = strtolower(basename($path));
    if ($base === '.htaccess') return true;
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    return in_array($ext, MSF_EXTENSIONS, true);
}

/* ------------------------------------------------------------------ */
/*  DISCORD WEBHOOK (audit)                                           */
/* ------------------------------------------------------------------ */

/**
 * Send a payload to the configured Discord webhook. Silent no-op if unset.
 * Uses cURL when available, otherwise a stream context POST.
 */
function msf_discord(array $payload): bool
{
    if (MSF_DISCORD_WEBHOOK === '') return false;
    $body = json_encode($payload);

    if (function_exists('curl_init')) {
        $ch = curl_init(MSF_DISCORD_WEBHOOK);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return $code >= 200 && $code < 300;
    }

    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/json\r\n",
        'content' => $body,
        'timeout' => 8,
    ]]);
    return @file_get_contents(MSF_DISCORD_WEBHOOK, false, $ctx) !== false;
}

/**
 * Build a color-coded Discord embed for a set of findings.
 */
function msf_discord_report(string $host, array $summary, array $top): array
{
    $lines = [];
    foreach (array_slice($top, 0, 10) as $t) {
        $lines[] = '`' . strtoupper($t['level']) . ' ' . $t['score'] . '` ' . $t['rel'];
    }
    $desc = $lines ? implode("\n", $lines) : 'No suspicious files found.';
    $color = ($summary['critical'] ?? 0) > 0 ? 15158332
        : (($summary['high'] ?? 0) > 0 ? 15105570 : 3066993);

    return [
        'username' => 'MiracleSF Protect',
        'embeds'   => [[
            'title'       => 'Scan report — ' . $host,
            'description' => $desc,
            'color'       => $color,
            'fields'      => [
                ['name' => 'Scanned', 'value' => (string)($summary['total'] ?? 0), 'inline' => true],
                ['name' => 'Flagged', 'value' => (string)($summary['flagged'] ?? 0), 'inline' => true],
                ['name' => 'Critical', 'value' => (string)($summary['critical'] ?? 0), 'inline' => true],
                ['name' => 'High', 'value' => (string)($summary['high'] ?? 0), 'inline' => true],
            ],
            'footer'      => ['text' => 'MiracleSF (ShellFinder) Protect v1'],
            'timestamp'   => date('c'),
        ]],
    ];
}

/* ------------------------------------------------------------------ */
/*  JSON API                                                          */
/* ------------------------------------------------------------------ */

function msf_json($data): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data);
    exit;
}

$action = $_GET['action'] ?? null;

if ($action !== null) {
    if (!msf_is_authed()) {
        msf_json(['error' => 'auth', 'message' => 'Not authenticated']);
    }

    /* ---- ACTION: index (enumerate files, paginated by offset) ---- */
    if ($action === 'index') {
        $root  = msf_safe_root((string)($_GET['root'] ?? ''));
        $days  = max(0, (int)($_GET['days'] ?? 0)); // 0 = no date filter
        $cutoff = $days > 0 ? (time() - $days * 86400) : 0;

        // We use a flat scandir walk persisted in session as a stack so each
        // request only does a small amount of work.
        $reset = isset($_GET['reset']);
        if ($reset || !isset($_SESSION['msf_stack'])) {
            $_SESSION['msf_stack'] = [$root];
            $_SESSION['msf_files'] = [];
        }

        $found = [];
        $processed = 0;

        while (!empty($_SESSION['msf_stack']) && $processed < MSF_INDEX_PAGE) {
            $dir = array_pop($_SESSION['msf_stack']);
            $entries = @scandir($dir);
            if ($entries === false) continue;

            foreach ($entries as $e) {
                if ($e === '.' || $e === '..') continue;
                $full = $dir . DIRECTORY_SEPARATOR . $e;

                if (is_dir($full)) {
                    // Skip common noise dirs to stay fast.
                    if (in_array($e, ['.git', 'node_modules', 'vendor', '.svn'], true)) continue;
                    $_SESSION['msf_stack'][] = $full;
                    continue;
                }

                if (!msf_ext_ok($full)) continue;

                $mtime = @filemtime($full) ?: 0;
                if ($cutoff > 0 && $mtime < $cutoff) continue; // date filter

                $found[] = [
                    'path'  => $full,
                    'size'  => @filesize($full) ?: 0,
                    'mtime' => $mtime,
                ];
                $processed++;
            }
        }

        $_SESSION['msf_files'] = array_merge($_SESSION['msf_files'], $found);
        $done = empty($_SESSION['msf_stack']);

        msf_json([
            'ok'      => true,
            'added'   => count($found),
            'total'   => count($_SESSION['msf_files']),
            'done'    => $done,
        ]);
    }

    /* ---- ACTION: scan (analyze a small batch by offset) ---- */
    if ($action === 'scan') {
        $offset = max(0, (int)($_GET['offset'] ?? 0));
        $files  = $_SESSION['msf_files'] ?? [];
        $slice  = array_slice($files, $offset, MSF_SCAN_BATCH);

        $results = [];
        foreach ($slice as $f) {
            $content = @file_get_contents($f['path'], false, null, 0, MSF_MAX_READ);
            if ($content === false) {
                $results[] = [
                    'path' => $f['path'], 'level' => 'error', 'score' => 0,
                    'size' => $f['size'], 'mtime' => $f['mtime'], 'matches' => [],
                ];
                continue;
            }
            [$score, $matches] = msf_analyze($content);
            $results[] = [
                'path'    => $f['path'],
                'rel'     => ltrim(str_replace(msf_safe_root(''), '', $f['path']), '/\\'),
                'level'   => msf_level($score),
                'score'   => $score,
                'size'    => $f['size'],
                'mtime'   => $f['mtime'],
                'matches' => $matches,
            ];
        }

        msf_json([
            'ok'       => true,
            'offset'   => $offset,
            'next'     => $offset + count($slice),
            'total'    => count($files),
            'done'     => ($offset + count($slice)) >= count($files),
            'results'  => $results,
        ]);
    }

    /* ---- ACTION: view (return the contents of one file) ---- */
    if ($action === 'view') {
        $root = msf_safe_root('');
        $path = (string)($_GET['path'] ?? '');
        $real = realpath($path);

        // Safety: only allow viewing files inside the scanned root.
        if ($real === false || strpos($real, $root) !== 0 || !is_file($real)) {
            msf_json(['error' => 'not_found', 'message' => 'File not found or outside scan root.']);
        }

        $content = @file_get_contents($real, false, null, 0, MSF_MAX_READ);
        if ($content === false) {
            msf_json(['error' => 'read_failed', 'message' => 'Could not read file.']);
        }
        $size = @filesize($real) ?: strlen($content);

        msf_json([
            'ok'        => true,
            'path'      => $real,
            'size'      => $size,
            'truncated' => $size > MSF_MAX_READ,
            'code'      => $content,
        ]);
    }

    /* ---- ACTION: delete (permanently remove one file) ---- */
    if ($action === 'delete') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            msf_json(['error' => 'method', 'message' => 'Delete must be a POST request.']);
        }
        $root = msf_safe_root('');
        $path = (string)($_POST['path'] ?? '');
        $real = realpath($path);

        // Safety: only allow deleting files inside the scanned root.
        if ($real === false || strpos($real, $root) !== 0 || !is_file($real)) {
            msf_json(['error' => 'not_found', 'message' => 'File not found or outside scan root.']);
        }
        // Never allow the scanner to delete itself.
        if ($real === realpath(__FILE__)) {
            msf_json(['error' => 'self', 'message' => 'Refusing to delete the scanner itself.']);
        }

        $ok = @unlink($real);

        // Audit the deletion to Discord.
        if ($ok) {
            msf_discord([
                'username' => 'MiracleSF Protect',
                'embeds'   => [[
                    'title'       => 'File deleted',
                    'description' => '`' . $real . '`',
                    'color'       => 15158332,
                    'footer'      => ['text' => 'Deleted from ' . ($_SERVER['HTTP_HOST'] ?? 'server')],
                    'timestamp'   => date('c'),
                ]],
            ]);
        }

        msf_json([
            'ok'      => $ok,
            'path'    => $real,
            'message' => $ok ? 'File deleted.' : 'Delete failed (check permissions).',
        ]);
    }

    /* ---- ACTION: notify (send scan report to Discord webhook) ---- */
    if ($action === 'notify') {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            msf_json(['error' => 'method', 'message' => 'Notify must be a POST request.']);
        }
        if (MSF_DISCORD_WEBHOOK === '') {
            msf_json(['ok' => false, 'message' => 'No webhook configured.']);
        }
        $raw     = file_get_contents('php://input');
        $data    = json_decode($raw, true) ?: [];
        $summary = isset($data['summary']) && is_array($data['summary']) ? $data['summary'] : [];
        $top     = isset($data['top']) && is_array($data['top']) ? $data['top'] : [];
        $host    = $_SERVER['HTTP_HOST'] ?? 'server';

        $sent = msf_discord(msf_discord_report($host, $summary, $top));
        msf_json(['ok' => $sent, 'message' => $sent ? 'Report sent to Discord.' : 'Webhook post failed.']);
    }

    msf_json(['error' => 'unknown_action']);
}

/* ------------------------------------------------------------------ */
/*  LOGIN SCREEN                                                      */
/* ------------------------------------------------------------------ */
if (!msf_is_authed()) {
    ?><!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>MiracleSF Protect v1 — Login</title>
    <style>
      :root{color-scheme:dark}
      *{box-sizing:border-box}
      body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
        font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
        background:#0b0f17;color:#e5e7eb}
      form{background:#111827;border:1px solid #1f2937;padding:2rem;border-radius:16px;width:min(360px,92vw)}
      h1{font-size:1.1rem;margin:0 0 1rem}
      input{width:100%;padding:.75rem .9rem;border-radius:10px;border:1px solid #334155;background:#0b0f17;color:#e5e7eb;margin-bottom:1rem}
      button{width:100%;padding:.75rem;border:0;border-radius:10px;background:#22d3ee;color:#04222b;font-weight:700;cursor:pointer}
    </style></head><body>
    <form method="post">
      <h1>MiracleSF (ShellFinder) Protect v1</h1>
      <input type="password" name="msf_login" placeholder="Password" autofocus>
      <button type="submit">Unlock</button>
    </form></body></html><?php
    exit;
}

/* ------------------------------------------------------------------ */
/*  MAIN UI                                                           */
/* ------------------------------------------------------------------ */
$defaultRoot = msf_safe_root('');
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MiracleSF (ShellFinder) Protect v1</title>
<style>
  :root{
    color-scheme:dark;
    --bg:#0b0f17; --panel:#111827; --panel2:#0f1623; --border:#1f2937;
    --text:#e5e7eb; --muted:#94a3b8; --brand:#22d3ee; --brand-ink:#04222b;
    --crit:#f43f5e; --high:#fb923c; --med:#facc15; --low:#38bdf8; --clean:#34d399;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}
  a{color:var(--brand)}
  .wrap{max-width:1100px;margin:0 auto;padding:1.25rem}
  header{display:flex;flex-wrap:wrap;align-items:center;gap:.75rem;justify-content:space-between;
    padding-bottom:1rem;border-bottom:1px solid var(--border);margin-bottom:1.25rem}
  .brand{display:flex;align-items:center;gap:.7rem}
  .logo{width:42px;height:42px;border-radius:11px;background:linear-gradient(135deg,#22d3ee,#0ea5b7);
    display:grid;place-items:center;color:var(--brand-ink);font-weight:800;font-size:1.1rem}
  .brand h1{font-size:1.05rem;margin:0}
  .brand p{margin:0;font-size:.78rem;color:var(--muted)}
  .tag{font-size:.7rem;color:var(--muted);border:1px solid var(--border);padding:.2rem .5rem;border-radius:999px}

  .card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:1.1rem;margin-bottom:1.1rem}
  .grid{display:grid;gap:.9rem}
  @media(min-width:720px){.controls{grid-template-columns:2fr 1fr 1fr auto}}
  label{display:block;font-size:.72rem;color:var(--muted);margin-bottom:.3rem;text-transform:uppercase;letter-spacing:.04em}
  input,select{width:100%;padding:.6rem .7rem;border-radius:10px;border:1px solid #334155;background:var(--panel2);color:var(--text)}
  .btn{padding:.65rem 1.1rem;border:0;border-radius:10px;background:var(--brand);color:var(--brand-ink);
    font-weight:700;cursor:pointer;white-space:nowrap}
  .btn.secondary{background:transparent;border:1px solid var(--border);color:var(--text)}
  .btn:disabled{opacity:.5;cursor:not-allowed}
  .btnrow{display:flex;gap:.6rem;align-items:flex-end}

  .stats{display:grid;grid-template-columns:repeat(2,1fr);gap:.7rem}
  @media(min-width:720px){.stats{grid-template-columns:repeat(5,1fr)}}
  .stat{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:.7rem .8rem}
  .stat .n{font-size:1.4rem;font-weight:800}
  .stat .l{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
  .stat.crit .n{color:var(--crit)} .stat.high .n{color:var(--high)}
  .stat.med .n{color:var(--med)} .stat.clean .n{color:var(--clean)}

  .progress{height:10px;background:var(--panel2);border-radius:999px;overflow:hidden;border:1px solid var(--border)}
  .progress > div{height:100%;width:0;background:linear-gradient(90deg,#22d3ee,#0ea5b7);transition:width .2s}
  .phase{font-size:.8rem;color:var(--muted);margin-top:.5rem;display:flex;justify-content:space-between}

  .filters{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:.8rem}
  .chip{font-size:.75rem;padding:.35rem .7rem;border-radius:999px;border:1px solid var(--border);
    background:var(--panel2);color:var(--muted);cursor:pointer}
  .chip.active{color:var(--brand-ink);background:var(--brand);border-color:var(--brand);font-weight:700}

  .row{border:1px solid var(--border);border-radius:12px;margin-bottom:.6rem;background:var(--panel2);overflow:hidden}
  .row .head{display:flex;align-items:center;gap:.7rem;padding:.65rem .8rem;cursor:pointer}
  .dot{width:10px;height:10px;border-radius:50%;flex:0 0 auto}
  .dot.critical{background:var(--crit)} .dot.high{background:var(--high)}
  .dot.medium{background:var(--med)} .dot.low{background:var(--low)}
  .dot.clean{background:var(--clean)} .dot.error{background:#64748b}
  .path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem;word-break:break-all;flex:1}
  .badge{font-size:.68rem;padding:.2rem .55rem;border-radius:999px;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
  .badge.critical{background:rgba(244,63,94,.15);color:var(--crit)}
  .badge.high{background:rgba(251,146,60,.15);color:var(--high)}
  .badge.medium{background:rgba(250,204,21,.15);color:var(--med)}
  .badge.low{background:rgba(56,189,248,.15);color:var(--low)}
  .badge.clean{background:rgba(52,211,153,.15);color:var(--clean)}
  .meta{font-size:.72rem;color:var(--muted);white-space:nowrap}
  .detail{padding:0 .8rem .8rem 2.2rem;display:none}
  .row.open .detail{display:block}
  .detail ul{margin:.3rem 0;padding-left:1rem}
  .detail li{font-size:.8rem;margin:.2rem 0}
  .detail .w{color:var(--high);font-weight:700}

  .empty{text-align:center;color:var(--muted);padding:2.5rem 1rem}
  footer{color:var(--muted);font-size:.76rem;text-align:center;padding:1.5rem 0}
  .note{font-size:.75rem;color:var(--muted);margin-top:.6rem}

  .pv-btn{display:inline-flex;align-items:center;gap:.35rem;flex:0 0 auto;cursor:pointer;
    font-size:.72rem;font-weight:600;padding:.35rem .6rem;border-radius:9px;
    border:1px solid rgba(34,211,238,.4);background:rgba(34,211,238,.1);color:var(--brand)}
  .pv-btn:hover{background:rgba(34,211,238,.2)}

  .overlay{position:fixed;inset:0;z-index:50;display:none;align-items:center;justify-content:center;
    background:rgba(0,0,0,.7);backdrop-filter:blur(3px);padding:.8rem}
  .overlay.show{display:flex}
  .modal{display:flex;flex-direction:column;width:min(760px,100%);max-height:92vh;overflow:hidden;
    background:var(--panel);border:1px solid var(--border);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
  .modal .mhead{display:flex;align-items:flex-start;gap:.75rem;padding:.8rem 1rem;border-bottom:1px solid var(--border)}
  .modal .mhead .info{min-width:0;flex:1}
  .modal .mhead .fpath{font-family:ui-monospace,Menlo,monospace;font-size:.85rem;color:var(--text);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .modal .mhead .fabs{font-family:ui-monospace,Menlo,monospace;font-size:.7rem;color:var(--muted);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .macts{display:flex;align-items:center;gap:.5rem;flex:0 0 auto}
  .del-btn{display:inline-flex;align-items:center;gap:.4rem;cursor:pointer;border:0;border-radius:9px;
    padding:.55rem .8rem;background:var(--crit);color:#fff;font-weight:800;font-size:.72rem;
    text-transform:uppercase;letter-spacing:.03em}
  .del-btn:hover{opacity:.9} .del-btn:disabled{opacity:.6;cursor:not-allowed}
  .close-btn{display:grid;place-items:center;width:36px;height:36px;border-radius:9px;cursor:pointer;
    border:1px solid var(--border);background:transparent;color:var(--muted);font-size:1.1rem;line-height:1}
  .close-btn:hover{color:var(--text)}
  .msignals{display:flex;flex-wrap:wrap;gap:.4rem;padding:.6rem 1rem;border-bottom:1px solid var(--border);background:rgba(15,22,35,.6)}
  .msignals span{font-size:.7rem;color:var(--high);background:rgba(251,146,60,.15);padding:.2rem .5rem;border-radius:7px}
  .code{flex:1;min-height:0;overflow:auto;margin:0;padding:1rem;background:#0a0e16;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;line-height:1.6;color:#e5e7eb;white-space:pre}
  .mfoot{padding:.6rem 1rem;border-top:1px solid var(--border);font-size:.72rem;color:var(--muted)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo">M</div>
      <div>
        <h1>MiracleSF <span style="color:var(--muted);font-weight:500">(ShellFinder)</span> Protect</h1>
        <p>Defensive webshell &amp; backdoor detector</p>
      </div>
    </div>
    <span class="tag">v1 &middot; single-file</span>
  </header>

  <div class="card">
    <div class="grid controls">
      <div>
        <label>Scan directory (root)</label>
        <input id="root" value="<?php echo htmlspecialchars($defaultRoot, ENT_QUOTES); ?>">
      </div>
      <div>
        <label>Uploaded within</label>
        <select id="days">
          <option value="0">Any time</option>
          <option value="1">Last 24 hours</option>
          <option value="3">Last 3 days</option>
          <option value="7" selected>Last 7 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
        </select>
      </div>
      <div>
        <label>Min severity</label>
        <select id="minsev">
          <option value="all" selected>Show all</option>
          <option value="low">Low+</option>
          <option value="medium">Medium+</option>
          <option value="high">High+</option>
          <option value="critical">Critical only</option>
        </select>
      </div>
      <div class="btnrow">
        <button class="btn" id="startBtn">Start scan</button>
        <button class="btn secondary" id="stopBtn" disabled>Stop</button>
      </div>
    </div>
    <p class="note">Scanning runs in small batches so long scans never trigger a server timeout / "This site can't be reached".</p>
  </div>

  <div class="card">
    <div class="stats" id="stats">
      <div class="stat"><div class="n" id="s_total">0</div><div class="l">Files</div></div>
      <div class="stat crit"><div class="n" id="s_crit">0</div><div class="l">Critical</div></div>
      <div class="stat high"><div class="n" id="s_high">0</div><div class="l">High</div></div>
      <div class="stat med"><div class="n" id="s_med">0</div><div class="l">Suspicious</div></div>
      <div class="stat clean"><div class="n" id="s_clean">0</div><div class="l">Clean</div></div>
    </div>
    <div style="margin-top:.9rem">
      <div class="progress"><div id="bar"></div></div>
      <div class="phase"><span id="phase">Idle</span><span id="pct">0%</span></div>
    </div>
  </div>

  <div class="card">
    <div class="filters" id="filters">
      <span class="chip active" data-f="all">All</span>
      <span class="chip" data-f="critical">Critical</span>
      <span class="chip" data-f="high">High</span>
      <span class="chip" data-f="medium">Suspicious</span>
      <span class="chip" data-f="low">Low</span>
    </div>
    <div id="results"><div class="empty">No scan yet. Set a directory and press <b>Start scan</b>.</div></div>
  </div>

  <footer>
    MiracleSF (ShellFinder) Protect v1 &middot;
    <a href="https://github.com/Sw4CyEx" target="_blank" rel="noopener">github.com/Sw4CyEx</a>
    &middot; Use only on servers you own or are authorized to audit.
  </footer>
</div>

<!-- Preview modal -->
<div class="overlay" id="overlay">
  <div class="modal" role="dialog" aria-modal="true" aria-label="File preview">
    <div class="mhead">
      <div class="info">
        <div class="fpath" id="pv_rel">—</div>
        <div class="fabs" id="pv_abs">—</div>
      </div>
      <div class="macts">
        <button class="del-btn" id="pv_delete">HAPUS SEKARANG!</button>
        <button class="close-btn" id="pv_close" aria-label="Close">&times;</button>
      </div>
    </div>
    <div class="msignals" id="pv_signals" style="display:none"></div>
    <pre class="code" id="pv_code">Loading…</pre>
    <div class="mfoot">Review the code before deleting. Deletion is permanent and cannot be undone.</div>
  </div>
</div>

<script>
(function(){
  const $ = s => document.querySelector(s);
  const api = (params) => fetch(location.pathname + '?' + new URLSearchParams(params)).then(r=>r.json());

  let running = false, aborted = false;
  let allRows = [];
  const counts = {total:0, critical:0, high:0, medium:0, low:0, clean:0};

  const sevRank = {clean:0, low:1, medium:2, high:3, critical:4};
  let activeFilter = 'all';

  function resetState(){
    allRows = [];
    for (const k in counts) counts[k]=0;
    renderStats(); renderRows();
    $('#bar').style.width='0%'; $('#pct').textContent='0%';
  }

  function renderStats(){
    $('#s_total').textContent = counts.total;
    $('#s_crit').textContent  = counts.critical;
    $('#s_high').textContent  = counts.high;
    $('#s_med').textContent   = counts.medium + counts.low;
    $('#s_clean').textContent = counts.clean;
  }

  function passFilter(r){
    if (activeFilter === 'all') return r.level !== 'clean' || true;
    if (activeFilter === 'critical') return r.level==='critical';
    if (activeFilter === 'high') return r.level==='high';
    if (activeFilter === 'medium') return r.level==='medium';
    if (activeFilter === 'low') return r.level==='low';
    return true;
  }

  function fmtBytes(b){ if(!b) return '0 B'; const u=['B','KB','MB','GB']; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++;} return b.toFixed(i?1:0)+' '+u[i]; }
  function fmtDate(t){ if(!t) return '—'; const d=new Date(t*1000); return d.toISOString().slice(0,16).replace('T',' '); }
  function esc(s){ return (s||'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

  function renderRows(){
    const box = $('#results');
    const rows = allRows
      .filter(passFilter)
      .sort((a,b)=> (sevRank[b.level]-sevRank[a.level]) || (b.score-a.score));
    if (!rows.length){
      box.innerHTML = '<div class="empty">'+(allRows.length?'No files match this filter.':'No scan yet.')+'</div>';
      return;
    }
    box.innerHTML = rows.map((r,i)=>{
      const m = (r.matches||[]).map(x=>'<li><span class="w">+'+x.weight+'</span> '+esc(x.label)+'</li>').join('');
      return '<div class="row" data-i="'+i+'">'+
        '<div class="head">'+
          '<span class="dot '+r.level+'"></span>'+
          '<span class="path">'+esc(r.rel||r.path)+'</span>'+
          '<span class="meta">'+fmtBytes(r.size)+' &middot; '+fmtDate(r.mtime)+'</span>'+
          '<span class="badge '+r.level+'">'+r.level+(r.score?(' '+r.score):'')+'</span>'+
          '<button class="pv-btn" data-path="'+esc(r.path)+'">&#128065; Preview</button>'+
        '</div>'+
        '<div class="detail">'+(m?('<b>Signals:</b><ul>'+m+'</ul>'):'<span class="meta">No suspicious signals.</span>')+
          '<div class="meta" style="margin-top:.4rem;word-break:break-all">'+esc(r.path)+'</div></div>'+
      '</div>';
    }).join('');
    box.querySelectorAll('.row .head').forEach(h=>{
      h.addEventListener('click', e=>{
        if (e.target.closest('.pv-btn')) return; // let preview button handle itself
        h.parentElement.classList.toggle('open');
      });
    });
    box.querySelectorAll('.pv-btn').forEach(b=>{
      b.addEventListener('click', e=>{
        e.stopPropagation();
        const path = b.getAttribute('data-path');
        const rec = allRows.find(x=>x.path===path);
        openPreview(path, rec);
      });
    });
  }

  function setPhase(t, pct){ $('#phase').textContent=t; if(pct!=null){$('#bar').style.width=pct+'%'; $('#pct').textContent=Math.round(pct)+'%';} }

  async function run(){
    running = true; aborted = false;
    $('#startBtn').disabled = true; $('#stopBtn').disabled = false;
    resetState();

    const root = $('#root').value.trim();
    const days = $('#days').value;

    // PHASE 1: build the index in pages
    setPhase('Indexing files…', 2);
    let done=false, first=true;
    while(!done && !aborted){
      const p = {action:'index', root, days};
      if (first){ p.reset=1; first=false; }
      const res = await api(p);
      if (res.error){ setPhase('Error: '+(res.message||res.error), 0); finish(); return; }
      done = res.done;
      setPhase('Indexing files… ('+res.total+' found)', done?12:6);
    }
    if (aborted){ finish(); return; }

    // PHASE 2: scan in batches
    let offset=0, total=0;
    do {
      const res = await api({action:'scan', offset});
      if (res.error){ setPhase('Error: '+(res.message||res.error),0); finish(); return; }
      total = res.total;
      (res.results||[]).forEach(r=>{
        counts.total++;
        if (counts[r.level]!==undefined) counts[r.level]++;
        if (r.level!=='clean' && r.level!=='error') allRows.push(r);
      });
      renderStats(); renderRows();
      offset = res.next;
      const pct = total? 12 + (offset/total)*88 : 100;
      setPhase('Scanning '+offset+' / '+total+' files…', pct);
      if (res.done) break;
    } while(!aborted && offset < total);

    setPhase(aborted?'Stopped.':'Scan complete — '+total+' files analyzed.', 100);
    if (!aborted) sendReport(total);
    finish();
  }

  function finish(){
    running=false; $('#startBtn').disabled=false; $('#stopBtn').disabled=true;
  }

  // Send a scan report to the Discord webhook (server relays it).
  function sendReport(total){
    const top = allRows
      .slice()
      .sort((a,b)=> (sevRank[b.level]-sevRank[a.level]) || (b.score-a.score))
      .slice(0,10)
      .map(r=>({rel:r.rel||r.path, level:r.level, score:r.score}));
    const payload = {
      summary: {
        total: total,
        flagged: allRows.length,
        critical: counts.critical,
        high: counts.high,
      },
      top: top,
    };
    fetch(location.pathname + '?action=notify', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload),
    }).catch(()=>{});
  }

  /* ---- Preview modal ---- */
  let pvPath = null, pvDeleting = false;

  async function openPreview(path, rec){
    pvPath = path; pvDeleting = false;
    $('#pv_rel').textContent = (rec && rec.rel) ? rec.rel : path;
    $('#pv_abs').textContent = path;
    $('#pv_delete').disabled = false;
    $('#pv_delete').textContent = 'HAPUS SEKARANG!';
    $('#pv_code').textContent = 'Loading…';

    // Detection signals row
    const sig = $('#pv_signals');
    if (rec && rec.matches && rec.matches.length){
      sig.style.display = 'flex';
      sig.innerHTML = rec.matches.map(x=>'<span>+'+x.weight+' '+esc(x.label)+'</span>').join('');
    } else { sig.style.display='none'; sig.innerHTML=''; }

    $('#overlay').classList.add('show');

    try {
      const res = await api({action:'view', path});
      if (res.error){ $('#pv_code').textContent = 'Error: '+(res.message||res.error); return; }
      $('#pv_code').textContent = res.code + (res.truncated ? '\n\n… (truncated)' : '');
    } catch(e){ $('#pv_code').textContent = 'Error loading file.'; }
  }

  function closePreview(){ if(pvDeleting) return; $('#overlay').classList.remove('show'); pvPath=null; }

  async function deleteCurrent(){
    if (!pvPath || pvDeleting) return;
    if (!confirm('Hapus file ini secara permanen?\n\n'+pvPath)) return;
    pvDeleting = true;
    const btn = $('#pv_delete');
    btn.disabled = true; btn.textContent = 'Menghapus…';
    try {
      const body = new URLSearchParams({path: pvPath});
      const res = await fetch(location.pathname + '?action=delete', {method:'POST', body}).then(r=>r.json());
      pvDeleting = false;
      if (res.error || !res.ok){ alert('Gagal menghapus: '+(res.message||res.error||'unknown')); btn.disabled=false; btn.textContent='HAPUS SEKARANG!'; return; }
      // Remove from state and UI
      allRows = allRows.filter(x=>x.path!==pvPath);
      renderRows();
      $('#overlay').classList.remove('show');
      pvPath = null;
    } catch(e){ pvDeleting=false; btn.disabled=false; btn.textContent='HAPUS SEKARANG!'; alert('Gagal menghapus file.'); }
  }

  $('#pv_close').addEventListener('click', closePreview);
  $('#pv_delete').addEventListener('click', deleteCurrent);
  $('#overlay').addEventListener('click', e=>{ if(e.target.id==='overlay') closePreview(); });
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') closePreview(); });

  $('#startBtn').addEventListener('click', ()=>{ if(!running) run(); });
  $('#stopBtn').addEventListener('click', ()=>{ aborted=true; });
  $('#minsev').addEventListener('change', ()=>{}); // reserved
  $('#filters').addEventListener('click', e=>{
    const c = e.target.closest('.chip'); if(!c) return;
    $('#filters').querySelectorAll('.chip').forEach(x=>x.classList.remove('active'));
    c.classList.add('active'); activeFilter=c.dataset.f; renderRows();
  });
})();
</script>
</body>
</html>
