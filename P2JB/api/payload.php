<?php
/* Reference handler for  POST api/payload/<name>
 * ------------------------------------------------------------------
 * The ELF tile menu cannot deliver a payload by itself: JavaScript has no raw
 * sockets, and an HTTP POST straight to the console's port 9021 would prepend
 * HTTP headers, so elfldr would not see \x7fELF at offset 0. The page therefore
 * asks the SERVER to open the TCP connection and write the file verbatim.
 *
 * The console is the one making this request, so its address is simply
 * REMOTE_ADDR - no configuration, no hardcoded IP.
 *
 * Set PS5_ALLOWED_ORIGINS to the exact page origin(s), then route
 * api/payload/<name> to this file. With Apache the .htaccess shipped alongside
 * does that. Reply is the JSON the page expects:
 *     {"ok":true,"bytes":N}
 */
header('Content-Type: application/json');

$PORT       = 9021;
$PAYLOAD_DIR = __DIR__ . '/../payloads';

function normalized_origin($value) {
    $parts = parse_url($value);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])
        || !in_array(strtolower($parts['scheme']), ['http', 'https'], true)
        || isset($parts['user']) || isset($parts['pass'])
        || (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/')
        || isset($parts['query']) || isset($parts['fragment'])) return '';
    $scheme = strtolower($parts['scheme']);
    $host = strtolower($parts['host']);
    $port = $parts['port'] ?? null;
    if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) $port = null;
    return $scheme . '://' . $host . ($port === null ? '' : ':' . $port);
}

function request_origin_is_allowed() {
    $origin = normalized_origin($_SERVER['HTTP_ORIGIN'] ?? '');
    if ($origin === '') return false;
    foreach (explode(',', getenv('PS5_ALLOWED_ORIGINS') ?: '') as $allowed) {
        if ($origin === normalized_origin(trim($allowed))) return true;
    }
    return false;
}

function path_is_within($root, $path) {
    $root = rtrim($root, DIRECTORY_SEPARATOR);
    $prefix = ($root === '' ? DIRECTORY_SEPARATOR : $root . DIRECTORY_SEPARATOR);
    return strpos($path, $prefix) === 0;
}

function fail($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    fail('method not allowed', 405);
}
if (!request_origin_is_allowed()) fail('origin not allowed', 403);

/* name comes from the URL. Accept ONLY a bare filename of the expected shape -
 * no directories, no traversal - then confirm the resolved path really is inside
 * payloads/ before opening it. */
$name = basename($_SERVER['PATH_INFO'] ?? $_GET['name'] ?? '');
if ($name === '' || !preg_match('/^[A-Za-z0-9._-]+\.(elf|bin)$/', $name))
    fail('bad payload name');

$path = realpath($PAYLOAD_DIR . '/' . $name);
$root = realpath($PAYLOAD_DIR);
if ($path === false || $root === false || !path_is_within($root, $path))
    fail('payload not found', 404);

$data = @file_get_contents($path);
if ($data === false || strlen($data) === 0) fail('payload unreadable', 404);

$ip = $_SERVER['REMOTE_ADDR'] ?? '';
if ($ip === '') fail('no client address');
if (strpos($ip, '::ffff:') === 0) $ip = substr($ip, 7);   // IPv4-mapped IPv6

$sock = @stream_socket_client("tcp://$ip:$PORT", $errno, $errstr, 5);
if (!$sock) fail("connect $ip:$PORT failed: $errstr ($errno)", 502);

stream_set_timeout($sock, 15);
$sent = 0; $len = strlen($data);
while ($sent < $len) {
    $n = @fwrite($sock, substr($data, $sent, 65536));
    if ($n === false || $n === 0) { fclose($sock); fail("write failed after $sent bytes", 502); }
    $sent += $n;
}
fclose($sock);

echo json_encode(['ok' => true, 'bytes' => $sent, 'name' => $name, 'to' => "$ip:$PORT"]);
