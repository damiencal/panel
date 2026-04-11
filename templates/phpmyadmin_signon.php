<?php
/**
 * phpMyAdmin Single Sign-On Bridge Script
 *
 * Validates an opaque one-time handle issued by the Hosting Control Panel
 * and establishes a phpMyAdmin session with the provided MySQL credentials.
 *
 * Security model:
 *   - The handle is 128-bit random, single-use, and expires in 90 seconds.
 *   - Credentials are exchanged over a loopback HTTP call; they never appear
 *     in the URL, browser history, or web-server access logs.
 *   - This script does NOT need — and does NOT read — the panel master secret.
 */

// ── 1. Read and validate the opaque handle from the URL ──────────────────────

$handle = isset($_GET['handle']) ? trim($_GET['handle']) : '';

if (empty($handle)) {
    http_response_code(400);
    die('Missing handle parameter');
}

// URL-safe base64 chars only (A-Z a-z 0-9 - _), max 64 chars.
if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/', $handle)) {
    http_response_code(400);
    die('Invalid handle format');
}

// ── 2. Exchange the handle for credentials via loopback ──────────────────────

$panel_port = getenv('PANEL_INTERNAL_PORT');
if (!$panel_port) {
    $panel_port = '3000'; // default panel listen port
}

// Bind source to 127.0.0.1 so the exchange never leaves the loopback interface.
$exchange_url = 'http://127.0.0.1:' . intval($panel_port)
    . '/api/pma-token-exchange?handle=' . rawurlencode($handle);

$ctx = stream_context_create([
    'http' => [
        'method'  => 'GET',
        'timeout' => 5,
        'ignore_errors' => true,
    ],
    'socket' => [
        'bindto' => '127.0.0.1:0',  // loopback only
    ],
]);

$body = @file_get_contents($exchange_url, false, $ctx);

if ($body === false) {
    http_response_code(503);
    die('Token exchange service unavailable');
}

// Check HTTP response code from $http_response_header.
$status_code = 200;
if (isset($http_response_header[0])) {
    if (preg_match('/HTTP\/\d+\.\d+ (\d{3})/', $http_response_header[0], $m)) {
        $status_code = intval($m[1]);
    }
}

if ($status_code !== 200) {
    // 404 = handle not found or expired; 429 = rate-limited
    http_response_code(403);
    die('Handle not found, expired, or rate-limited');
}

$creds = json_decode($body, true);

if (!$creds
    || !isset($creds['user'])
    || !isset($creds['password'])
    || !isset($creds['host'])) {
    http_response_code(503);
    die('Unexpected response from token exchange service');
}

// ── 3. Establish the phpMyAdmin signon session ───────────────────────────────

$session_name = 'PMA_single_signon';
session_name($session_name);
session_start();

$_SESSION['PMA_single_signon_user']     = $creds['user'];
$_SESSION['PMA_single_signon_password'] = $creds['password'];
$_SESSION['PMA_single_signon_host']     = $creds['host'];

if (!empty($creds['db'])) {
    $_SESSION['PMA_single_signon_db'] = $creds['db'];
}

session_write_close();

// ── 4. Redirect into phpMyAdmin ──────────────────────────────────────────────

$pma_path    = dirname($_SERVER['SCRIPT_NAME']);
$redirect_url = rtrim($pma_path, '/') . '/index.php';

header('Location: ' . $redirect_url);
exit;
