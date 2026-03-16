<?php
/**
 * phpMyAdmin Single Sign-On Bridge Script
 * 
 * Validates an HMAC-SHA256-signed token from the Hosting Control Panel
 * and establishes a phpMyAdmin session with the provided MySQL credentials.
 *
 * Token format: base64url(json_payload).base64url(hmac_signature)
 * Payload: {"u": mysql_user, "p": mysql_password, "d": db_name, "exp": unix_timestamp}
 *
 * The HMAC secret must match PANEL_SECRET_KEY from the panel configuration.
 */

// Load the panel secret key from environment or config
$panel_secret = getenv('PANEL_SECRET_KEY');
if (!$panel_secret) {
    // Try reading from panel.toml
    $toml_paths = [
        '/opt/panel/panel.toml',
        '/etc/panel/panel.toml',
    ];
    foreach ($toml_paths as $path) {
        if (file_exists($path)) {
            $content = file_get_contents($path);
            if (preg_match('/secret_key\s*=\s*"([^"]+)"/', $content, $matches)) {
                $panel_secret = $matches[1];
                break;
            }
        }
    }
}

if (!$panel_secret) {
    http_response_code(500);
    die('Configuration error: secret key not available');
}

// Get token from query parameter
$token = isset($_GET['token']) ? $_GET['token'] : '';

if (empty($token)) {
    http_response_code(400);
    die('Missing token parameter');
}

// Split token into payload and signature
$parts = explode('.', $token, 2);
if (count($parts) !== 2) {
    http_response_code(400);
    die('Invalid token format');
}

$payload_b64 = $parts[0];
$signature_b64 = $parts[1];

// Verify HMAC signature
$expected_sig = hash_hmac('sha256', $payload_b64, $panel_secret, true);
$expected_sig_b64 = rtrim(strtr(base64_encode($expected_sig), '+/', '-_'), '=');

if (!hash_equals($expected_sig_b64, $signature_b64)) {
    http_response_code(403);
    die('Invalid token signature');
}

// Decode payload (base64url to standard base64)
$payload_b64_std = strtr($payload_b64, '-_', '+/');
$padding = 4 - (strlen($payload_b64_std) % 4);
if ($padding < 4) {
    $payload_b64_std .= str_repeat('=', $padding);
}
$payload_json = base64_decode($payload_b64_std, true);

if ($payload_json === false) {
    http_response_code(400);
    die('Invalid token encoding');
}

$payload = json_decode($payload_json, true);

if (!$payload || !isset($payload['u']) || !isset($payload['p']) || !isset($payload['exp'])) {
    http_response_code(400);
    die('Invalid token payload');
}

// Check expiry
if (time() > intval($payload['exp'])) {
    http_response_code(403);
    die('Token expired');
}

// Start the phpMyAdmin signon session
$session_name = 'PMA_single_signon';
session_name($session_name);
session_start();

// Set session variables for phpMyAdmin signon authentication
$_SESSION['PMA_single_signon_user'] = $payload['u'];
$_SESSION['PMA_single_signon_password'] = $payload['p'];
$_SESSION['PMA_single_signon_host'] = 'localhost';

// Pre-select database if specified
if (!empty($payload['d'])) {
    $_SESSION['PMA_single_signon_db'] = $payload['d'];
}

session_write_close();

// Redirect to phpMyAdmin index
$pma_path = dirname($_SERVER['SCRIPT_NAME']);
$redirect_url = rtrim($pma_path, '/') . '/index.php';

header('Location: ' . $redirect_url);
exit;
