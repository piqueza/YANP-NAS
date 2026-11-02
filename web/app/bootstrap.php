<?php
// SPDX-License-Identifier: GPL-2.0-only

declare(strict_types=1);

final class HttpError extends RuntimeException {
    public function __construct(public int $status, string $message) { parent::__construct($message); }
}

set_exception_handler(function (Throwable $e): void {
    $status = $e instanceof HttpError ? $e->status : 500;
    if ($status === 500) error_log('YANP Nas: ' . $e->getMessage());
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => $status === 500 ? 'Server unavailable. Check Apache and yanp-agent logs.' : $e->getMessage()]);
});

function config(): array {
    static $config;
    if ($config === null) {
        $path = getenv('YANP_WEB_CONFIG') ?: '/etc/yanp-nas/web.json';
        $config = json_decode(file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
    }
    return $config;
}

function db(): PDO {
    static $db;
    if ($db === null) {
        $c = config();
        $db = new PDO('mysql:unix_socket=' . ($c['db_socket'] ?? '/run/mysqld/mysqld.sock') . ';dbname=' . $c['db_name'] . ';charset=utf8mb4',
            $c['db_user'], $c['db_password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
        $db->exec("SET time_zone = '+00:00'");
    }
    return $db;
}

function query(string $sql, array $params = []): array {
    $q = db()->prepare($sql);
    $q->execute($params);
    return $q->columnCount() ? $q->fetchAll() : [];
}

function check(bool $condition, string $message, int $status = 422): void {
    if (!$condition) throw new HttpError($status, $message);
}

function fields(array $p, array $required, array $optional = []): void {
    check(!array_diff($required, array_keys($p)) && !array_diff(array_keys($p), array_merge($required, $optional)), 'Missing or unexpected fields');
}

function id(mixed $value): int {
    check(is_int($value) && $value > 0, 'Invalid account ID');
    return $value;
}

function account_name(mixed $value): string {
    check(is_string($value) && preg_match('/\Ayanp_[a-z][a-z0-9_]{0,26}\z/D', $value) === 1,
        'Username must start with yanp_ followed by lowercase letters, digits or underscores');
    return $value;
}

function display_name(mixed $value): string {
    check(is_string($value) && strlen($value) >= 1 && strlen($value) <= 120 && !preg_match('/[\x00-\x1f\x7f]/', $value), 'Invalid display name');
    return $value;
}

function password_hash_secure(mixed $value): string {
    check(is_string($value) && strlen($value) >= 12 && strlen($value) <= 128 && !str_contains($value, "\0"),
        'Use a password of 12–128 bytes');
    check(defined('PASSWORD_ARGON2ID'), 'PHP must provide Argon2id support', 503);
    return password_hash($value, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 3, 'threads' => 1]);
}

function session_start_secure(): void {
    $c = config();
    $tls = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    check($tls || ($c['allow_http_dev'] ?? false), 'HTTPS is required. Open the configured HTTPS management URL.', 400);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', '1800');
    if (isset($c['session_path'])) session_save_path($c['session_path']);
    session_name($tls ? '__Host-yanp_session' : 'yanp_dev_session');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $tls, 'httponly' => true, 'samesite' => 'Strict']);
    session_start();
    $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function csrf(): void {
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    check(is_string($token) && hash_equals($_SESSION['csrf'], $token), 'Session token expired. Reload the page.', 403);
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    if ($origin !== null) {
        $tls = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        check($origin === ($tls ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'], 'Origin rejected', 403);
    }
}

function current_user(bool $admin = false, bool $touch = true): array {
    $now = time();
    check(isset($_SESSION['uid'], $_SESSION['login_at'], $_SESSION['last_seen']) &&
        $now - $_SESSION['last_seen'] <= 1800 && $now - $_SESSION['login_at'] <= 28800, 'Please log in again', 401);
    $rows = query('SELECT id,username,display_name,role,enabled,session_version,system_synced FROM users WHERE id=?', [$_SESSION['uid']]);
    check(count($rows) === 1 && (bool)$rows[0]['enabled'] && $rows[0]['session_version'] === $_SESSION['version'], 'Please log in again', 401);
    check(!$admin || $rows[0]['role'] === 'admin', 'Administrator permission required', 403);
    if ($touch) $_SESSION['last_seen'] = $now;
    return $rows[0];
}

function audit(?int $actor, string $action, array $details = []): void {
    query('INSERT INTO audit(actor_id,action,details) VALUES(?,?,?)', [$actor, $action, json_encode($details, JSON_THROW_ON_ERROR)]);
}

function agent(string $operation, array $params, int $actor): mixed {
    $c = config();
    $payload = json_encode(['time' => time(), 'nonce' => bin2hex(random_bytes(16)), 'actor' => $actor,
        'operation' => $operation, 'params' => (object)$params], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $socket = stream_socket_client('unix://' . $c['agent_socket'], $errno, $error, 3);
    if ($socket === false) throw new HttpError(503, 'Management service unavailable. Check systemctl status yanp-agent.');
    stream_set_timeout($socket, 100);
    $data = json_encode(['payload' => base64_encode($payload), 'signature' => hash_hmac('sha256', $payload, $c['agent_key'])], JSON_THROW_ON_ERROR) . "\n";
    $offset = 0;
    while ($offset < strlen($data)) {
        $written = fwrite($socket, substr($data, $offset));
        if (!$written) { fclose($socket); throw new HttpError(503, 'Management socket write failed'); }
        $offset += $written;
    }
    $response = fgets($socket, 8 * 1024 * 1024);
    fclose($socket);
    check($response !== false, 'Management service did not respond', 503);
    $result = json_decode($response, true, flags: JSON_THROW_ON_ERROR);
    check($result['ok'] === true, $result['error'] ?? 'Management action failed', 422);
    return $result['data'];
}

function result(mixed $data): never {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => true, 'data' => $data], JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
