<?php
// SPDX-License-Identifier: GPL-2.0-only

declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
session_start_secure();
$route = $_GET['route'] ?? 'me';
$method = $_SERVER['REQUEST_METHOD'];
$reads = ['me', 'setup.status', 'state', 'events'];
check(in_array($route, $reads, true) ? $method === 'GET' : $method === 'POST', 'Method not allowed', 405);
$p = [];
if ($method === 'POST') {
    csrf();
    check((int)($_SERVER['CONTENT_LENGTH'] ?? 0) <= 65536, 'Request is too large', 413);
    check(str_starts_with($_SERVER['CONTENT_TYPE'] ?? '', 'application/json'), 'JSON request required', 415);
    $raw = file_get_contents('php://input', false, null, 0, 65537);
    check(strlen($raw) <= 65536, 'Request is too large', 413);
    try { $p = json_decode($raw, true, flags: JSON_THROW_ON_ERROR); }
    catch (JsonException) { throw new HttpError(400, 'Invalid JSON'); }
    check(is_array($p) && str_starts_with(ltrim($raw), '{'), 'JSON object required', 400);
}

if ($route === 'setup.status') result(['required' => !query('SELECT id FROM users LIMIT 1'), 'csrf' => $_SESSION['csrf']]);
if ($route === 'setup') {
    fields($p, ['token', 'username', 'display_name', 'password']);
    check(is_string($p['token']) && strlen($p['token']) <= 128 && hash_equals(config()['setup_token_hash'], hash('sha256', $p['token'])), 'Setup token rejected', 403);
    $name = account_name($p['username']); $display = display_name($p['display_name']); $hash = password_hash_secure($p['password']);
    check((int)query("SELECT GET_LOCK('yanp_setup',5) AS acquired")[0]['acquired'] === 1, 'Setup is busy', 409);
    try {
        db()->beginTransaction();
        check(!query('SELECT id FROM users LIMIT 1'), 'Initial setup has already completed', 409);
        query("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,'admin')", [$name, $display, $hash]);
        audit((int)db()->lastInsertId(), 'setup.completed');
        db()->commit();
    } catch (Throwable $e) { if (db()->inTransaction()) db()->rollBack(); throw $e; }
    finally { query("SELECT RELEASE_LOCK('yanp_setup')"); }
    result(['created' => true]);
}
if ($route === 'login') {
    // This appliance serves its API at the document root. Require the same
    // canonical URL logged by Apache and matched by the login Fail2ban filter;
    // extra/duplicate/encoded query variants must not authenticate unseen.
    check(($_SERVER['REQUEST_URI'] ?? '') === '/api.php?route=login', 'Use /api.php?route=login for sign-in', 400);
    fields($p, ['username', 'password']);
    check(is_string($p['username']) && strlen($p['username']) <= 32 && is_string($p['password']) && strlen($p['password']) <= 128, 'Invalid login', 401);
    // REMOTE_ADDR is supplied by Apache. Never trust forwarded client-address headers.
    $ip = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'], config()['agent_key']);
    $nameHash = hash('sha256', strtolower($p['username']));
    check((int)query("SELECT GET_LOCK('yanp_login',5) AS acquired")[0]['acquired'] === 1, 'Login busy; try again', 429);
    try {
        $attempts = query('SELECT SUM(ip_hash=?) AS ip_count,SUM(username_hash=?) AS name_count FROM login_attempts WHERE attempted_at > UTC_TIMESTAMP() - INTERVAL 15 MINUTE AND (ip_hash=? OR username_hash=?)', [$ip,$nameHash,$ip,$nameHash])[0];
        check((int)$attempts['ip_count'] < 20 && (int)$attempts['name_count'] < 10, 'Too many login attempts. Try again in 15 minutes.', 429);
        query('INSERT INTO login_attempts(ip_hash,username_hash) VALUES(?,?)', [$ip,$nameHash]);
    } finally { query("SELECT RELEASE_LOCK('yanp_login')"); }
    $rows = query('SELECT * FROM users WHERE username=?', [$p['username']]);
    // A valid Argon2id dummy hash keeps unknown-account verification expensive too.
    $dummy = '$argon2id$v=19$m=65536,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$UoHeXJM3Fsa6Yj1r9h70YpSNwm8H9KUFB8fnBc5j9TI';
    $valid = password_verify($p['password'], $rows[0]['password_hash'] ?? $dummy);
    if (!$valid || !$rows || !$rows[0]['enabled']) { audit(null, 'login.failed', ['ip_hash' => $ip]); throw new HttpError(401, 'Invalid username or password'); }
    $u = $rows[0];
    session_regenerate_id(true);
    $_SESSION = ['uid' => $u['id'], 'version' => $u['session_version'], 'csrf' => bin2hex(random_bytes(32)), 'login_at' => time(), 'last_seen' => time()];
    audit($u['id'], 'login.succeeded');
    result(['user' => current_user(), 'csrf' => $_SESSION['csrf']]);
}

if ($route === 'me') {
    try { $u = current_user(false, false); } catch (HttpError $e) { if ($e->status !== 401) throw $e; $u = null; }
    result(['user' => $u, 'csrf' => $_SESSION['csrf']]);
}
$passiveAction = $route === 'action' && in_array($p['operation'] ?? '', ['snapshot.client_view','state','job.read','backup.inspect','storage.signatures','storage.browse','system.warnings','firewall.status','fail2ban.status'], true);
$u = current_user(false, $method === 'POST' && !$passiveAction);
if ($route === 'activity') {
    fields($p, []);
    result(['active' => true]);
}
if ($route === 'logout') {
    fields($p, []);
    audit($u['id'], 'logout');
    $_SESSION = [];
    session_destroy();
    result(['logged_out' => true]);
}
if ($route === 'password') {
    fields($p, ['current_password', 'password']);
    $hash = query('SELECT password_hash FROM users WHERE id=?', [$u['id']])[0]['password_hash'];
    check(is_string($p['current_password']) && strlen($p['current_password']) <= 128 && password_verify($p['current_password'], $hash), 'Current password is incorrect', 403);
    query('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?', [password_hash_secure($p['password']), $u['id']]);
    $_SESSION['version']++;
    session_regenerate_id(true);
    audit($u['id'], 'account.password_changed');
    result(['changed' => true]);
}
if ($route === 'state') result(agent('state', [], $u['id']));
if ($route === 'action') {
    fields($p, ['operation', 'params']);
    check(is_string($p['operation']) && is_array($p['params']), 'Invalid action');
    check($u['role'] === 'admin' || in_array($p['operation'], ['backup.inspect','job.read'], true), 'Administrator permission required', 403);
    // Agent has its own independent operation allowlist and live account lookup.
    result(agent($p['operation'], $p['params'], $u['id']));
}
if ($route === 'events') {
    $started = time(); $uid = $u['id']; $version = $u['session_version']; $admin = $u['role'] === 'admin';
    $lastSeen = $_SESSION['last_seen']; $loginAt = $_SESSION['login_at'];
    session_write_close();
    header('Content-Type: text/event-stream');
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache');
    ini_set('zlib.output_compression', '0');
    while (ob_get_level() > 0) ob_end_flush();
    $last = null;
    while (time() - $started < 25 && !connection_aborted()) {
        $account = query('SELECT enabled,role,session_version FROM users WHERE id=?', [$uid]);
        if (!$account || !$account[0]['enabled'] || $account[0]['session_version'] !== $version || $account[0]['role'] !== $u['role']) { echo "event: expired\ndata: {}\n\n"; flush(); break; }
        // Reconnect to re-read the session. Human activity may have renewed it in
        // another request since this stream released its session-file lock.
        if (time()-$lastSeen > 1800 || time()-$loginAt > 28800) break;
        if ($admin) {
            $stamp = query('SELECT COALESCE(MAX(id),0) AS n FROM events')[0]['n'];
        } else {
            $stamp = query('SELECT COALESCE(MAX(j.ended_at),MAX(j.started_at),0) AS n FROM jobs j JOIN backups b ON b.id=j.backup_id JOIN directory_access a ON a.directory_id=b.source_id AND a.user_id=b.owner_id WHERE b.owner_id=? AND b.allow_owner_view=1', [$uid])[0]['n'];
        }
        if ($stamp !== $last) { echo 'event: change' . "\ndata: " . json_encode(['revision' => $stamp]) . "\n\n"; $last = $stamp; }
        else echo "event: tick\ndata: {}\n\n";
        flush();
        sleep(2);
    }
    exit;
}

current_user(true);
if ($route === 'users.create') {
    fields($p, ['username', 'display_name', 'role', 'password']);
    check(in_array($p['role'], ['admin','user'], true), 'Invalid role');
    $name = account_name($p['username']);
    check(!query('SELECT id FROM users WHERE username=?', [$name]), 'Username is already in use', 409);
    query('INSERT INTO users(username,display_name,role,password_hash) VALUES(?,?,?,?)', [$name,display_name($p['display_name']),$p['role'],password_hash_secure($p['password'])]);
    $ident = (int)db()->lastInsertId();
    audit($u['id'], 'user.created', ['id'=>$ident, 'username'=>$name]);
    result(['id'=>$ident, 'system_synced'=>false]);
}
if ($route === 'users.edit') {
    fields($p, ['id', 'display_name', 'role']);
    id($p['id']);
    check(in_array($p['role'], ['admin','user'], true), 'Invalid role');
    check($p['id'] !== $u['id'], 'Use your account settings; another administrator must change your role');
    check((bool)query('SELECT id FROM users WHERE id=?', [$p['id']]), 'User not found', 404);
    check((int)query("SELECT GET_LOCK('yanp_accounts',10) AS acquired")[0]['acquired'] === 1, 'Account management is busy', 409);
    try {
        current_user(true);
        query('UPDATE users SET display_name=?,role=?,session_version=session_version+1 WHERE id=?', [display_name($p['display_name']),$p['role'],$p['id']]);
    } finally { query("SELECT RELEASE_LOCK('yanp_accounts')"); }
    audit($u['id'], 'user.edited', ['id'=>$p['id'], 'role'=>$p['role']]);
    result(['updated'=>true]);
}
if ($route === 'users.password') {
    fields($p, ['id', 'password']);
    id($p['id']);
    check((bool)query('SELECT id FROM users WHERE id=?', [$p['id']]), 'User not found', 404);
    check($p['id'] !== $u['id'], 'Use your account settings to change your own password');
    query('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?', [password_hash_secure($p['password']),$p['id']]);
    audit($u['id'], 'user.password_reset', ['id'=>$p['id']]);
    result(['updated'=>true]);
}
throw new HttpError(404, 'Endpoint not found');
