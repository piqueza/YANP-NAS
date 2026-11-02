<?php
// SPDX-License-Identifier: GPL-2.0-only
 declare(strict_types=1);
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');
$jsVersion = substr(hash_file('sha256', __DIR__ . '/assets/app.js'), 0, 16);
$cssVersion = substr(hash_file('sha256', __DIR__ . '/assets/app.css'), 0, 16);
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#101b22">
<title>YANP Nas · Management</title><link rel="stylesheet" href="assets/app.css?v=<?=$cssVersion?>"><script src="assets/app.js?v=<?=$jsVersion?>" defer></script></head>
<body><div id="app"><main class="starting"><div class="brandmark">Y</div><p>Connecting to YANP Nas…</p></main></div>
<div id="toasts" aria-live="polite"></div><dialog id="dialog"><div id="dialog-content"></div></dialog>
<noscript>This management interface requires JavaScript. All operations are authorized on the server.</noscript></body></html>
