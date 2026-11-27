<?php
declare(strict_types=1);

$uri = $_SERVER['REQUEST_URI'] ?? '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$target = 'http://127.0.0.1:3450' . $uri;

$ch = curl_init($target);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 20);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

$forwardHeaders = [
    'X-Via-Public-Proxy: 1',
    'X-Forwarded-Proto: https',
    'X-Forwarded-Host: ' . ($_SERVER['HTTP_HOST'] ?? ''),
    'X-Forwarded-For: ' . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? ''),
];
foreach (['CONTENT_TYPE' => 'Content-Type', 'HTTP_COOKIE' => 'Cookie', 'HTTP_ACCEPT' => 'Accept', 'HTTP_ORIGIN' => 'Origin', 'HTTP_REFERER' => 'Referer'] as $srvKey => $hdrName) {
    if (!empty($_SERVER[$srvKey])) {
        $forwardHeaders[] = $hdrName . ': ' . $_SERVER[$srvKey];
    }
}
curl_setopt($ch, CURLOPT_HTTPHEADER, $forwardHeaders);

if (!in_array($method, ['GET', 'HEAD'], true)) {
    $rawBody = file_get_contents('php://input');
    if ($rawBody !== false) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $rawBody);
    }
}

$rawResponse = curl_exec($ch);
if ($rawResponse === false) {
    http_response_code(502);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    echo json_encode(['ok' => false, 'error' => 'Managed Relay backend unavailable on 127.0.0.1:3450']);
    curl_close($ch);
    exit;
}

$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$respHeadersRaw = substr($rawResponse, 0, $headerSize);
$respBody = substr($rawResponse, $headerSize);
curl_close($ch);

http_response_code($status);
foreach (preg_split("/\r\n|\n|\r/", $respHeadersRaw) as $line) {
    if ($line === '' || stripos($line, 'HTTP/') === 0) continue;
    $colon = strpos($line, ':');
    if ($colon === false) continue;
    $name = strtolower(trim(substr($line, 0, $colon)));
    if (in_array($name, ['transfer-encoding', 'connection', 'keep-alive', 'content-length'], true)) continue;
    header($line, $name === 'set-cookie' ? false : true);
}
echo $respBody;
