<?php

$startTime = microtime(true);
ob_start();

require_once __DIR__ . '/../app/logs/logger.php';
require_once __DIR__ . '/../app/routes/api.php';

// Fix Authorization header
if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
    $_SERVER['Authorization'] = $_SERVER['HTTP_AUTHORIZATION'];
}

// CORS
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    ob_end_flush();
    exit;
}

header("Content-Type: application/json");

$method     = $_SERVER['REQUEST_METHOD'];
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$uri        = parse_url($requestUri, PHP_URL_PATH);

/**
 * Detect base path
 * Example:
 *  /fitness-guru/public/index.php → /fitness-guru
 */
$scriptDir = str_replace('/public', '', dirname($_SERVER['SCRIPT_NAME']));
$basePath  = rtrim($scriptDir, '/');

// Remove base path from URI
if ($basePath && strpos($uri, $basePath) === 0) {
    $path = substr($uri, strlen($basePath));
} else {
    $path = $uri;
}

$path = $path ?: '/';

// Capture raw payload & query params
$rawInput = file_get_contents("php://input");
$payload  = !empty($_POST) ? $_POST : (json_decode($rawInput, true) ?: $rawInput);

// Route request
try {
    route($method, $path);
} catch (\Throwable $e) {
    Logger::error($e);
    http_response_code(500);
    echo json_encode(["success" => false, "message" => "Internal Server Error", "error" => $e->getMessage()]);
}

$durationMs     = (microtime(true) - $startTime) * 1000;
$statusCode     = http_response_code() ?: 200;
$responseOutput = ob_get_contents();

Logger::logApiCall(
    $method,
    $requestUri,
    $statusCode,
    $durationMs,
    $_GET,
    $payload,
    $responseOutput
);

ob_end_flush();




