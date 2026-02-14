<?php

// // Always return JSON
// header("Content-Type: application/json");

// // Basic autoloader (simple & enough for now)
// require_once __DIR__ . '/../app/routes/api.php';


// // Get request details
// $method = $_SERVER['REQUEST_METHOD'];
// $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// // Remove project base path
// $basePath = '/fitness-guru';
// $path = str_replace($basePath, '', $uri);

// // Route the request
// route($method, $path);

// ================= CORS HEADERS =================
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ================= JSON RESPONSE =================
header("Content-Type: application/json");

// Load routes
require_once __DIR__ . '/../app/routes/api.php';

$method = $_SERVER['REQUEST_METHOD'];
$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

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

// Route request
route($method, $path);



