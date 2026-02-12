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


