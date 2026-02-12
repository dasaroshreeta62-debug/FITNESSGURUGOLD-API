<?php

// Always return JSON
header("Content-Type: application/json");

// Basic autoloader (simple & enough for now)
require_once __DIR__ . '/../app/routes/api.php';

// Get request details
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Remove project base path
$basePath = '/fitness-guru';
$path = str_replace($basePath, '', $uri);

// Route the request
route($method, $path);


