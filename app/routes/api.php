<?php

require_once __DIR__ . '/../controllers/controller.php';

function route(string $method, string $path): void
{
    // Normalize path (remove trailing slash)
    $path = rtrim($path, '/');

    // Create controller instance
    $controller = new Controller();

    switch (true) {

        // ================= AUTH ROUTES =================
        case $method === 'POST' && $path === '/api/auth/login':
            $controller->login();
            return;

        case $method === 'POST' && $path === '/api/auth/logout':
            $controller->logout();
            return;
        
        case $method === 'POST' && $path === '/api/auth/register':
            $controller->register();
            return;

        // ================= DEFAULT =================
        default:
            http_response_code(404);
            echo json_encode([
                "status" => "error",
                "message" => "Route not found"
            ]);
            return;
    }
}

