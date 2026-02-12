<?php

require_once __DIR__ . '/../controllers/controller.php';

function route(string $method, string $path): void
{
    // Health check API
    if ($method === 'GET' && $path === '/api/health') {
        Controller::health();
        return;
    }

    if ($method === 'POST' && $path === '/api/postreq'){
        Controller::postreq();
    }

    // If no route matched
    http_response_code(404);
    echo json_encode([
        "error" => "Route not found"
    ]);
}
