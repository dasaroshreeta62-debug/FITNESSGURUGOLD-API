<?php

require_once __DIR__ . '/../services/workflow.php';

class Controller
{
    public static function health(): void
    {
        header('Content-Type: application/json');

        try {
            $service = new Workflow();
            $users = $service->getAllUsers();

            http_response_code(200);
            echo json_encode([
                "status" => "success",
                "count"  => count($users),
                "data"   => $users
            ]);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode([
                "status" => "error",
                "message" => "Internal Server Error"
            ]);

            Logger::error($e); // 👈 logging
        }
    }

    public static function postreq(): void
    {
        header('Content-Type: application/json');
        try {
            $service = new Workflow();
            $users = $service->getAllUsers();

            http_response_code(200);
            echo json_encode([
                "status" => "success",
                "count"  => count($users),
                "data"   => $users
            ]);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode([
                "status" => "error",
                "message" => "Internal Server Error"
            ]);

            Logger::error($e); // 👈 logging
        }
    }
}
