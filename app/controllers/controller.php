<?php

require_once __DIR__ . '/../services/workflow.php';

class Controller
{
    private Workflow $workflow;

    public function __construct()
    {
        $this->workflow = new Workflow();
    }

    public function login(): void
    {
        // Try JSON first
        $input = json_decode(file_get_contents("php://input"), true);

        // Fallback to form-data
        if (empty($input)) {
            $input = $_POST;
        }

        $email    = trim($input['email'] ?? '');
        $password = trim($input['password'] ?? '');

        if (empty($email) || empty($password)) {
            http_response_code(400);
            echo json_encode([
                "status"  => "error",
                "message" => "Email and password are required"
            ]);
            return;
        }

        $response = $this->workflow->login($email, $password);
        echo json_encode($response);
    }
    public function logout(): void
    {
        $headers = getallheaders();

        if (empty($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return;
        }

        // Try JSON first
        $input = json_decode(file_get_contents("php://input"), true);

        // Fallback to form-data
        if (empty($input)) {
            $input = $_POST;
        }

        if (empty($input['refresh_token'])) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Refresh token is required"
            ]);
            return;
        }

        $accessToken  = str_replace('Bearer ', '', $headers['Authorization']);
        $refreshToken = $input['refresh_token'];

        $response = $this->workflow->logout($accessToken, $refreshToken);
        echo json_encode($response);
    }
    public function register(): void
    {
        // Try JSON first
        $input = json_decode(file_get_contents("php://input"), true);

        // Fallback to form-data / x-www-form-urlencoded
        if (empty($input)) {
            $input = $_POST;
        }

        if (empty($input)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Invalid request body"
            ]);
            return;
        }

        $required = ['gym_id', 'branch_id', 'name', 'email', 'phone', 'password', 'role'];

        foreach ($required as $field) {
            if (!isset($input[$field]) || trim($input[$field]) === '') {
                http_response_code(400);
                echo json_encode([
                    "status" => "error",
                    "message" => ucfirst($field) . " is required"
                ]);
                return;
            }
        }

        $response = $this->workflow->register($input);
        echo json_encode($response);
    }
}
