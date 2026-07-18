<?php

require_once __DIR__ . '/../services/EmployeeWorkflow.php';

class EmployeeController
{
    private EmployeeWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new EmployeeWorkflow();
    }

    private function getBearerToken(): string|false
    {
        $headers = getallheaders();
        if (empty($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return false;
        }
        return str_replace('Bearer ', '', $headers['Authorization']);
    }

    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            parse_str(file_get_contents("php://input"), $input);
        }
        return is_array($input) ? $input : [];
    }

    public function onboardEmployee(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->onboardEmployee($token, $input);
        echo json_encode($response);
    }

    public function onboardTrainer(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->onboardTrainer($token, $input);
        echo json_encode($response);
    }

    public function getEmployee(int $employeeId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getEmployee($token, $employeeId);
        echo json_encode($response);
    }

    public function getTrainer(int $employeeId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getTrainer($token, $employeeId);
        echo json_encode($response);
    }

    public function updateEmployee(int $employeeId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateEmployee($token, $employeeId, $input);
        echo json_encode($response);
    }

    public function updateTrainer(int $employeeId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateTrainer($token, $employeeId, $input);
        echo json_encode($response);
    }

    public function updateEmployeeDocuments(int $employeeId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $documents = $input['documents'] ?? [];
        if (!is_array($documents)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "documents parameter must be an array"
            ]);
            return;
        }
        $response = $this->workflow->updateEmployeeDocuments($token, $employeeId, $documents);
        echo json_encode($response);
    }

    public function updateEmployeeStatus(int $employeeId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $status = $input['status'] ?? '';
        if (empty($status)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "status is required"
            ]);
            return;
        }
        $response = $this->workflow->updateEmployeeStatus($token, $employeeId, $status);
        echo json_encode($response);
    }

    public function listEmployees(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listEmployees($token, $_GET);
        echo json_encode($response);
    }

    public function listTrainers(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listTrainers($token, $_GET);
        echo json_encode($response);
    }

    public function updateTrainerSelfProfile(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateTrainerSelfProfile($token, $input);
        echo json_encode($response);
    }

    /**
     * GET /api/member/trainers
     */
    public function listMemberTrainers(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->listMemberTrainers($token, $_GET);
        echo json_encode($response);
    }
}
