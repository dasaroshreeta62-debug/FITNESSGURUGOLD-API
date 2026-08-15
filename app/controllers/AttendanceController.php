<?php

require_once __DIR__ . '/../services/AttendanceWorkflow.php';

class AttendanceController
{
    private AttendanceWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new AttendanceWorkflow();
    }

    private function getBearerToken(): string|false
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (empty($authHeader)) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return false;
        }

        return str_replace('Bearer ', '', $authHeader);
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

    public function checkIn(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->checkIn($token, $input);
        echo json_encode($response);
    }

    public function checkOut(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->checkOut($token, $input);
        echo json_encode($response);
    }

    public function listAttendance(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $filters = [
            'user_id'   => $_GET['user_id'] ?? null,
            'gym_id'    => $_GET['gym_id'] ?? null,
            'branch_id' => $_GET['branch_id'] ?? null,
            'from_date' => $_GET['from_date'] ?? null,
            'to_date'   => $_GET['to_date'] ?? null,
            'date'      => $_GET['date'] ?? null,
            'source'    => $_GET['source'] ?? null,
            'status'    => $_GET['status'] ?? null,
            'search'    => $_GET['search'] ?? null,
            'page'      => $_GET['page'] ?? 1,
            'limit'     => $_GET['limit'] ?? 20
        ];

        $response = $this->workflow->listAttendance($token, $filters);
        echo json_encode($response);
    }

    public function getAttendanceDetails(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $userId       = isset($_GET['user_id']) ? (int)$_GET['user_id'] : null;
        $date         = $_GET['date'] ?? null;
        $attendanceId = isset($_GET['attendance_id']) ? (int)$_GET['attendance_id'] : null;

        $response = $this->workflow->getAttendanceDetails($token, $userId, $date, $attendanceId);
        echo json_encode($response);
    }

    public function markOrUpdateAttendance(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->markOrUpdateAttendance($token, $input);
        echo json_encode($response);
    }

    public function deleteAttendance(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $attendanceId = !empty($input['attendance_id']) ? (int)$input['attendance_id'] : (isset($_GET['attendance_id']) ? (int)$_GET['attendance_id'] : 0);

        $response = $this->workflow->deleteAttendance($token, $attendanceId);
        echo json_encode($response);
    }

    public function adminManualEntry(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->adminManualEntry($token, $input);
        echo json_encode($response);
    }

    public function memberManualEntry(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->memberManualEntry($token, $input);
        echo json_encode($response);
    }

    public function getAttendanceLogs(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $filters = [
            'branch_id'  => $_GET['branch_id'] ?? null,
            'user_id'    => $_GET['user_id'] ?? null,
            'start_date' => $_GET['start_date'] ?? null,
            'end_date'   => $_GET['end_date'] ?? null,
            'source'     => $_GET['source'] ?? null,
            'page'       => $_GET['page'] ?? 1,
            'limit'      => $_GET['limit'] ?? 20
        ];

        $response = $this->workflow->getAttendanceLogs($token, $filters);
        echo json_encode($response);
    }
}

