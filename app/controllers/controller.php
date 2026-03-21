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
    public function profile(): void
    {
        // 🔍 DEBUG: log all incoming headers
        // error_log(print_r(getallheaders(), true));
        $headers = getallheaders();

        if (empty($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return;
        }

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $response = $this->workflow->getProfile($accessToken);
        echo json_encode($response);
    }
    public function updateProfile(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        // ✅ Try JSON first
        $input = json_decode(file_get_contents("php://input"), true);

        // ✅ Fallback to form-data / x-www-form-urlencoded
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

        $response = $this->workflow->updateProfile($accessToken, $input);
        echo json_encode($response);
    }
    public function listUsers(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        // Query params
        $filters = [
            'role'      => $_GET['role'] ?? null,
            'status'    => $_GET['status'] ?? null,
            'gym_id'    => $_GET['gym_id'] ?? null,
            'branch_id' => $_GET['branch_id'] ?? null,
            'page'      => (int)($_GET['page'] ?? 1),
            'limit'     => (int)($_GET['limit'] ?? 20),
        ];

        $response = $this->workflow->listUsers($accessToken, $filters);
        echo json_encode($response);
    }
    public function getGyms(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $filters = [
            'status'  => $_GET['status'] ?? null,
            'city_id' => $_GET['city_id'] ?? null,
            'page'    => (int)($_GET['page'] ?? 1),
            'limit'   => (int)($_GET['limit'] ?? 20),
        ];

        $response = $this->workflow->getGyms($accessToken, $filters);
        echo json_encode($response);
    }
    public function createGym(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        // Try JSON first
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }

        if (empty($input['gym_name']) || empty($input['city_id'])) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Gym name and city are required"
            ]);
            return;
        }

        $response = $this->workflow->createGym($accessToken, $input);
        echo json_encode($response);
    }
    public function getGymDetails(int $gymId): void
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);

        if (empty($headers['authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return;
        }

        if (!preg_match('/Bearer\s(\S+)/', $headers['authorization'], $matches)) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Invalid Authorization header format"
            ]);
            return;
        }

        $accessToken = $matches[1];

        $response = $this->workflow->getGymDetails($accessToken, $gymId);
        echo json_encode($response);
    }
    public function updateGym(int $gymId): void
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);

        if (empty($headers['authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return;
        }

        if (!preg_match('/Bearer\s(\S+)/', $headers['authorization'], $matches)) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Invalid Authorization header format"
            ]);
            return;
        }

        $accessToken = $matches[1];
        $payload = json_decode(file_get_contents("php://input"), true) ?? [];

        $response = $this->workflow->updateGym($accessToken, $gymId, $payload);
        echo json_encode($response);
    }
    public function listCountry(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        // No filters required for now
        $response = $this->workflow->listCountry($accessToken);
        echo json_encode($response);
    }
    public function listState(): void
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

        $country_id = $_GET['country_id'] ?? null;

        if (!$country_id) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "country_id is required"
            ]);
            return;
        }

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $response = $this->workflow->listState(
            $accessToken,
            (int)$country_id
        );

        echo json_encode($response);
    }
    public function listDistrict(): void
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

        $state_id = $_GET['state_id'] ?? null;

        if (!$state_id) {
            http_response_code(400);
            echo json_encode([
                "status"  => "error",
                "message" => "state_id is required"
            ]);
            return;
        }

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $response = $this->workflow->listDistrict(
            $accessToken,
            (int)$state_id
        );

        echo json_encode($response);
    }
    public function listGymBranches(): void
    {
        // ❌ REMOVE AUTH CHECK COMPLETELY

        if (empty($_GET['gym_id'])) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "gym_id is required"
            ]);
            return;
        }

        $filters = [
            'gym_id' => (int)$_GET['gym_id']
        ];

        $response = $this->workflow->listGymBranches($filters);
        echo json_encode($response);
    }
    public function listCities(): void
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

        if (empty($_GET['district_id'])) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "district_id is required"
            ]);
            return;
        }

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $filters = [
            'district_id' => (int)$_GET['district_id']
        ];

        $response = $this->workflow->listCities($accessToken, $filters);
        echo json_encode($response);
    }
    // public function addMember()
    // {
    //     $data = $_POST;

    //     if (empty($data)) {
    //         $data = json_decode(file_get_contents("php://input"), true);
    //     }

    //     if (
    //         empty($data['name']) ||
    //         empty($data['email']) ||
    //         empty($data['phone']) ||
    //         empty($data['password']) ||
    //         empty($data['branch_id']) ||
    //         empty($data['gym_id'])
    //     ) {
    //         http_response_code(400);
    //         echo json_encode([
    //             "status" => "error",
    //             "message" => "Required fields missing"
    //         ]);
    //         return;
    //     }

    //     $success = $this->workflow->addMember($data);

    //     if ($success) {
    //         echo json_encode([
    //             "status" => "success",
    //             "message" => "Member added successfully"
    //         ]);
    //     } else {
    //         http_response_code(500);
    //         echo json_encode([
    //             "status" => "error",
    //             "message" => "Failed to add member"
    //         ]);
    //     }
    // }
    public function addMember()
    {
        $data = $_POST;

        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true);
        }

        if (
            empty($data['name']) ||
            empty($data['email']) ||
            empty($data['phone']) ||
            empty($data['password']) ||
            empty($data['branch_id']) ||
            empty($data['gym_id'])
        ) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Required fields missing"
            ]);
            return;
        }

        $response = $this->workflow->addMember($data);

        if ($response['status'] === 'success') {
            echo json_encode($response);
        } else {
            http_response_code(500);
            echo json_encode($response);
        }
    }
    public function viewMember(): void
    {
        $user_id = $_GET['user_id'] ?? null;

        if (!$user_id) {
            http_response_code(400);
            echo json_encode([
                'status'  => 'error',
                'message' => 'user_id is required'
            ]);
            return;
        }

        $result = $this->workflow->getMemberDetails((int)$user_id);

        if (!$result) {
            http_response_code(404);
            echo json_encode([
                'status'  => 'error',
                'message' => 'Member not found'
            ]);
            return;
        }

        echo json_encode([
            'status' => 'success',
            'data'   => $result
        ]);
    }
    public function viewAllMembers(): void
    {
        $result = $this->workflow->getAllMemberDetails();

        echo json_encode([
            'status' => 'success',
            'count'  => count($result),
            'data'   => $result
        ]);
    }
    public function updateMember(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);
        $data = json_decode(file_get_contents("php://input"), true);

        if (empty($data['user_id'])) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "User ID is required"
            ]);
            return;
        }

        $response = $this->workflow->updateMember($accessToken, $data);
        echo json_encode($response);
    }
    public function listMembershipPlan(): void
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

        $gym_id = $_GET['gym_id'] ?? null;
        $branch_id = $_GET['branch_id'] ?? null;

        if (!$gym_id || !$branch_id) {
            http_response_code(400);
            echo json_encode([
                'status'  => 'error',
                'message' => 'gym_id and branch_id are required'
            ]);
            return;
        }

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $response = $this->workflow->listMembershipPlan(
            $accessToken,
            (int)$gym_id,
            (int)$branch_id
        );

        echo json_encode($response);
    }
    public function addAttendance(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);
        $data = json_decode(file_get_contents("php://input"), true);

        /* ===== BASIC VALIDATION ===== */
        $required = ['user_id', 'gym_id', 'branch_id'];

        foreach ($required as $field) {
            if (empty($data[$field])) {
                http_response_code(400);
                echo json_encode([
                    "status" => "error",
                    "message" => "$field is required"
                ]);
                return;
            }
        }

        $response = $this->workflow->addAttendance($accessToken, $data);
        echo json_encode($response);
    }
    public function checkOutAttendance(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);
        $data = json_decode(file_get_contents("php://input"), true);

        if (empty($data['user_id'])) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "user_id is required"
            ]);
            return;
        }

        $response = $this->workflow->checkOutAttendance($accessToken, $data);
        echo json_encode($response);
    }
    public function listAttendance(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $filters = [
            'from_date' => $_GET['from_date'] ?? null,
            'to_date'   => $_GET['to_date'] ?? null,
            'state_id'  => $_GET['state_id'] ?? null,
            'district_id' => $_GET['district_id'] ?? null,
            'branch_id' => $_GET['branch_id'] ?? null,
            'page'      => $_GET['page'] ?? 1,
            'limit'     => $_GET['limit'] ?? 20
        ];

        $response = $this->workflow->listAttendance($accessToken, $filters);
        echo json_encode($response);
    }
    public function viewUserAttendanceWithSessions(): void
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

        $accessToken = str_replace('Bearer ', '', $headers['Authorization']);

        $userId = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;
        $date   = $_GET['date'] ?? null;

        if (!$userId || !$date) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "user_id and date are required"
            ]);
            return;
        }

        $response = $this->workflow->viewUserAttendanceWithSessions(
            $accessToken,
            $userId,
            $date
        );

        echo json_encode($response);
    }
    public function submitContactForm(): void
    {
        $input = json_decode(file_get_contents("php://input"), true);

        if (empty($input)) {
            $input = $_POST;
        }

        $name     = trim($input['name'] ?? '');
        $email    = trim($input['email'] ?? '');
        $phone    = trim($input['phone'] ?? '');
        $service  = trim($input['service'] ?? '');
        $message  = trim($input['message'] ?? '');

        // Validation
        if (!$name || !$email || !$phone || !$service || !$message) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "All fields are required"
            ]);
            return;
        }

        $response = $this->workflow->submitContactForm([
            "name" => $name,
            "email" => $email,
            "phone" => $phone,
            "service" => $service,
            "message" => $message
        ]);

        echo json_encode($response);
    }
    public function getContactList(): void
    {
        $page  = (int)($_GET['page'] ?? 1);
        $limit = (int)($_GET['limit'] ?? 10);

        $page  = max(1, $page);
        $limit = max(1, $limit);
        $offset = ($page - 1) * $limit;

        $response = $this->workflow->getContactList($limit, $offset);

        echo json_encode($response);
    }
}
