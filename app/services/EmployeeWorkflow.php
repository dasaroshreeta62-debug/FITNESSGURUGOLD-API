<?php

require_once __DIR__ . '/../repositories/EmployeeModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class EmployeeWorkflow
{
    private EmployeeModel $model;

    private const JWT_SECRET  = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    private const ALLOWED_DESIGNATIONS = [
        'OWNER', 'BRANCH_MANAGER', 'SENIOR_TRAINER', 'TRAINER', 'JUNIOR_TRAINER',
        'RECEPTIONIST', 'ACCOUNTANT', 'NUTRITIONIST', 'HOUSEKEEPING', 'MAINTENANCE', 'OTHER'
    ];

    private const ALLOWED_EMPLOYMENT_TYPES = [
        'FULL_TIME', 'PART_TIME', 'CONTRACT', 'INTERN'
    ];

    private const ALLOWED_SALARY_TYPES = [
        'MONTHLY', 'HOURLY', 'PER_SESSION', 'COMMISSION'
    ];

    private const ALLOWED_STATUSES = [
        'ACTIVE', 'ON_LEAVE', 'INACTIVE', 'TERMINATED'
    ];

    private const ALLOWED_DOCUMENT_TYPES = [
        'AADHAAR', 'PAN', 'PASSPORT', 'DRIVING_LICENSE', 'RESUME', 'EMPLOYMENT_CONTRACT',
        'FITNESS_CERTIFICATE', 'MEDICAL_CERTIFICATE', 'POLICE_VERIFICATION',
        'EDUCATIONAL_CERTIFICATE', 'TRAINER_CERTIFICATION', 'OTHER'
    ];

    public function __construct()
    {
        $this->model = new EmployeeModel();
    }

    private function verifyRole(string $accessToken, array $allowedRoles): object
    {
        $decoded = JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));
        $role = str_replace(['_', '-'], '', strtoupper($decoded->role ?? ''));
        $allowedNormalized = array_map(function ($r) {
            return str_replace(['_', '-'], '', strtoupper($r));
        }, $allowedRoles);

        if (!in_array($role, $allowedNormalized)) {
            throw new Exception("Access denied. Authorized role required.", 403);
        }
        return $decoded;
    }

    public function onboardEmployee(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;
            $adminRole = strtoupper($decoded->role);

            // Fetch admin details to get gym_id
            $stmt = Database::getConnection()->prepare("SELECT gym_id FROM users WHERE user_id = :id LIMIT 1");
            $stmt->execute(['id' => $adminUserId]);
            $adminUser = $stmt->fetch(PDO::FETCH_ASSOC);
            $gymId = ($adminRole === 'SUPER_ADMIN' && !empty($data['gym_id'])) ? (int)$data['gym_id'] : (int)($adminUser['gym_id'] ?? 0);

            if (!$gymId) {
                http_response_code(400);
                return ["status" => "error", "message" => "Gym ID is required"];
            }

            // Required validations
            $required = ['branch_id', 'name', 'email', 'phone', 'password', 'role', 'designation', 'employment_type', 'salary_type', 'salary_amount', 'joining_date'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || trim((string)$data[$field]) === '') {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Field '$field' is required"];
                }
            }

            if ($this->model->emailExists(strtolower(trim($data['email'])))) {
                http_response_code(409);
                return ["status" => "error", "message" => "Email already registered"];
            }

            $designation = strtoupper(trim($data['designation']));
            if (!in_array($designation, self::ALLOWED_DESIGNATIONS)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid designation. Allowed values: " . implode(', ', self::ALLOWED_DESIGNATIONS)];
            }

            $empType = strtoupper(trim($data['employment_type']));
            if (!in_array($empType, self::ALLOWED_EMPLOYMENT_TYPES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid employment type. Allowed values: " . implode(', ', self::ALLOWED_EMPLOYMENT_TYPES)];
            }

            $salType = strtoupper(trim($data['salary_type']));
            if (!in_array($salType, self::ALLOWED_SALARY_TYPES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid salary type. Allowed values: " . implode(', ', self::ALLOWED_SALARY_TYPES)];
            }

            // Begin transaction
            $this->model->beginTransaction();

            // 1. Create auth user
            $passwordHash = password_hash($data['password'], PASSWORD_BCRYPT);
            $userData = [
                'gym_id'    => $gymId,
                'branch_id' => (int)$data['branch_id'],
                'name'      => trim($data['name']),
                'email'     => strtolower(trim($data['email'])),
                'phone'     => trim($data['phone']),
                'password'  => $passwordHash,
                'role'      => strtoupper(trim($data['role'])),
                'status'    => 1 // ACTIVE
            ];
            $userId = $this->model->insertEmployeeUser($userData);

            // 2. Generate employee code
            $employeeCode = "EMP-" . str_pad($userId, 5, '0', STR_PAD_LEFT);

            // 3. Create employee record
            $employeeData = [
                'user_id'                 => $userId,
                'gym_id'                  => $gymId,
                'branch_id'               => (int)$data['branch_id'],
                'employee_code'           => $employeeCode,
                'full_name'               => trim($data['name']),
                'email'                   => strtolower(trim($data['email'])),
                'phone'                   => trim($data['phone']),
                'designation'             => $designation,
                'employment_type'         => $empType,
                'salary_type'             => $salType,
                'salary_amount'           => (float)$data['salary_amount'],
                'joining_date'            => trim($data['joining_date']),
                'profile_photo'           => $data['profile_photo'] ?? null,
                'emergency_contact_name'  => $data['emergency_contact_name'] ?? null,
                'emergency_contact_phone' => $data['emergency_contact_phone'] ?? null,
                'address'                 => $data['address'] ?? null,
                'remarks'                 => $data['remarks'] ?? null,
                'status'                  => 'ACTIVE',
                'created_by'              => $adminUserId
            ];
            $employeeId = $this->model->insertEmployee($employeeData);

            // 4. Onboard documents
            if (!empty($data['documents']) && is_array($data['documents'])) {
                foreach ($data['documents'] as $doc) {
                    if (empty($doc['document_type']) || empty($doc['document_url']) || empty($doc['document_name'])) {
                        throw new Exception("Missing document_type, document_name, or document_url inside documents array", 400);
                    }
                    $docType = strtoupper(trim($doc['document_type']));
                    if (!in_array($docType, self::ALLOWED_DOCUMENT_TYPES)) {
                        throw new Exception("Invalid document type '$docType'. Allowed values: " . implode(', ', self::ALLOWED_DOCUMENT_TYPES), 400);
                    }

                    $this->model->insertEmployeeDocument([
                        'employee_id'         => $employeeId,
                        'document_type'       => $docType,
                        'document_name'       => trim($doc['document_name']),
                        'document_number'     => $doc['document_number'] ?? null,
                        'document_url'        => trim($doc['document_url']),
                        'issued_by'           => $doc['issued_by'] ?? null,
                        'issued_date'         => $doc['issued_date'] ?? null,
                        'expiry_date'         => $doc['expiry_date'] ?? null,
                        'verification_status' => 'PENDING',
                        'uploaded_by'         => $adminUserId
                    ]);
                }
            }

            $this->model->commit();

            return [
                "status"        => "success",
                "message"       => "Employee onboarded successfully",
                "user_id"       => $userId,
                "employee_id"   => $employeeId,
                "employee_code" => $employeeCode
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 409 ? 409 : ($e->getCode() === 403 ? 403 : 401)));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function onboardTrainer(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;
            $adminRole = strtoupper($decoded->role);

            // Fetch admin details to get gym_id
            $stmt = Database::getConnection()->prepare("SELECT gym_id FROM users WHERE user_id = :id LIMIT 1");
            $stmt->execute(['id' => $adminUserId]);
            $adminUser = $stmt->fetch(PDO::FETCH_ASSOC);
            $gymId = ($adminRole === 'SUPER_ADMIN' && !empty($data['gym_id'])) ? (int)$data['gym_id'] : (int)($adminUser['gym_id'] ?? 0);

            if (!$gymId) {
                http_response_code(400);
                return ["status" => "error", "message" => "Gym ID is required"];
            }

            // Required validations
            $required = ['branch_id', 'name', 'email', 'phone', 'password', 'employment_type', 'salary_type', 'salary_amount', 'joining_date'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || trim((string)$data[$field]) === '') {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Field '$field' is required"];
                }
            }

            if ($this->model->emailExists(strtolower(trim($data['email'])))) {
                http_response_code(409);
                return ["status" => "error", "message" => "Email already registered"];
            }

            $designation = isset($data['designation']) ? strtoupper(trim($data['designation'])) : 'TRAINER';
            if (!in_array($designation, self::ALLOWED_DESIGNATIONS)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid designation. Allowed values: " . implode(', ', self::ALLOWED_DESIGNATIONS)];
            }

            $empType = strtoupper(trim($data['employment_type']));
            if (!in_array($empType, self::ALLOWED_EMPLOYMENT_TYPES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid employment type. Allowed values: " . implode(', ', self::ALLOWED_EMPLOYMENT_TYPES)];
            }

            $salType = strtoupper(trim($data['salary_type']));
            if (!in_array($salType, self::ALLOWED_SALARY_TYPES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid salary type. Allowed values: " . implode(', ', self::ALLOWED_SALARY_TYPES)];
            }

            $availStatus = isset($data['availability_status']) ? strtoupper(trim($data['availability_status'])) : 'AVAILABLE';
            if (!in_array($availStatus, ['AVAILABLE', 'BUSY', 'ON_LEAVE'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid availability status. Allowed values: AVAILABLE, BUSY, ON_LEAVE"];
            }

            $rating = isset($data['rating']) ? (float)$data['rating'] : 0.0;

            // Begin transaction
            $this->model->beginTransaction();

            // 1. Create auth user (Role is 'TRAINER')
            $passwordHash = password_hash($data['password'], PASSWORD_BCRYPT);
            $userData = [
                'gym_id'    => $gymId,
                'branch_id' => (int)$data['branch_id'],
                'name'      => trim($data['name']),
                'email'     => strtolower(trim($data['email'])),
                'phone'     => trim($data['phone']),
                'password'  => $passwordHash,
                'role'      => 'TRAINER',
                'status'    => 1
            ];
            $userId = $this->model->insertEmployeeUser($userData);

            // 2. Generate employee code
            $employeeCode = "EMP-" . str_pad($userId, 5, '0', STR_PAD_LEFT);

            // 3. Create employee record
            $employeeData = [
                'user_id'                 => $userId,
                'gym_id'                  => $gymId,
                'branch_id'               => (int)$data['branch_id'],
                'employee_code'           => $employeeCode,
                'full_name'               => trim($data['name']),
                'email'                   => strtolower(trim($data['email'])),
                'phone'                   => trim($data['phone']),
                'designation'             => $designation,
                'employment_type'         => $empType,
                'salary_type'             => $salType,
                'salary_amount'           => (float)$data['salary_amount'],
                'joining_date'            => trim($data['joining_date']),
                'profile_photo'           => $data['profile_photo'] ?? null,
                'emergency_contact_name'  => $data['emergency_contact_name'] ?? null,
                'emergency_contact_phone' => $data['emergency_contact_phone'] ?? null,
                'address'                 => $data['address'] ?? null,
                'remarks'                 => $data['remarks'] ?? null,
                'status'                  => 'ACTIVE',
                'created_by'              => $adminUserId
            ];
            $employeeId = $this->model->insertEmployee($employeeData);

            // 4. Create trainer profile
            $trainerData = [
                'employee_id'         => $employeeId,
                'specialization'      => $data['specialization'] ?? null,
                'experience'          => isset($data['experience']) ? (float)$data['experience'] : null,
                'certifications'      => $data['certifications'] ?? null,
                'bio'                 => $data['bio'] ?? null,
                'showcase_photo'      => $data['showcase_photo'] ?? null,
                'availability_status' => $availStatus,
                'rating'              => $rating,
                'instagram_url'       => $data['instagram_url'] ?? null,
                'facebook_url'        => $data['facebook_url'] ?? null,
                'linkedin_url'        => $data['linkedin_url'] ?? null
            ];
            $trainerProfileId = $this->model->insertTrainerProfile($trainerData);

            // 5. Onboard documents
            if (!empty($data['documents']) && is_array($data['documents'])) {
                foreach ($data['documents'] as $doc) {
                    if (empty($doc['document_type']) || empty($doc['document_url']) || empty($doc['document_name'])) {
                        throw new Exception("Missing document_type, document_name, or document_url inside documents array", 400);
                    }
                    $docType = strtoupper(trim($doc['document_type']));
                    if (!in_array($docType, self::ALLOWED_DOCUMENT_TYPES)) {
                        throw new Exception("Invalid document type '$docType'. Allowed values: " . implode(', ', self::ALLOWED_DOCUMENT_TYPES), 400);
                    }

                    $this->model->insertEmployeeDocument([
                        'employee_id'         => $employeeId,
                        'document_type'       => $docType,
                        'document_name'       => trim($doc['document_name']),
                        'document_number'     => $doc['document_number'] ?? null,
                        'document_url'        => trim($doc['document_url']),
                        'issued_by'           => $doc['issued_by'] ?? null,
                        'issued_date'         => $doc['issued_date'] ?? null,
                        'expiry_date'         => $doc['expiry_date'] ?? null,
                        'verification_status' => 'PENDING',
                        'uploaded_by'         => $adminUserId
                    ]);
                }
            }

            $this->model->commit();

            return [
                "status"             => "success",
                "message"            => "Trainer onboarded successfully",
                "user_id"            => $userId,
                "employee_id"        => $employeeId,
                "trainer_profile_id" => $trainerProfileId,
                "employee_code"      => $employeeCode
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 409 ? 409 : ($e->getCode() === 403 ? 403 : 401)));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getEmployee(string $accessToken, int $employeeId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'STAFF']);

            $employee = $this->model->fetchEmployeeById($employeeId);
            if (!$employee) {
                http_response_code(404);
                return ["status" => "error", "message" => "Employee not found"];
            }

            $documents = $this->model->fetchEmployeeDocuments($employeeId);

            return [
                "status" => "success",
                "data"   => [
                    "employee_details" => [
                        "employee_id"             => $employee['employee_id'],
                        "employee_code"           => $employee['employee_code'],
                        "full_name"               => $employee['full_name'],
                        "email"                   => $employee['email'],
                        "phone"                   => $employee['phone'],
                        "designation"             => $employee['designation'],
                        "employment_type"         => $employee['employment_type'],
                        "joining_date"            => $employee['joining_date'],
                        "profile_photo"           => $employee['profile_photo'],
                        "emergency_contact_name"  => $employee['emergency_contact_name'],
                        "emergency_contact_phone" => $employee['emergency_contact_phone'],
                        "address"                 => $employee['address'],
                        "remarks"                 => $employee['remarks'],
                        "status"                  => $employee['status'],
                        "created_at"              => $employee['created_at'],
                        "updated_at"              => $employee['updated_at']
                    ],
                    "user_information" => [
                        "user_id"    => $employee['user_id'],
                        "gym_id"     => $employee['gym_id'],
                        "branch_id"  => $employee['branch_id'],
                        "role"       => $employee['role'],
                        "status"     => $employee['user_status'] == 1 ? "ACTIVE" : "INACTIVE",
                        "last_login" => $employee['last_login']
                    ],
                    "salary_information" => [
                        "salary_type"   => $employee['salary_type'],
                        "salary_amount" => $employee['salary_amount']
                    ],
                    "documents" => $documents
                ]
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getTrainer(string $accessToken, int $employeeId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'STAFF', 'TRAINER']);

            $employee = $this->model->fetchEmployeeById($employeeId);
            if (!$employee) {
                http_response_code(404);
                return ["status" => "error", "message" => "Employee not found"];
            }

            $trainerProfile = $this->model->fetchTrainerByEmployeeId($employeeId);
            if (!$trainerProfile) {
                http_response_code(404);
                return ["status" => "error", "message" => "Trainer profile details not found for this employee ID"];
            }

            $documents = $this->model->fetchEmployeeDocuments($employeeId);

            return [
                "status" => "success",
                "data"   => [
                    "employee_details" => [
                        "employee_id"             => $employee['employee_id'],
                        "employee_code"           => $employee['employee_code'],
                        "full_name"               => $employee['full_name'],
                        "email"                   => $employee['email'],
                        "phone"                   => $employee['phone'],
                        "designation"             => $employee['designation'],
                        "employment_type"         => $employee['employment_type'],
                        "joining_date"            => $employee['joining_date'],
                        "profile_photo"           => $employee['profile_photo'],
                        "emergency_contact_name"  => $employee['emergency_contact_name'],
                        "emergency_contact_phone" => $employee['emergency_contact_phone'],
                        "address"                 => $employee['address'],
                        "status"                  => $employee['status']
                    ],
                    "trainer_profile" => $trainerProfile,
                    "documents"       => $documents
                ]
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateEmployee(string $accessToken, int $employeeId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->fetchEmployeeById($employeeId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Employee not found"];
            }

            // Validations
            if (isset($data['designation'])) {
                $designation = strtoupper(trim($data['designation']));
                if (!in_array($designation, self::ALLOWED_DESIGNATIONS)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid designation."];
                }
            }

            if (isset($data['employment_type'])) {
                $empType = strtoupper(trim($data['employment_type']));
                if (!in_array($empType, self::ALLOWED_EMPLOYMENT_TYPES)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid employment type."];
                }
            }

            if (isset($data['salary_type'])) {
                $salType = strtoupper(trim($data['salary_type']));
                if (!in_array($salType, self::ALLOWED_SALARY_TYPES)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid salary type."];
                }
            }

            $this->model->beginTransaction();

            // Update employee table
            $this->model->updateEmployee($employeeId, $data);

            // Update user table if necessary
            $userUpdates = [];
            if (isset($data['full_name'])) {
                $userUpdates['name'] = trim($data['full_name']);
            }
            if (isset($data['phone'])) {
                $userUpdates['phone'] = trim($data['phone']);
            }
            if (isset($data['branch_id'])) {
                $userUpdates['branch_id'] = (int)$data['branch_id'];
            }
            if (isset($data['role'])) {
                $userUpdates['role'] = strtoupper(trim($data['role']));
            }

            if (!empty($userUpdates)) {
                $this->model->updateUser((int)$existing['user_id'], $userUpdates);
            }

            $this->model->commit();

            return ["status" => "success", "message" => "Employee updated successfully"];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401)));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateTrainer(string $accessToken, int $employeeId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->fetchEmployeeById($employeeId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Employee not found"];
            }

            $trainerProfile = $this->model->fetchTrainerByEmployeeId($employeeId);
            if (!$trainerProfile) {
                http_response_code(404);
                return ["status" => "error", "message" => "Trainer profile details not found for this employee ID"];
            }

            if (isset($data['availability_status'])) {
                $status = strtoupper(trim($data['availability_status']));
                if (!in_array($status, ['AVAILABLE', 'BUSY', 'ON_LEAVE'])) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid availability status."];
                }
            }

            $this->model->beginTransaction();

            // Update Employee details
            $this->model->updateEmployee($employeeId, $data);

            // Update Trainer profile
            $this->model->updateTrainerProfile($employeeId, $data);

            // Update user table if necessary
            $userUpdates = [];
            if (isset($data['full_name'])) {
                $userUpdates['name'] = trim($data['full_name']);
            }
            if (isset($data['phone'])) {
                $userUpdates['phone'] = trim($data['phone']);
            }
            if (isset($data['branch_id'])) {
                $userUpdates['branch_id'] = (int)$data['branch_id'];
            }
            if (!empty($userUpdates)) {
                $this->model->updateUser((int)$existing['user_id'], $userUpdates);
            }

            $this->model->commit();

            return ["status" => "success", "message" => "Trainer updated successfully"];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401)));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateEmployeeDocuments(string $accessToken, int $employeeId, array $documents): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            $existing = $this->model->fetchEmployeeById($employeeId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Employee not found"];
            }

            $this->model->beginTransaction();

            foreach ($documents as $doc) {
                $action = strtoupper(trim($doc['action'] ?? 'ADD'));

                if ($action === 'REMOVE') {
                    if (empty($doc['document_id'])) {
                        throw new Exception("Missing document_id for REMOVE action", 400);
                    }
                    $this->model->deleteEmployeeDocument((int)$doc['document_id']);
                } elseif ($action === 'UPDATE') {
                    if (empty($doc['document_id'])) {
                        throw new Exception("Missing document_id for UPDATE action", 400);
                    }
                    
                    $updateFields = [];
                    if (isset($doc['document_type'])) {
                        $docType = strtoupper(trim($doc['document_type']));
                        if (!in_array($docType, self::ALLOWED_DOCUMENT_TYPES)) {
                            throw new Exception("Invalid document type '$docType'", 400);
                        }
                        $updateFields['document_type'] = $docType;
                    }
                    if (isset($doc['document_name'])) $updateFields['document_name'] = trim($doc['document_name']);
                    if (isset($doc['document_number'])) $updateFields['document_number'] = trim($doc['document_number']);
                    if (isset($doc['document_url'])) $updateFields['document_url'] = trim($doc['document_url']);
                    if (isset($doc['issued_by'])) $updateFields['issued_by'] = trim($doc['issued_by']);
                    if (isset($doc['issued_date'])) $updateFields['issued_date'] = trim($doc['issued_date']);
                    if (isset($doc['expiry_date'])) $updateFields['expiry_date'] = trim($doc['expiry_date']);
                    if (isset($doc['verification_status'])) {
                        $vStatus = strtoupper(trim($doc['verification_status']));
                        if (in_array($vStatus, ['PENDING', 'VERIFIED', 'REJECTED'])) {
                            $updateFields['verification_status'] = $vStatus;
                        }
                    }
                    if (isset($doc['remarks'])) $updateFields['remarks'] = trim($doc['remarks']);

                    $this->model->updateEmployeeDocument((int)$doc['document_id'], $updateFields);
                } else {
                    // ADD
                    if (empty($doc['document_type']) || empty($doc['document_url']) || empty($doc['document_name'])) {
                        throw new Exception("Missing document_type, document_name, or document_url for ADD action", 400);
                    }
                    $docType = strtoupper(trim($doc['document_type']));
                    if (!in_array($docType, self::ALLOWED_DOCUMENT_TYPES)) {
                        throw new Exception("Invalid document type '$docType'", 400);
                    }

                    $this->model->insertEmployeeDocument([
                        'employee_id'         => $employeeId,
                        'document_type'       => $docType,
                        'document_name'       => trim($doc['document_name']),
                        'document_number'     => $doc['document_number'] ?? null,
                        'document_url'        => trim($doc['document_url']),
                        'issued_by'           => $doc['issued_by'] ?? null,
                        'issued_date'         => $doc['issued_date'] ?? null,
                        'expiry_date'         => $doc['expiry_date'] ?? null,
                        'verification_status' => 'PENDING',
                        'uploaded_by'         => $adminUserId
                    ]);
                }
            }

            $this->model->commit();

            return ["status" => "success", "message" => "Employee documents updated successfully"];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401)));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateEmployeeStatus(string $accessToken, int $employeeId, string $status): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->fetchEmployeeById($employeeId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Employee not found"];
            }

            $status = strtoupper(trim($status));
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed values: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            $this->model->beginTransaction();

            // Update employees status
            $this->model->updateEmployee($employeeId, ['status' => $status]);

            // Update user status
            // If Terminated or Inactive, disable login (status = 0)
            $userStatus = in_array($status, ['INACTIVE', 'TERMINATED']) ? 0 : 1;
            $this->model->updateUser((int)$existing['user_id'], ['status' => $userStatus]);

            $this->model->commit();

            return ["status" => "success", "message" => "Employee status updated to $status successfully"];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401)));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function listEmployees(string $accessToken, array $filters): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'STAFF']);
            $callerUserId = (int)$decoded->sub;
            $callerRole   = strtoupper($decoded->role);

            // Access check: restrict list by gym_id if not SUPER_ADMIN
            if ($callerRole !== 'SUPER_ADMIN') {
                $stmt = Database::getConnection()->prepare("SELECT gym_id FROM users WHERE user_id = :id LIMIT 1");
                $stmt->execute(['id' => $callerUserId]);
                $callerUser = $stmt->fetch(PDO::FETCH_ASSOC);
                $filters['gym_id'] = (int)($callerUser['gym_id'] ?? 0);
            }

            $page  = max(1, isset($filters['page']) ? (int)$filters['page'] : 1);
            $limit = max(1, isset($filters['limit']) ? (int)$filters['limit'] : 10);
            $offset = ($page - 1) * $limit;

            $employees = $this->model->fetchEmployees($filters, $limit, $offset);
            $total = $this->model->countEmployees($filters);

            return [
                "status"  => "success",
                "message" => "Employees fetched successfully",
                "count"   => count($employees),
                "total"   => $total,
                "page"    => $page,
                "limit"   => $limit,
                "data"    => $employees
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function listTrainers(string $accessToken, array $filters): array
    {
        try {
            // Trainers list can be viewed by all roles (public search is also fine, but we'll enforce verifyRole with any system user for security)
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'STAFF', 'TRAINER', 'MEMBER']);
            $callerUserId = (int)$decoded->sub;
            $callerRole   = strtoupper($decoded->role);

            if ($callerRole !== 'SUPER_ADMIN') {
                $stmt = Database::getConnection()->prepare("SELECT gym_id FROM users WHERE user_id = :id LIMIT 1");
                $stmt->execute(['id' => $callerUserId]);
                $callerUser = $stmt->fetch(PDO::FETCH_ASSOC);
                $filters['gym_id'] = (int)($callerUser['gym_id'] ?? 0);
            }

            $page  = max(1, isset($filters['page']) ? (int)$filters['page'] : 1);
            $limit = max(1, isset($filters['limit']) ? (int)$filters['limit'] : 10);
            $offset = ($page - 1) * $limit;

            $trainers = $this->model->fetchTrainers($filters, $limit, $offset);
            $total = $this->model->countTrainers($filters);

            return [
                "status"  => "success",
                "message" => "Trainers fetched successfully",
                "count"   => count($trainers),
                "total"   => $total,
                "page"    => $page,
                "limit"   => $limit,
                "data"    => $trainers
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}
