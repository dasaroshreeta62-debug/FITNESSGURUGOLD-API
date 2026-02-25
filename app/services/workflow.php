<?php

require_once __DIR__ . '/../repositories/model.php';
require_once __DIR__ . '/../../vendor/autoload.php'; // ✅ correct path

use Firebase\JWT\JWT;        // ✅ REQUIRED
use Firebase\JWT\Key;        // (for decode later)

class Workflow
{
    private Model $model;

    private const JWT_SECRET  = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';
    private const ACCESS_EXP  = 3600;
    private const REFRESH_EXP = 604800;

    public function __construct()
    {
        $this->model = new Model();
    }

    public function login(string $email, string $password): array
    {
        $user = $this->model->getUserByEmail($email);

        if (!$user || !password_verify($password, $user['password'])) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid email or password"
            ];
        }

        if ((int)$user['status'] !== 1) {
            http_response_code(403);
            return [
                "status" => "error",
                "message" => "Account suspended. Please contact admin."
            ];
        }

        $now = time();

        $accessToken = JWT::encode([
            "iss"  => "fitness-guru",
            "sub"  => $user['user_id'],
            "role" => $user['role'],
            "iat"  => $now,
            "exp"  => $now + self::ACCESS_EXP
        ], self::JWT_SECRET, 'HS256');

        $refreshToken = JWT::encode([
            "sub" => $user['user_id'],
            "iat" => $now,
            "exp" => $now + self::REFRESH_EXP
        ], self::JWT_SECRET, 'HS256');

        $this->model->updateLogin($user['user_id'], $refreshToken);

        return [
            "status" => "success",
            "message" => "Login successful",
            "user" => [
                "user_id"    => (int)$user['user_id'],
                "gym_id"     => (int)$user['gym_id'],
                "branch_id"  => (int)$user['branch_id'],
                "name"       => $user['name'],
                "email"      => $user['email'],
                "phone"      => $user['phone'],
                "role"       => strtoupper($user['role']),
                "status"     => "ACTIVE",
                "last_login" => $user['last_login']
            ],
            "tokens" => [
                "access_token"  => $accessToken,
                "refresh_token" => $refreshToken,
                "expires_in"    => self::ACCESS_EXP
            ]
        ];
    }
    public function logout(string $accessToken, string $refreshToken): array
    {
        try {
            // 1️⃣ Verify access token
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $userId = (int)$decoded->sub;

            // 2️⃣ Validate refresh token against DB
            $isValid = $this->model->validateRefreshToken($userId, $refreshToken);

            if (!$isValid) {
                http_response_code(401);
                return [
                    "status" => "error",
                    "message" => "Invalid refresh token"
                ];
            }

            // 3️⃣ Revoke refresh token
            $this->model->revokeRefreshToken($userId);

            // (Optional) Access-token blacklist can be added here

            return [
                "status" => "success",
                "message" => "Logged out successfully"
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired access token"
            ];
        }
    }
    public function register(array $data): array
    {
        // Email already exists check
        if ($this->model->getUserByEmail($data['email'])) {
            http_response_code(409);
            return [
                "status" => "error",
                "message" => "Email already registered"
            ];
        }

        // Password validation
        if (!preg_match('/^(?=.*[A-Z])(?=.*\d).{8,}$/', $data['password'])) {
            http_response_code(400);
            return [
                "status" => "error",
                "message" => "Password must contain at least one uppercase letter and one number"
            ];
        }

        // Hash password (bcrypt)
        $passwordHash = password_hash($data['password'], PASSWORD_BCRYPT);

        // Create user
        $userId = $this->model->createUser([
            'gym_id'    => (int)$data['gym_id'],
            'branch_id' => (int)$data['branch_id'],
            'name'      => trim($data['name']),
            'email'     => strtolower(trim($data['email'])),
            'phone'     => trim($data['phone']),
            'password'  => $passwordHash,
            'role'      => strtoupper($data['role'])
        ]);

        $now = time();

        // Generate tokens
        $accessToken = JWT::encode([
            "iss"  => "fitness-guru",
            "sub"  => $userId,
            "role" => strtoupper($data['role']),
            "iat"  => $now,
            "exp"  => $now + self::ACCESS_EXP
        ], self::JWT_SECRET, 'HS256');

        $refreshToken = JWT::encode([
            "sub" => $userId,
            "iat" => $now,
            "exp" => $now + self::REFRESH_EXP
        ], self::JWT_SECRET, 'HS256');

        // Store refresh token
        $this->model->updateLogin($userId, $refreshToken);

        http_response_code(201);

        return [
            "status" => "success",
            "message" => "User registered successfully",
            "user" => [
                "user_id"    => $userId,
                "gym_id"     => (int)$data['gym_id'],
                "branch_id"  => (int)$data['branch_id'],
                "name"       => $data['name'],
                "email"      => $data['email'],
                "phone"      => $data['phone'],
                "role"       => strtoupper($data['role']),
                "status"     => "ACTIVE",
                "created_at" => gmdate('Y-m-d\TH:i:s\Z')
            ],
            "tokens" => [
                "access_token"  => $accessToken,
                "refresh_token" => $refreshToken,
                "expires_in"    => self::ACCESS_EXP
            ]
        ];
    }
    public function getProfile(string $accessToken): array
    {
        // 🔍 DEBUG: log received token
        // error_log('ACCESS TOKEN RECEIVED: ' . $accessToken);

        try {
            // Decode JWT
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            // 🔍 DEBUG: log decoded payload
            // error_log('JWT DECODED: ' . print_r($decoded, true));

            $userId = (int)$decoded->sub;

            // Fetch user profile
            $user = $this->model->getUserProfileById($userId);

            if (!$user) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "User not found"
                ];
            }

            return [
                "status" => "success",
                "user" => [
                    "user_id"   => (int)$user['user_id'],
                    "gym_id"    => (int)$user['gym_id'],
                    "branch_id" => (int)$user['branch_id'],
                    "name"      => $user['name'],
                    "email"     => $user['email'],
                    "phone"     => $user['phone'],
                    "role"      => strtoupper($user['role']),
                    "status"    => ((int)$user['status'] === 1) ? "ACTIVE" : "INACTIVE"
                ]
            ];

        } catch (\Throwable $e) {
            // 🔥 VERY IMPORTANT DEBUG
            error_log('JWT ERROR: ' . $e->getMessage());

            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function updateProfile(string $accessToken, array $data): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $userId = (int)$decoded->sub;
            $role   = strtoupper($decoded->role);

            $user = $this->model->getUserProfileById($userId);
            if (!$user) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "User not found"
                ];
            }

            // Allowed fields
            $updateData = [
                'name'  => trim($data['name'] ?? $user['name']),
                'phone' => trim($data['phone'] ?? $user['phone']),
                'email' => trim($data['email'] ?? $user['email'])
            ];

            // Email uniqueness check
            if ($updateData['email'] !== $user['email']) {
                if ($this->model->getUserByEmail($updateData['email'])) {
                    http_response_code(409);
                    return [
                        "status" => "error",
                        "message" => "Email already in use"
                    ];
                }
            }

            // Admin-only fields
            if ($role === 'ADMIN') {
                if (isset($data['role'])) {
                    $updateData['role'] = strtoupper($data['role']);
                }
                if (isset($data['status'])) {
                    $updateData['status'] = (int)$data['status'];
                }
            }

            $this->model->updateUserProfile($userId, $updateData);

            $updatedUser = $this->model->getUserProfileById($userId);

            return [
                "status" => "success",
                "message" => "Profile updated successfully",
                "user" => [
                    "user_id"    => (int)$updatedUser['user_id'],
                    "gym_id"     => (int)$updatedUser['gym_id'],
                    "branch_id"  => (int)$updatedUser['branch_id'],
                    "name"       => $updatedUser['name'],
                    "email"      => $updatedUser['email'],
                    "phone"      => $updatedUser['phone'],
                    "role"       => strtoupper($updatedUser['role']),
                    "status"     => ((int)$updatedUser['status'] === 1) ? "ACTIVE" : "INACTIVE",
                    "updatedDate"=> gmdate('Y-m-d\TH:i:s\Z')
                ]
            ];

        } catch (\Throwable $e) {
            http_response_code(403);
            return [
                "status" => "error",
                "message" => "You are not allowed to edit this profile"
            ];
        }
    }

    public function listUsers(string $accessToken, array $filters): array
    {
        try {
            // Decode JWT
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $role = strtoupper($decoded->role ?? '');

            // Admin-only access
            if (!in_array($role, ['ADMIN', 'SUPER_ADMIN'])) {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Access denied — admin privileges required"
                ];
            }

            $page  = max(1, (int)$filters['page']);
            $limit = max(1, (int)$filters['limit']);
            $offset = ($page - 1) * $limit;

            // Fetch data
            $users  = $this->model->getUsers($filters, $limit, $offset);
            $total  = $this->model->countUsers($filters);

            return [
                "status" => "success",
                "meta" => [
                    "page"  => $page,
                    "limit"=> $limit,
                    "total"=> $total
                ],
                "users" => $users
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function getGyms(string $accessToken, array $filters): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            if (!in_array(strtoupper($decoded->role), ['ADMIN', 'SUPER_ADMIN'])) {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Access denied"
                ];
            }

            $data  = $this->model->getGyms($filters);
            $total = $this->model->countGyms($filters);

            return [
                "status" => "success",
                "meta" => [
                    "page"  => $filters['page'],
                    "limit"=> $filters['limit'],
                    "total"=> $total
                ],
                "gyms" => $data
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function createGym(string $accessToken, array $data): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            // SUPER ADMIN only
            if (strtoupper($decoded->role) !== 'SUPER_ADMIN') {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Only Super Admin can create gyms"
                ];
            }

            // Create gym
            $gymId = $this->model->createGym($data);

            http_response_code(201);

            return [
                "status" => "success",
                "message" => "Gym created successfully",
                "gym" => [
                    "gym_id"       => $gymId,
                    "gym_name"     => $data['gym_name'],
                    "email"        => $data['email'] ?? null,
                    "phone_number" => $data['phone_number'] ?? null,
                    "status"       => "ACTIVE"
                ]
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function getGymDetails(string $accessToken, int $gymId): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $role = strtoupper($decoded->role);

            if (!in_array($role, ['SUPER_ADMIN', 'ADMIN'])) {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Access denied"
                ];
            }

            // Gym admin can access only own gym
            if ($role === 'ADMIN' && (int)$decoded->gym_id !== $gymId) {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Unauthorized gym access"
                ];
            }

            $gym = $this->model->getGymById($gymId);

            if (!$gym) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "Gym not found"
                ];
            }

            return [
                "status" => "success",
                "gym" => $gym
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function updateGym(string $accessToken, int $gymId, array $data): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $role = strtoupper($decoded->role ?? '');
            $tokenGymId = (int)($decoded->gym_id ?? 0);

            // Role validation
            if (!in_array($role, ['SUPER_ADMIN', 'GYM_ADMIN'])) {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Access denied"
                ];
            }

            // Gym admin restriction
            if ($role === 'GYM_ADMIN' && $tokenGymId !== $gymId) {
                http_response_code(403);
                return [
                    "status" => "error",
                    "message" => "Unauthorized gym access"
                ];
            }

            // Prevent Gym Admin from updating status
            if ($role === 'GYM_ADMIN' && isset($data['status'])) {
                unset($data['status']);
            }

            if (empty($data)) {
                http_response_code(400);
                return [
                    "status" => "error",
                    "message" => "No data provided for update"
                ];
            }

            $updated = $this->model->updateGymById($gymId, $data);

            if (!$updated) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "Gym not found or no changes made"
                ];
            }

            $gym = $this->model->getGymById($gymId);

            return [
                "status" => "success",
                "message" => "Gym updated successfully",
                "gym" => $gym
            ];

        } catch (\Throwable $e) {
            error_log('UPDATE GYM JWT ERROR: ' . $e->getMessage());

            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function listCountry(string $accessToken): array
    {
        try {
            // Decode JWT
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $role = strtoupper($decoded->role ?? '');

            // Optional: role validation
            // if (!in_array($role, ['ADMIN', 'SUPER_ADMIN'])) {
            //     throw new Exception('Unauthorized role');
            // }

            $countries = $this->model->getCountry();

            return [
                "status" => "success",
                "data"   => $countries
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function listState(string $accessToken, int $country_id): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            // Optional role validation
            // $role = strtoupper($decoded->role ?? '');
            // if (!in_array($role, ['ADMIN', 'SUPER_ADMIN'])) { ... }

            $states = $this->model->getStateByCountry($country_id);

            return [
                "status" => "success",
                "data"   => $states
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function listDistrict(string $accessToken, int $state_id): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            // Optional role validation
            // $role = strtoupper($decoded->role ?? '');
            // if (!in_array($role, ['ADMIN', 'SUPER_ADMIN'])) { ... }

            $districts = $this->model->getDistrictByState($state_id);

            return [
                "status" => "success",
                "data"   => $districts
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function listGymBranches(string $accessToken, array $filters): array
    {
        try {
            /* ========= AUTH ========= */
            JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $branches = $this->model->getGymBranches($filters);

            return [
                "status"  => "success",
                "message" => "Gym branches fetched successfully",
                "count"   => count($branches),
                "data"    => $branches
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status"  => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function listCities(string $accessToken, array $filters): array
    {
        try {
            /* ========= AUTH ========= */
            JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $cities = $this->model->getCities($filters);

            return [
                "status"  => "success",
                "message" => "City list fetched successfully",
                "count"   => count($cities),
                "data"    => $cities
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status"  => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function addMember(array $data): bool
    {
        $payload = [
            'name'             => $data['name'],
            'email'            => $data['email'],
            'phone'            => $data['phone'],
            'password'         => password_hash($data['password'], PASSWORD_BCRYPT),

            'gym_id'           => $data['gym_id'],
            'branch_id'        => $data['branch_id'],

            'join_date'        => $data['join_date'] ?? date('Y-m-d'),
            'status'           => $data['status'] ?? 1,
            'membership_plan'  => $data['membership_plan'] ?? null,

            'dob'              => $data['dob'] ?? null,
            'gender'           => $data['gender'] ?? null,
            'blood_group'      => $data['blood_group'] ?? null,
            'height'           => $data['height'] ?? null,
            'weight'           => $data['weight'] ?? null,
            'fitness_level'    => $data['fitness_level'] ?? null,
            'goal_focus'       => $data['goal_focus'] ?? null,

            'country'          => $data['country'] ?? null,
            'state'            => $data['state'] ?? null,
            'district'         => $data['district'] ?? null,
            'city'             => $data['city'] ?? null,
            'address_line1'    => $data['address_line1'] ?? null,
            'address_line2'    => $data['address_line2'] ?? null,
            'emergency_contact'  => $data['emergency_contact'] ?? null
        ];

        return $this->model->insertMember($payload);
    }
    public function getMemberDetails(int $user_id): array|false
    {
        // 🔒 Business rules can be added here later
        // ex: role check, gym scope, branch scope, permissions

        return $this->model->fetchMemberDetails($user_id);
    }
    public function getAllMemberDetails(): array
    {
        // 🔒 Later: role / gym / branch validation
        return $this->model->fetchAllMemberDetails();
    }
    public function updateMember(string $accessToken, array $data): array
    {
        try {
            /* ========= AUTH ========= */
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            /* ========= OPTIONAL ROLE CHECK ========= */
            $role = strtoupper($decoded->role ?? '');

            // Optional (enable if needed)
            // if (!in_array($role, ['ADMIN', 'STAFF'])) {
            //     http_response_code(403);
            //     return [
            //         "status" => "error",
            //         "message" => "Unauthorized access"
            //     ];
            // }

            /* ========= PASSWORD VALIDATION ========= */
            if (!empty($data['new_password'])) {

                if ($data['new_password'] !== ($data['confirm_password'] ?? '')) {
                    http_response_code(400);
                    return [
                        "status" => "error",
                        "message" => "Password confirmation does not match"
                    ];
                }

                $data['hashed_password'] = password_hash(
                    $data['new_password'],
                    PASSWORD_BCRYPT
                );
            }

            /* ========= UPDATE ========= */
            $this->model->updateMember($data);

            return [
                "status" => "success",
                "message" => "Member details updated successfully"
            ];

        } catch (\Throwable $e) {

            error_log('UPDATE MEMBER ERROR: ' . $e->getMessage());

            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function listMembershipPlan(string $accessToken,int $gym_id,int $branch_id): array
    {
        try {
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            // Optional role validation
            // $role = strtoupper($decoded->role ?? '');
            // if (!in_array($role, ['ADMIN', 'OWNER'])) { ... }

            $plans = $this->model->getMembershipPlanByGymBranch(
                $gym_id,
                $branch_id
            );

            if (empty($plans)) {
                return [
                    "status"  => "success",
                    "message" => "No membership plans found",
                    "data"    => []
                ];
            }

            return [
                "status" => "success",
                "data"   => $plans
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token"
            ];
        }
    }
    public function addAttendance(string $accessToken, array $data): array
    {
        try {
            JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));

            $payload = [
                'user_id'         => (int)$data['user_id'],
                'gym_id'          => (int)$data['gym_id'],
                'branch_id'       => (int)$data['branch_id'],
                'shift_id'        => $data['shift_id'] ?? null,
                'role_type'       => $data['role_type'] ?? 'MEMBER',
                'attendance_date' => $data['attendance_date'],
                'total_sessions'  => $data['total_sessions'] ?? 1,
                'status'          => $data['status'] ?? 'ON_TIME',

                /* SESSION DATA */
                'check_in_time'   => $data['check_in_time'],
                'source'          => $data['source'] ?? 'DEVICE',
                'device_id'       => $data['device_id'],
                'remarks'         => $data['remarks'] ?? null
            ];

            $this->model->insertAttendanceWithSession($payload);

            return [
                "status"  => "success",
                "message" => "Attendance & session recorded successfully"
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status" => "error",
                "message" => "Failed to record attendance",
                "error" => $e->getMessage()
            ];
        }
    }
    public function checkOutAttendance(string $accessToken, array $data): array
    {
        try {
            /* ========= AUTH ========= */
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            /* ========= CHECKOUT ========= */
            $result = $this->model->checkOutAttendance($data);

            if (!$result) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "No active session found for checkout"
                ];
            }

            return [
                "status"  => "success",
                "message" => "Checked out successfully"
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Checkout failed",
                "error"   => $e->getMessage()
            ];
        }
    }
    public function listAttendance(string $accessToken, array $filters): array
    {
        try {
            /* ========= AUTH ========= */
            $decoded = JWT::decode(
                $accessToken,
                new Key(self::JWT_SECRET, 'HS256')
            );

            $data = $this->model->getAttendanceList($filters);

            return [
                "status" => "success",
                "page"   => (int)$filters['page'],
                "limit"  => (int)$filters['limit'],
                "data"   => $data
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Failed to fetch attendance list",
                "error"   => $e->getMessage()
            ];
        }
    }
    public function viewUserAttendanceWithSessions(
        string $accessToken,
        int $userId,
        string $date
    ): array {
        try {
            JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));

            $attendance = $this->model->getUserAttendanceSummary($userId, $date);

            if (!$attendance) {
                return [
                    "status" => "error",
                    "message" => "Attendance not found"
                ];
            }

            $sessions = $this->model->getAttendanceSessions(
                $attendance['attendance_id']
            );

            return [
                "status" => "success",
                "data" => [
                    "user" => [
                        "name"   => $attendance['user_name'],
                        "email"  => $attendance['email'],
                        "phone"  => $attendance['phone'],
                        "role"   => $attendance['role'],
                        "branch" => $attendance['branch_name'],
                        "date"   => $attendance['attendance_date']
                    ],
                    "attendance_summary" => [
                        "total_sessions" => (int)$attendance['total_sessions'],
                        "total_duration" => $attendance['total_duration_min'],
                        "status"          => $attendance['status']
                    ],
                    "sessions" => $sessions
                ]
            ];

        } catch (\Throwable $e) {
            http_response_code(401);
            return [
                "status" => "error",
                "message" => "Invalid or expired token",
                "error"   => $e->getMessage()
            ];
        }
    }
}
