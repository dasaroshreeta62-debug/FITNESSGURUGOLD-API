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
}
