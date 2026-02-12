<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
header('Content-Type: application/json');
echo json_encode(["status" => "ok", "message" => "API reachable"]);
exit;

header('Content-Type: application/json');
require_once "db_connection.php";
require_once "../vendor/autoload.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

define('JWT_SECRET', '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1');
define('ACCESS_TOKEN_EXP', 3600); // 1 hour
define('REFRESH_TOKEN_EXP', 604800); // 7 days

$action = $_POST['action'] ?? '';

if($action == 'login')
{
    $email    = trim($_POST['email'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (empty($email) || empty($password)) {
        http_response_code(400);
        echo json_encode([
            "status" => "error",
            "message" => "Email and password are required"
        ]);
        exit;
    }

    /* ---- FETCH USER ---- */
    $sql = "SELECT 
                user_id, gym_id, branch_id, name, email, password, role,phone, status, last_login
            FROM users
            WHERE email = :email
            LIMIT 1";

    $stmt = $conn->prepare($sql);
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    /* ---- INVALID CREDENTIALS ---- */
    if (!$user || !password_verify($password, $user['password'])) {
        http_response_code(401);
        echo json_encode([
            "status" => "error",
            "message" => "Invalid email or password"
        ]);
        exit;
    }

    /* ---- ACCOUNT SUSPENDED ---- */
    if ((int)$user['status'] !== 1) {
        http_response_code(403);
        echo json_encode([
            "status" => "error",
            "message" => "Account suspended. Please contact admin."
        ]);
        exit;
    }

    /* ---- JWT PAYLOAD ---- */
    $now = time();

    $accessPayload = [
        "iss" => "gym_app",
        "iat" => $now,
        "exp" => $now + ACCESS_TOKEN_EXP,
        "sub" => $user['user_id'],
        "role" => $user['role']
    ];

    $refreshPayload = [
        "iat" => $now,
        "exp" => $now + REFRESH_TOKEN_EXP,
        "sub" => $user['user_id']
    ];

    $accessToken  = JWT::encode($accessPayload, JWT_SECRET, 'HS256');
    $refreshToken = JWT::encode($refreshPayload, JWT_SECRET, 'HS256');

    /* ---- UPDATE LAST LOGIN ---- */
    $update = $conn->prepare(
        "UPDATE users SET last_login = NOW() WHERE user_id = :id"
    );
    $update->execute(['id' => $user['user_id']]);

    /* ---- SUCCESS RESPONSE ---- */
    echo json_encode([
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
            "expires_in"    => ACCESS_TOKEN_EXP
        ]
    ]);
    exit;
}
if ($action === 'logout') {

    /* ---- GET AUTH HEADER ---- */
    $headers = getallheaders();

    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode([
            "status" => "error",
            "message" => "Authorization token missing"
        ]);
        exit;
    }

    $authHeader  = $headers['Authorization'];
    $accessToken = str_replace('Bearer ', '', $authHeader);

    $refreshToken = $_POST['refresh_token'] ?? '';

    if (empty($refreshToken)) {
        http_response_code(400);
        echo json_encode([
            "status" => "error",
            "message" => "Refresh token is required"
        ]);
        exit;
    }

    /* ---- VERIFY ACCESS TOKEN ---- */
    try {
        $decoded = JWT::decode($accessToken, new Key(JWT_SECRET, 'HS256'));
        $userId  = $decoded->sub; // <-- you used sub in login payload

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode([
            "status" => "error",
            "message" => "Invalid or expired access token"
        ]);
        exit;
    }

    /* ---- REVOKE REFRESH TOKEN ---- */
    $stmt = $conn->prepare(
        "UPDATE users SET refresh_token = NULL WHERE user_id = :user_id"
    );
    $stmt->execute(['user_id' => $userId]);

    echo json_encode([
        "status" => "success",
        "message" => "Logged out successfully"
    ]);
    exit;
}

if ($action === 'register') {

    /* ---- INPUT ---- */
    $gym_id    = (int)($_POST['gym_id'] ?? 0);
    $branch_id = (int)($_POST['branch_id'] ?? 0);
    $name      = trim($_POST['name'] ?? '');
    $email     = trim($_POST['email'] ?? '');
    $phone     = trim($_POST['phone'] ?? '');
    $password  = $_POST['password'] ?? '';
    $role      = strtoupper($_POST['role'] ?? 'MEMBER');

    /* ---- BASIC VALIDATION ---- */
    if (!$gym_id || !$branch_id || !$name || !$email || !$password) {
        http_response_code(400);
        echo json_encode([
            "status" => "error",
            "message" => "All required fields must be provided"
        ]);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode([
            "status" => "error",
            "message" => "Invalid email format"
        ]);
        exit;
    }

    /* ---- PASSWORD RULE ---- */
    if (
        strlen($password) < 8 ||
        !preg_match('/[A-Z]/', $password) ||
        !preg_match('/[0-9]/', $password)
    ) {
        http_response_code(400);
        echo json_encode([
            "status" => "error",
            "message" => "Password must be at least 8 characters in length and include at least one uppercase letter and one numeric digit."
        ]);
        exit;
    }

    /* ---- CHECK EMAIL EXISTS ---- */
    $check = $conn->prepare("SELECT user_id FROM users WHERE email = :email");
    $check->execute(['email' => $email]);

    if ($check->fetch()) {
        http_response_code(409);
        echo json_encode([
            "status" => "error",
            "message" => "Email already registered"
        ]);
        exit;
    }

    /* ---- HASH PASSWORD ---- */
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    /* ---- INSERT USER ---- */
    $insert = $conn->prepare("
        INSERT INTO users (gym_id, branch_id, name, email, phone, password, role)
        VALUES (:gym_id, :branch_id, :name, :email, :phone, :password, :role)
    ");

    $insert->execute([
        'gym_id'    => $gym_id,
        'branch_id' => $branch_id,
        'name'      => $name,
        'email'     => $email,
        'phone'     => $phone,
        'password'  => $passwordHash,
        'role'      => $role
    ]);

    $userId = $conn->lastInsertId();

    /* ---- GENERATE TOKENS ---- */
    $now = time();

    $accessPayload = [
        "iss"  => "gym_app",
        "iat"  => $now,
        "exp"  => $now + ACCESS_TOKEN_EXP,
        "sub"  => $userId,
        "role" => $role
    ];

    $refreshPayload = [
        "iat" => $now,
        "exp" => $now + REFRESH_TOKEN_EXP,
        "sub" => $userId
    ];

    $accessToken  = JWT::encode($accessPayload, JWT_SECRET, 'HS256');
    $refreshToken = JWT::encode($refreshPayload, JWT_SECRET, 'HS256');

    /* ---- RESPONSE ---- */
    http_response_code(201);
    echo json_encode([
        "status" => "success",
        "message" => "User registered successfully",
        "user" => [
            "user_id"    => (int)$userId,
            "gym_id"     => $gym_id,
            "branch_id"  => $branch_id,
            "name"       => $name,
            "email"      => $email,
            "phone"      => $phone,
            "role"       => $role,
            "status"     => "ACTIVE",
            "created_at" => gmdate("Y-m-d\TH:i:s\Z")
        ],
        "tokens" => [
            "access_token"  => $accessToken,
            "refresh_token" => $refreshToken,
            "expires_in"    => ACCESS_TOKEN_EXP
        ]
    ]);
    exit;
}
if ($action === 'refresh') {

    $refreshToken = $_POST['refresh_token'] ?? '';

    if (empty($refreshToken)) {
        http_response_code(400);
        echo json_encode([
            "status" => "error",
            "message" => "Refresh token is required"
        ]);
        exit;
    }

    /* ---- VERIFY REFRESH TOKEN ---- */
    try {
        $decoded = JWT::decode($refreshToken, new Key(JWT_SECRET, 'HS256'));

        // user id from token
        $userId = (int)$decoded->sub;

    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode([
            "status" => "error",
            "message" => "Invalid or expired refresh token"
        ]);
        exit;
    }

    /* ---- VERIFY REFRESH TOKEN IN DB ---- */
    $stmt = $conn->prepare("
        SELECT user_id, role, status 
        FROM users 
        WHERE user_id = :user_id 
          AND refresh_token = :refresh_token
        LIMIT 1
    ");

    $stmt->execute([
        'user_id' => $userId,
        'refresh_token' => $refreshToken
    ]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        http_response_code(401);
        echo json_encode([
            "status" => "error",
            "message" => "Invalid or expired refresh token"
        ]);
        exit;
    }

    if ((int)$user['status'] !== 1) {
        http_response_code(403);
        echo json_encode([
            "status" => "error",
            "message" => "Account suspended. Please contact admin."
        ]);
        exit;
    }

    /* ---- GENERATE NEW ACCESS TOKEN ---- */
    $now = time();

    $accessPayload = [
        "iss"  => "gym_app",
        "iat"  => $now,
        "exp"  => $now + ACCESS_TOKEN_EXP,
        "sub"  => $user['user_id'],
        "role" => $user['role']
    ];

    $newAccessToken = JWT::encode($accessPayload, JWT_SECRET, 'HS256');

    echo json_encode([
        "status" => "success",
        "access_token" => $newAccessToken,
        "expires_in" => ACCESS_TOKEN_EXP
    ]);
    exit;
}

