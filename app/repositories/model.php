<?php

require_once __DIR__ . '/../config/database.php';

class Model
{
    private PDO $db;

    public function __construct()
    {
        global $conn;
        $this->db = $conn;
    }

    // /* ===================== USERS ===================== */

    // public function getAllUsers(): array
    // {
    //     $stmt = $this->db->query("SELECT * FROM users");
    //     return $stmt->fetchAll();
    // }

    public function getUserByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare(
            "SELECT * FROM users WHERE email = :email LIMIT 1"
        );
        $stmt->execute(['email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function updateLogin(int $userId, string $refreshToken): void
    {
        $stmt = $this->db->prepare(
            "UPDATE users
             SET last_login = NOW(), refresh_token = :token
             WHERE user_id = :id"
        );
        $stmt->execute([
            'token' => $refreshToken,
            'id' => $userId
        ]);
    }
    public function validateRefreshToken(int $userId, string $refreshToken): bool
    {
        $stmt = $this->db->prepare(
            "SELECT user_id
            FROM users
            WHERE user_id = :id
            AND refresh_token = :token
            LIMIT 1"
        );

        $stmt->execute([
            'id'    => $userId,
            'token' => $refreshToken
        ]);

        return (bool)$stmt->fetch();
    }

    public function revokeRefreshToken(int $userId): void
    {
        $stmt = $this->db->prepare(
            "UPDATE users
            SET refresh_token = NULL
            WHERE user_id = :id"
        );

        $stmt->execute(['id' => $userId]);
    }
    public function createUser(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO users (
                gym_id,
                branch_id,
                name,
                email,
                phone,
                password,
                role,
                status,
                createdDate
            ) VALUES (
                :gym_id,
                :branch_id,
                :name,
                :email,
                :phone,
                :password,
                :role,
                1,
                NOW()
            )
        ");

        $stmt->execute([
            'gym_id'    => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'name'      => $data['name'],
            'email'     => $data['email'],
            'phone'     => $data['phone'],
            'password'  => $data['password'],
            'role'      => $data['role']
        ]);

        return (int)$this->db->lastInsertId();
    }

}
