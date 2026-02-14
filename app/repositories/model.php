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
    public function getUserProfileById(int $userId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT
                user_id,
                gym_id,
                branch_id,
                name,
                email,
                phone,
                role,
                status,
                createdDate,
                updatedDate
            FROM users
            WHERE user_id = :id
            LIMIT 1
        ");

        $stmt->execute(['id' => $userId]);

        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }
    public function updateUserProfile(int $userId, array $data): bool
    {
        $fields = [];
        $params = [];

        foreach ($data as $key => $value) {
            $fields[] = "$key = :$key";
            $params[":$key"] = $value;
        }

        $params[':user_id'] = $userId;

        $sql = "
            UPDATE users
            SET " . implode(', ', $fields) . ",
                updatedDate = CURDATE(),
                updatedTime = CURTIME()
            WHERE user_id = :user_id
        ";

        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }
    public function getUsers(array $filters, int $limit, int $offset): array
    {
        $sql = "SELECT 
                    user_id,
                    gym_id,
                    branch_id,
                    name,
                    email,
                    phone,
                    role,
                    status,
                    createdDate,
                    createdTime
                FROM users
                WHERE 1=1";

        $params = [];

        if (!empty($filters['role'])) {
            $sql .= " AND role = :role";
            $params[':role'] = strtoupper($filters['role']);
        }

        if (!empty($filters['status'])) {
            $sql .= " AND status = :status";
            $params[':status'] = ($filters['status'] === 'ACTIVE') ? 1 : 0;
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND gym_id = :gym_id";
            $params[':gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND branch_id = :branch_id";
            $params[':branch_id'] = (int)$filters['branch_id'];
        }

        $sql .= " ORDER BY user_id DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->db->prepare($sql);

        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }

        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

        $stmt->execute();

        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Format output
        return array_map(function ($u) {
            return [
                "user_id"    => (int)$u['user_id'],
                "gym_id"     => (int)$u['gym_id'],
                "branch_id"  => (int)$u['branch_id'],
                "name"       => $u['name'],
                "email"      => $u['email'],
                "phone"      => $u['phone'],
                "role"       => strtoupper($u['role']),
                "status"     => ((int)$u['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "createdDate"=> $u['createdDate'] . 'T' . $u['createdTime'] . 'Z'
            ];
        }, $users);
    }
    public function countUsers(array $filters): int
    {
        $sql = "SELECT COUNT(*) FROM users WHERE 1=1";
        $params = [];

        if (!empty($filters['role'])) {
            $sql .= " AND role = :role";
            $params[':role'] = strtoupper($filters['role']);
        }

        if (!empty($filters['status'])) {
            $sql .= " AND status = :status";
            $params[':status'] = ($filters['status'] === 'ACTIVE') ? 1 : 0;
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND gym_id = :gym_id";
            $params[':gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND branch_id = :branch_id";
            $params[':branch_id'] = (int)$filters['branch_id'];
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int)$stmt->fetchColumn();
    }
}
