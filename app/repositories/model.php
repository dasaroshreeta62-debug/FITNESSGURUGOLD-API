<?php

require_once __DIR__ . '/../config/database.php';

class Model
{
    private PDO $db;

    public function __construct()
    {
        // global $conn;
        // $this->db = $conn;
        $this->db = Database::getConnection();

    }

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
    public function getGyms(array $filters): array
    {
        $sql = "SELECT
                    gym_id,
                    gym_name,
                    email,
                    phone_number,
                    city_id,
                    status,
                    createdDate
                FROM gyms
                WHERE 1=1";

        $params = [];

        if (!empty($filters['status'])) {
            $sql .= " AND status = :status";
            $params[':status'] = $filters['status'];
        }

        if (!empty($filters['city_id'])) {
            $sql .= " AND city_id = :city_id";
            $params[':city_id'] = (int)$filters['city_id'];
        }

        $limit  = max(1, (int)$filters['limit']);
        $offset = (max(1, (int)$filters['page']) - 1) * $limit;

        $sql .= " ORDER BY gym_id DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->db->prepare($sql);

        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }

        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function countGyms(array $filters): int
    {
        $sql = "SELECT COUNT(*) FROM gyms WHERE 1=1";
        $params = [];

        if (!empty($filters['status'])) {
            $sql .= " AND status = :status";
            $params[':status'] = $filters['status'];
        }

        if (!empty($filters['city_id'])) {
            $sql .= " AND city_id = :city_id";
            $params[':city_id'] = (int)$filters['city_id'];
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int)$stmt->fetchColumn();
    }
    public function createGym(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO gyms (
                gym_name,
                email,
                phone_number,
                address_line1,
                city_id,
                district,
                state,
                country,
                pincode,
                status,
                createdDate
            ) VALUES (
                :gym_name,
                :email,
                :phone_number,
                :address_line1,
                :city_id,
                :district_id,
                :state_id,
                :country_id,
                :pincode,
                1,
                NOW()
            )
        ");

        $stmt->execute([
            'gym_name'      => trim($data['gym_name']),
            'email'         => $data['email'] ?? null,
            'phone_number'  => $data['phone_number'] ?? null,
            'address_line1' => $data['address_line1'] ?? null,
            'city_id'       => (int)$data['city_id'],
            'district_id'   => (int)($data['district_id'] ?? null),
            'state_id'      => (int)($data['state_id'] ?? null),
            'country_id'    => (int)($data['country_id'] ?? null),
            'pincode'       => $data['pincode'] ?? null
        ]);

        return (int)$this->db->lastInsertId();
    }
    public function getGymById(int $gymId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT
                g.gym_id,
                g.gym_name,
                g.email,
                g.phone_number,
                g.address_line1,
                c.city_name     AS city,
                s.state_name    AS state,
                co.country_name AS country,
                g.pincode,
                g.status
            FROM gyms g
            LEFT JOIN cities c    ON c.city_id = g.city_id
            LEFT JOIN states s    ON s.state_id = g.state
            LEFT JOIN countries co ON co.country_id = g.country
            WHERE g.gym_id = :gym_id
            LIMIT 1
        ");

        $stmt->execute([
            'gym_id' => $gymId
        ]);

        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result ?: null;
    }
    public function updateGymById(int $gymId, array $data): bool
    {
        $allowedFields = [
            'gym_name',
            'email',
            'phone_number',
            'status'
        ];

        $fields = [];
        $params = ['gym_id' => (int)$gymId];

        foreach ($data as $key => $value) {
            if (in_array($key, $allowedFields)) {
                $fields[] = "$key = :$key";
                $params[$key] = $value;
            }
        }

        if (empty($fields)) {
            return false;
        }

        $sql = "UPDATE gyms SET " . implode(', ', $fields) . " WHERE gym_id = :gym_id";

        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }
    public function getState(): array
    {
        $sql = "SELECT 
                    state_id,
                    country_id,
                    state_name,
                    status,
                    createdDate,
                    createdTime
                FROM states
                ORDER BY state_name ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute();

        $states = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($c) {
            return [
                "state_id"   => (int)$c['state_id'],
                "country_id" => (int)$c['country_id'],
                "state_name" => $c['state_name'],
                "status"     => ((int)$c['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $c['createdDate'] . 'T' . $c['createdTime'] . 'Z'
            ];
        }, $states);
    }
    public function getDistrict(): array
    {
        $sql = "SELECT 
                    district_id,
                    state_id,
                    district_name,
                    status,
                    createdDate,
                    createdTime
                FROM districts
                ORDER BY district_name ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute();

        $states = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($c) {
            return [
                "district_id"   => (int)$c['district_id'],
                "state_id" => (int)$c['state_id'],
                "district_name" => $c['district_name'],
                "status"     => ((int)$c['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $c['createdDate'] . 'T' . $c['createdTime'] . 'Z'
            ];
        }, $states);
    }
    public function getGymBranches(array $filters): array
    {
        $sql = "SELECT 
                    branch_id,
                    gym_id,
                    branch_name,
                    status,
                    createdDate,
                    createdTime
                FROM gym_branches
                WHERE 1=1";

        $params = [];

        $sql .= " ORDER BY branch_id ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        $branches = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($b) {
            return [
                "branch_id"   => (int)$b['branch_id'],
                "gym_id"      => (int)$b['gym_id'],
                "branch_name" => $b['branch_name'],
                "status"      => ((int)$b['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at"  => $b['createdDate'] . 'T' . $b['createdTime'] . 'Z'
            ];
        }, $branches);
    }
    public function insertMember(array $data): bool
    {
        $sql = "INSERT INTO members (
                    full_name, email, phone, password,
                    branch_id, join_date, status, membership_plan,
                    dob, gender, blood_group,
                    height, weight, fitness_level, goal_focus,
                    country, state, district, city,
                    address_line1, address_line2, emergency_phone
                ) VALUES (
                    :full_name, :email, :phone, :password,
                    :branch_id, :join_date, :status, :membership_plan,
                    :dob, :gender, :blood_group,
                    :height, :weight, :fitness_level, :goal_focus,
                    :country, :state, :district, :city,
                    :address_line1, :address_line2, :emergency_phone
                )";

        $stmt = $this->db->prepare($sql);
        return $stmt->execute($data);
    }

}
