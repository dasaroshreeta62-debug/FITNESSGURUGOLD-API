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
            'id' => $userId,
            'token' => $refreshToken
        ]);

        return (bool) $stmt->fetch();
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
            'gym_id' => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'name' => $data['name'],
            'email' => $data['email'],
            'phone' => $data['phone'],
            'password' => $data['password'],
            'role' => $data['role']
        ]);

        return (int) $this->db->lastInsertId();
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
            $params[':gym_id'] = (int) $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND branch_id = :branch_id";
            $params[':branch_id'] = (int) $filters['branch_id'];
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
                "user_id" => (int) $u['user_id'],
                "gym_id" => (int) $u['gym_id'],
                "branch_id" => (int) $u['branch_id'],
                "name" => $u['name'],
                "email" => $u['email'],
                "phone" => $u['phone'],
                "role" => strtoupper($u['role']),
                "status" => ((int) $u['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "createdDate" => $u['createdDate'] . 'T' . $u['createdTime'] . 'Z'
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
            $params[':gym_id'] = (int) $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND branch_id = :branch_id";
            $params[':branch_id'] = (int) $filters['branch_id'];
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int) $stmt->fetchColumn();
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
            $params[':city_id'] = (int) $filters['city_id'];
        }

        $limit = max(1, (int) $filters['limit']);
        $offset = (max(1, (int) $filters['page']) - 1) * $limit;

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
            $params[':city_id'] = (int) $filters['city_id'];
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int) $stmt->fetchColumn();
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
            'gym_name' => trim($data['gym_name']),
            'email' => $data['email'] ?? null,
            'phone_number' => $data['phone_number'] ?? null,
            'address_line1' => $data['address_line1'] ?? null,
            'city_id' => (int) $data['city_id'],
            'district_id' => (int) ($data['district_id'] ?? null),
            'state_id' => (int) ($data['state_id'] ?? null),
            'country_id' => (int) ($data['country_id'] ?? null),
            'pincode' => $data['pincode'] ?? null
        ]);

        return (int) $this->db->lastInsertId();
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
        $params = ['gym_id' => (int) $gymId];

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
    public function getCountry(): array
    {
        $sql = "SELECT 
                    country_id,
                    country_name,
                    status,
                    createdDate,
                    createdTime
                FROM countries
                ORDER BY country_name ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute();

        $states = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($c) {
            return [
                "country_id" => (int) $c['country_id'],
                "country_name" => $c['country_name'],
                "status" => ((int) $c['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $c['createdDate'] . 'T' . $c['createdTime'] . 'Z'
            ];
        }, $states);
    }
    public function getStateByCountry(int $country_id): array
    {
        $sql = "
            SELECT 
                state_id,
                country_id,
                state_name,
                status,
                createdDate,
                createdTime
            FROM states
            WHERE country_id = :country_id
            ORDER BY state_name ASC
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'country_id' => $country_id
        ]);

        $states = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($s) {
            return [
                "state_id" => (int) $s['state_id'],
                "country_id" => (int) $s['country_id'],
                "state_name" => $s['state_name'],
                "status" => ((int) $s['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $s['createdDate'] . 'T' . $s['createdTime'] . 'Z'
            ];
        }, $states);
    }
    public function getDistrictByState(int $state_id): array
    {
        $sql = "
            SELECT 
                district_id,
                state_id,
                district_name,
                status,
                createdDate,
                createdTime
            FROM districts
            WHERE state_id = :state_id
            ORDER BY district_name ASC
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'state_id' => $state_id
        ]);

        $districts = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($d) {
            return [
                "district_id" => (int) $d['district_id'],
                "state_id" => (int) $d['state_id'],
                "district_name" => $d['district_name'],
                "status" => ((int) $d['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $d['createdDate'] . 'T' . $d['createdTime'] . 'Z'
            ];
        }, $districts);
    }
    public function getGymBranches(array $filters): array
    {
        $sql = "
            SELECT 
                branch_id,
                gym_id,
                branch_name,
                status,
                createdDate,
                createdTime
            FROM gym_branches
            WHERE 1=1
        ";

        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND gym_id = :gym_id";
            $params['gym_id'] = $filters['gym_id'];
        }

        $sql .= " ORDER BY branch_name ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        $branches = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($b) {
            return [
                "branch_id" => (int) $b['branch_id'],
                "gym_id" => (int) $b['gym_id'],
                "branch_name" => $b['branch_name'],
                "status" => ((int) $b['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $b['createdDate'] . 'T' . $b['createdTime'] . 'Z'
            ];
        }, $branches);
    }

    public function getAdminGymBranches(int $gymId): array
    {
        $sql = "
            SELECT 
                gb.*,
                c.city_name,
                d.district_name,
                s.state_name
            FROM gym_branches gb
            LEFT JOIN cities c ON c.city_id = gb.city_id
            LEFT JOIN districts d ON d.district_id = gb.district_id
            LEFT JOIN states s ON s.state_id = gb.state_id
            WHERE gb.gym_id = :gym_id
            ORDER BY gb.branch_name ASC
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute(['gym_id' => $gymId]);
        $branches = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($b) {
            return [
                "branch_id" => (int) $b['branch_id'],
                "gym_id" => (int) $b['gym_id'],
                "branch_name" => $b['branch_name'],
                "address_line1" => $b['address_line1'],
                "address_line2" => $b['address_line2'],
                "city_id" => $b['city_id'] !== null ? (int) $b['city_id'] : null,
                "city_name" => $b['city_name'],
                "district_id" => $b['district_id'] !== null ? (int) $b['district_id'] : null,
                "district_name" => $b['district_name'],
                "state_id" => $b['state_id'] !== null ? (int) $b['state_id'] : null,
                "state_name" => $b['state_name'],
                "pincode" => $b['pincode'],
                "phone_number" => $b['phone_number'],
                "alternate_phone" => $b['alternate_phone'],
                "email" => $b['email'],
                "opening_time" => $b['opening_time'],
                "closing_time" => $b['closing_time'],
                "latitude" => $b['latitude'] !== null ? (float) $b['latitude'] : null,
                "longitude" => $b['longitude'] !== null ? (float) $b['longitude'] : null,
                "status" => ((int) $b['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $b['createdDate'] . 'T' . $b['createdTime'] . 'Z',
                "updated_at" => ($b['updatedDate'] && $b['updatedTime']) ? ($b['updatedDate'] . 'T' . $b['updatedTime'] . 'Z') : null
            ];
        }, $branches);
    }

    public function getCities(array $filters): array
    {
        $sql = "
            SELECT 
                city_id,
                district_id,
                city_name,
                status,
                createdDate,
                createdTime
            FROM cities
            WHERE 1=1
        ";

        $params = [];

        if (!empty($filters['district_id'])) {
            $sql .= " AND district_id = :district_id";
            $params['district_id'] = $filters['district_id'];
        }

        $sql .= " ORDER BY city_name ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        $branches = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($b) {
            return [
                "city_id" => (int) $b['city_id'],
                "district_id" => (int) $b['district_id'],
                "city_name" => $b['city_name'],
                "status" => ((int) $b['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $b['createdDate'] . 'T' . $b['createdTime'] . 'Z'
            ];
        }, $branches);
    }
    // public function insertMember(array $data): bool
    // {
    //     try {
    //         $this->db->beginTransaction();

    //         /* ========== USERS ========== */
    //         $stmtUser = $this->db->prepare("
    //             INSERT INTO users (
    //                 name, email, phone, password,
    //                 branch_id, status, role, gym_id
    //             ) VALUES (
    //                 :name, :email, :phone, :password,
    //                 :branch_id, :status, :role, :gym_id
    //             )
    //         ");

    //         $stmtUser->execute([
    //             'name'      => $data['name'],
    //             'email'     => $data['email'],
    //             'phone'     => $data['phone'],
    //             'password'  => password_hash($data['password'], PASSWORD_BCRYPT),
    //             'branch_id' => $data['branch_id'],
    //             'status'    => $data['status'],
    //             'role'      => 'MEMBER',
    //             'gym_id'    => $data['gym_id'],
    //         ]);

    //         $user_id = $this->db->lastInsertId();

    //         /* ========== USERS PROFILE ========== */
    //         $stmtProfile = $this->db->prepare("
    //             INSERT INTO users_profile (
    //                 user_id, name, date_of_joining, membership_plan,
    //                 date_of_birth, gender, blood_group,
    //                 height_cm, weight_kg, fitness_level, goal_focus,
    //                 country_id, state_id, district_id, city_id,
    //                 address_line1, address_line2, emergency_contact
    //             ) VALUES (
    //                 :user_id, :name, :date_of_joining, :membership_plan,
    //                 :date_of_birth, :gender, :blood_group,
    //                 :height_cm, :weight_kg, :fitness_level, :goal_focus,
    //                 :country_id, :state_id, :district_id, :city_id,
    //                 :address_line1, :address_line2, :emergency_contact
    //             )
    //         ");

    //         $stmtProfile->execute([
    //             'user_id'           => $user_id,
    //             'name'              => $data['name'],
    //             'date_of_joining'   => $data['join_date'],
    //             'membership_plan'   => $data['membership_plan'],
    //             'date_of_birth'     => $data['dob'],
    //             'gender'            => $data['gender'],
    //             'blood_group'       => $data['blood_group'],
    //             'height_cm'         => $data['height'],
    //             'weight_kg'         => $data['weight'],
    //             'fitness_level'     => $data['fitness_level'],
    //             'goal_focus'        => $data['goal_focus'],
    //             'country_id'        => $data['country'],
    //             'state_id'          => $data['state'],
    //             'district_id'       => $data['district'],
    //             'city_id'           => $data['city'],
    //             'address_line1'     => $data['address_line1'],
    //             'address_line2'     => $data['address_line2'],
    //             'emergency_contact' => $data['emergency_contact']
    //         ]);

    //         /* ========== GET PLAN DURATION ========== */
    //         $stmtPlan = $this->db->prepare("
    //             SELECT duration_months
    //             FROM membership_plans
    //             WHERE plan_id = :plan_id
    //             AND gym_id = :gym_id
    //             AND branch_id = :branch_id
    //             AND status = 1
    //         ");

    //         $stmtPlan->execute([
    //             'plan_id'   => $data['membership_plan'],
    //             'gym_id'    => $data['gym_id'],
    //             'branch_id' => $data['branch_id']
    //         ]);

    //         $plan = $stmtPlan->fetch(PDO::FETCH_ASSOC);

    //         if (!$plan) {
    //             throw new Exception('Invalid membership plan');
    //         }

    //         $startDate = new DateTime($data['join_date']);
    //         $endDate   = (clone $startDate)->modify("+{$plan['duration_months']} months");

    //         /* ========== SUBSCRIPTIONS ========== */
    //         $stmtSub = $this->db->prepare("
    //             INSERT INTO subscriptions (
    //                 gym_id, branch_id, user_id, plan_id, trainer_id,
    //                 start_date, end_date, status
    //             ) VALUES (
    //                 :gym_id, :branch_id, :user_id, :plan_id, :trainer_id,
    //                 :start_date, :end_date, 1
    //             )
    //         ");

    //         $stmtSub->execute([
    //             'gym_id'     => $data['gym_id'],
    //             'branch_id'  => $data['branch_id'],
    //             'user_id'    => $user_id,
    //             'plan_id'    => $data['membership_plan'],
    //             'trainer_id' => $data['trainer_id'] ?? null,
    //             'start_date' => $startDate->format('Y-m-d'),
    //             'end_date'   => $endDate->format('Y-m-d')
    //         ]);

    //         $this->db->commit();
    //         return true;

    //     } catch (Exception $e) {
    //         $this->db->rollBack();
    //         error_log('Insert Member Error: ' . $e->getMessage());
    //         return false;
    //     }
    // }
    public function insertMember(array $data): array|false
    {
        try {
            $this->db->beginTransaction();

            /* ========== USERS ========== */
            $stmtUser = $this->db->prepare("
                INSERT INTO users (
                    name, email, phone, password,
                    branch_id, status, role, gym_id
                ) VALUES (
                    :name, :email, :phone, :password,
                    :branch_id, :status, :role, :gym_id
                )
            ");

            $stmtUser->execute([
                'name' => $data['name'],
                'email' => $data['email'],
                'phone' => $data['phone'],
                'password' => password_hash($data['password'], PASSWORD_BCRYPT),
                'branch_id' => $data['branch_id'],
                'status' => $data['status'],
                'role' => 'MEMBER',
                'gym_id' => $data['gym_id'],
            ]);

            $user_id = $this->db->lastInsertId();

            /* ========== USERS PROFILE ========== */
            $stmtProfile = $this->db->prepare("
                INSERT INTO users_profile (
                    user_id, name, date_of_joining, membership_plan,
                    date_of_birth, gender, blood_group,
                    height_cm, weight_kg, fitness_level, goal_focus,
                    country_id, state_id, district_id, city_id,
                    address_line1, address_line2, emergency_contact
                ) VALUES (
                    :user_id, :name, :date_of_joining, :membership_plan,
                    :date_of_birth, :gender, :blood_group,
                    :height_cm, :weight_kg, :fitness_level, :goal_focus,
                    :country_id, :state_id, :district_id, :city_id,
                    :address_line1, :address_line2, :emergency_contact
                )
            ");

            $stmtProfile->execute([
                'user_id' => $user_id,
                'name' => $data['name'],
                'date_of_joining' => $data['join_date'],
                'membership_plan' => $data['membership_plan'],
                'date_of_birth' => $data['dob'],
                'gender' => $data['gender'],
                'blood_group' => $data['blood_group'],
                'height_cm' => $data['height'],
                'weight_kg' => $data['weight'],
                'fitness_level' => $data['fitness_level'],
                'goal_focus' => $data['goal_focus'],
                'country_id' => $data['country'],
                'state_id' => $data['state'],
                'district_id' => $data['district'],
                'city_id' => $data['city'],
                'address_line1' => $data['address_line1'],
                'address_line2' => $data['address_line2'],
                'emergency_contact' => $data['emergency_contact']
            ]);

            /* ========== PLAN ========== */
            $stmtPlan = $this->db->prepare("
                SELECT plan_name, price, duration_months
                FROM membership_plans
                WHERE plan_id = :plan_id
                AND gym_id = :gym_id
                AND branch_id = :branch_id
                AND status = 1
            ");

            $stmtPlan->execute([
                'plan_id' => $data['membership_plan'],
                'gym_id' => $data['gym_id'],
                'branch_id' => $data['branch_id']
            ]);

            $plan = $stmtPlan->fetch(PDO::FETCH_ASSOC);

            if (!$plan) {
                throw new Exception('Invalid membership plan');
            }

            $startDate = new DateTime($data['join_date']);
            $endDate = (clone $startDate)->modify("+{$plan['duration_months']} months");

            /* ========== TAXES & REVERSE TAX MATH ========== */
            $stmtTax = $this->db->prepare("
                SELECT tax_name, percentage 
                FROM tax_rates 
                WHERE gym_id = :gym_id 
                  AND applies_to IN ('SUBSCRIPTIONS', 'ALL') 
                  AND status = 1
            ");
            $stmtTax->execute(['gym_id' => $data['gym_id']]);
            $taxRates = $stmtTax->fetchAll(PDO::FETCH_ASSOC);

            if (empty($taxRates)) {
                $taxRates = [
                    ['tax_name' => 'CGST', 'percentage' => 9.00],
                    ['tax_name' => 'SGST', 'percentage' => 9.00]
                ];
            }

            $totalTaxRate = 0.0;
            foreach ($taxRates as $tr) {
                $totalTaxRate += (float) $tr['percentage'];
            }

            $inclusivePrice = (float) $plan['price'];
            $basePrice = round($inclusivePrice / (1 + ($totalTaxRate / 100)), 2);
            $totalTaxAmount = round($inclusivePrice - $basePrice, 2);

            $taxBreakdown = [];
            $accumulatedTax = 0.0;
            $countRates = count($taxRates);
            for ($i = 0; $i < $countRates; $i++) {
                $tr = $taxRates[$i];
                $ratePct = (float) $tr['percentage'];
                $rateName = trim($tr['tax_name']);

                if ($i === $countRates - 1) {
                    $rateAmount = round($totalTaxAmount - $accumulatedTax, 2);
                } else {
                    $rateAmount = round($inclusivePrice * ($ratePct / (100 + $totalTaxRate)), 2);
                    $accumulatedTax += $rateAmount;
                }

                $key = str_replace(['.', '-'], '_', strtoupper($rateName) . '_' . (int) $ratePct);
                $taxBreakdown[$key] = $rateAmount;
            }

            /* ========== INVOICES ========== */
            $stmtInv = $this->db->prepare("
                INSERT INTO invoices (
                    user_id, invoice_number, total_amount, tax_amount, tax_breakdown, final_amount, status, issued_at, due_date
                ) VALUES (
                    :user_id, :invoice_number, :total_amount, :tax_amount, :tax_breakdown, :final_amount, 'PAID', NOW(), CURDATE()
                )
            ");
            $invoiceNumber = 'INV-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(4)));
            $stmtInv->execute([
                'user_id' => $user_id,
                'invoice_number' => $invoiceNumber,
                'total_amount' => $basePrice,
                'tax_amount' => $totalTaxAmount,
                'tax_breakdown' => json_encode($taxBreakdown),
                'final_amount' => $inclusivePrice
            ]);
            $invoiceId = (int) $this->db->lastInsertId();

            /* ========== INVOICE ITEMS ========== */
            $stmtItem = $this->db->prepare("
                INSERT INTO invoice_items (
                    invoice_id, item_type, reference_id, item_name, quantity, unit_price, tax_percentage, tax_amount, tax_breakdown, total_price
                ) VALUES (
                    :invoice_id, 'SUBSCRIPTION', :reference_id, :item_name, 1, :unit_price, :tax_percentage, :tax_amount, :tax_breakdown, :total_price
                )
            ");
            $stmtItem->execute([
                'invoice_id' => $invoiceId,
                'reference_id' => $data['membership_plan'],
                'item_name' => $plan['plan_name'],
                'unit_price' => $basePrice,
                'tax_percentage' => $totalTaxRate,
                'tax_amount' => $totalTaxAmount,
                'tax_breakdown' => json_encode($taxBreakdown),
                'total_price' => $inclusivePrice
            ]);

            /* ========== PAYMENT TRANSACTIONS ========== */
            $stmtPt = $this->db->prepare("
                INSERT INTO payment_transactions (
                    gym_id, branch_id, invoice_id, paid_by_user_id, amount, payment_mode, payment_status, transaction_ref, payment_date, status, createdDate, createdTime
                ) VALUES (
                    :gym_id, :branch_id, :invoice_id, :paid_by_user_id, :amount, :payment_mode, 'SUCCESS', :transaction_ref, CURDATE(), 1, CURDATE(), CURTIME()
                )
            ");
            $payMode = 'Online';
            if (isset($data['payment_method'])) {
                $payMethod = strtoupper(trim($data['payment_method']));
                if ($payMethod === 'CASH')
                    $payMode = 'Cash';
                elseif ($payMethod === 'CARD')
                    $payMode = 'Card';
                elseif ($payMethod === 'UPI')
                    $payMode = 'UPI';
            }
            $stmtPt->execute([
                'gym_id' => $data['gym_id'],
                'branch_id' => $data['branch_id'],
                'invoice_id' => $invoiceId,
                'paid_by_user_id' => $user_id,
                'amount' => $inclusivePrice,
                'payment_mode' => $payMode,
                'transaction_ref' => 'TXN-' . date('YmdHis') . '-' . rand(100, 999)
            ]);

            /* ========== FINANCIAL LEDGER ========== */
            $stmtFl = $this->db->prepare("
                INSERT INTO financial_ledger (
                    gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, created_at
                ) VALUES (
                    :gym_id, :branch_id, 'INFLOW', 'REVENUE', :amount, 'invoices', :reference_id, :payment_method, NOW()
                )
            ");
            $flMethod = 'BANK_TRANSFER';
            if (isset($data['payment_method'])) {
                $payMethod = strtoupper(trim($data['payment_method']));
                if ($payMethod === 'CASH')
                    $flMethod = 'CASH';
                elseif ($payMethod === 'CARD')
                    $flMethod = 'CARD';
                elseif ($payMethod === 'UPI')
                    $flMethod = 'UPI';
            }
            $stmtFl->execute([
                'gym_id' => $data['gym_id'],
                'branch_id' => $data['branch_id'],
                'amount' => $inclusivePrice,
                'reference_id' => $invoiceId,
                'payment_method' => $flMethod
            ]);

            /* ========== SUBSCRIPTION ========== */
            $stmtSub = $this->db->prepare("
                INSERT INTO subscriptions (
                    gym_id, branch_id, user_id, plan_id,
                    start_date, end_date, status
                ) VALUES (
                    :gym_id, :branch_id, :user_id, :plan_id,
                    :start_date, :end_date, 1
                )
            ");

            $stmtSub->execute([
                'gym_id' => $data['gym_id'],
                'branch_id' => $data['branch_id'],
                'user_id' => $user_id,
                'plan_id' => $data['membership_plan'],
                'start_date' => $startDate->format('Y-m-d'),
                'end_date' => $endDate->format('Y-m-d')
            ]);

            $this->db->commit();

            return [
                "user_id" => $user_id,
                "invoice_id" => $invoiceId
            ] + $data;

        } catch (Exception $e) {
            $this->db->rollBack();
            error_log('Insert Member Error: ' . $e->getMessage());
            return false;
        }
    }
    public function fetchMemberDetails(int $user_id): array|false
    {
        $stmt = $this->db->prepare("
            SELECT
                u.user_id        AS user_id,
                u.name           AS name,
                u.email,
                u.phone,
                u.status,
                u.role,
                u.gym_id,
                u.branch_id,

                g.gym_name,
                gb.branch_name,

                up.profile_id,
                up.date_of_joining,
                up.membership_plan,
                up.date_of_birth,
                up.gender,
                up.blood_group,
                up.height_cm,
                up.weight_kg,
                up.fitness_level,
                up.goal_focus,
                up.country_id,
                up.state_id,
                up.district_id,
                up.city_id,
                up.address_line1,
                up.address_line2,
                up.emergency_contact,

                c.country_name,
                st.state_name,
                d.district_name,
                ct.city_name,

                s.subscription_id,
                s.start_date,
                s.end_date,
                s.status AS subscription_status,

                mp.plan_name,
                mp.duration_months

            FROM users u

            /* ========= GYM & BRANCH ========= */
            LEFT JOIN gyms g
                ON g.gym_id = u.gym_id

            LEFT JOIN gym_branches gb
                ON gb.branch_id = u.branch_id

            /* ========= PROFILE ========= */
            LEFT JOIN users_profile up 
                ON up.user_id = u.user_id

            /* ========= LOCATION ========= */
            LEFT JOIN countries c 
                ON c.country_id = up.country_id

            LEFT JOIN states st 
                ON st.state_id = up.state_id

            LEFT JOIN districts d 
                ON d.district_id = up.district_id

            LEFT JOIN cities ct
                ON ct.city_id = up.city_id

            /* ========= SUBSCRIPTION ========= */
            LEFT JOIN subscriptions s 
                ON s.user_id = u.user_id 
                AND s.status = 1

            LEFT JOIN membership_plans mp 
                ON mp.plan_id = s.plan_id

            WHERE u.user_id = :user_id
            AND u.role = 'MEMBER'
            LIMIT 1
        ");

        $stmt->execute(['user_id' => $user_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    public function fetchAllMemberDetails(): array
    {
        $stmt = $this->db->prepare("
            SELECT
                /* ========= USER ========= */
                u.user_id,
                u.name,
                u.email,
                u.phone,
                u.status,
                u.role,
                u.gym_id,
                u.branch_id,

                /* ========= GYM & BRANCH ========= */
                g.gym_name,
                gb.branch_name,

                /* ========= PROFILE ========= */
                up.profile_id,
                up.date_of_joining,
                up.membership_plan,
                up.date_of_birth,
                up.gender,
                up.blood_group,
                up.height_cm,
                up.weight_kg,
                up.fitness_level,
                up.goal_focus,
                up.address_line1,
                up.address_line2,
                up.emergency_contact,

                /* ========= LOCATION ========= */
                c.country_name,
                st.state_name,
                d.district_name,
                ct.city_name,

                /* ========= SUBSCRIPTION ========= */
                s.subscription_id,
                s.start_date,
                s.end_date,
                s.status AS subscription_status,

                /* ========= PLAN ========= */
                mp.plan_name,
                mp.duration_months

            FROM users u

            LEFT JOIN gyms g
                ON g.gym_id = u.gym_id

            LEFT JOIN gym_branches gb
                ON gb.branch_id = u.branch_id

            LEFT JOIN users_profile up
                ON up.user_id = u.user_id

            LEFT JOIN countries c
                ON c.country_id = up.country_id

            LEFT JOIN states st
                ON st.state_id = up.state_id

            LEFT JOIN districts d
                ON d.district_id = up.district_id

            LEFT JOIN cities ct
                ON ct.city_id = up.city_id

            LEFT JOIN subscriptions s
                ON s.user_id = u.user_id
            AND s.status = 1

            LEFT JOIN membership_plans mp
                ON mp.plan_id = s.plan_id

            WHERE u.role = 'MEMBER'
            ORDER BY u.user_id DESC
        ");

        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    public function updateMember(array $data): void
    {
        $this->db->beginTransaction();

        try {
            /* ========= USERS ========= */
            $userSql = "
                UPDATE users SET
                    name = :name,
                    email = :email,
                    phone = :phone,
                    branch_id = :branch_id,
                    status = :status
            ";

            if (!empty($data['hashed_password'])) {
                $userSql .= ", password = :password";
            }

            $userSql .= " WHERE user_id = :user_id AND role = 'MEMBER'";

            $stmt = $this->db->prepare($userSql);

            $params = [
                'name' => $data['name'],
                'email' => $data['email'],
                'phone' => $data['phone'],
                'branch_id' => $data['branch_id'],
                'status' => $data['status'],
                'user_id' => $data['user_id']
            ];

            if (!empty($data['hashed_password'])) {
                $params['password'] = $data['hashed_password'];
            }

            $stmt->execute($params);

            /* ========= USERS PROFILE ========= */
            $this->db->prepare("
                UPDATE users_profile SET
                    date_of_joining = :join_date,
                    membership_plan = :membership_plan,
                    date_of_birth = :dob,
                    gender = :gender,
                    blood_group = :blood_group,
                    height_cm = :height,
                    weight_kg = :weight,
                    fitness_level = :fitness_level,
                    goal_focus = :goal_focus,
                    country_id = :country,
                    state_id = :state,
                    district_id = :district,
                    city_id = :city,
                    address_line1 = :address1,
                    address_line2 = :address2,
                    emergency_contact = :emergency
                WHERE user_id = :user_id
            ")->execute([
                        'join_date' => $data['join_date'],
                        'membership_plan' => $data['membership_plan'],
                        'dob' => $data['dob'],
                        'gender' => $data['gender'],
                        'blood_group' => $data['blood_group'],
                        'height' => $data['height'],
                        'weight' => $data['weight'],
                        'fitness_level' => $data['fitness_level'],
                        'goal_focus' => $data['goal_focus'],
                        'country' => $data['country'],
                        'state' => $data['state'],
                        'district' => $data['district'],
                        'city' => $data['city'],
                        'address1' => $data['address_line1'],
                        'address2' => $data['address_line2'],
                        'emergency' => $data['emergency_contact'],
                        'user_id' => $data['user_id']
                    ]);

            $this->db->commit();

        } catch (Exception $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
    public function getMembershipPlanByGymBranch(int $gym_id, int $branch_id): array
    {
        $sql = "
            SELECT 
                gym_id,
                branch_id,
                plan_name,
                status,
                createdDate,
                createdTime
            FROM membership_plans
            WHERE gym_id = :gym_id
            AND branch_id = :branch_id
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'gym_id' => $gym_id,
            'branch_id' => $branch_id
        ]);

        $plans = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($p) {
            return [
                "gym_id" => (int) $p['gym_id'],
                "branch_id" => (int) $p['branch_id'],
                "plan_name" => $p['plan_name'],
                "status" => ((int) $p['status'] === 1) ? "ACTIVE" : "INACTIVE",
                "created_at" => $p['createdDate'] . 'T' . $p['createdTime'] . 'Z'
            ];
        }, $plans);
    }
    public function insertAttendanceWithSession(array $data): void
    {
        $this->db->beginTransaction();

        try {
            date_default_timezone_set('Asia/Kolkata');
            $now = date('Y-m-d H:i:s');
            $attendanceDate = date('Y-m-d'); // always IST date

            /* ========= LOCK EXISTING ATTENDANCE ========= */
            $stmt = $this->db->prepare("
                SELECT attendance_id, total_sessions
                FROM attendance_logs
                WHERE user_id = :user_id
                AND attendance_date = :attendance_date
                FOR UPDATE
            ");

            $stmt->execute([
                'user_id' => $data['user_id'],
                'attendance_date' => $attendanceDate
            ]);

            $attendance = $stmt->fetch(PDO::FETCH_ASSOC);

            /* ========= FIRST CHECK-IN OF THE DAY ========= */
            if (!$attendance) {

                $stmt = $this->db->prepare("
                    INSERT INTO attendance_logs (
                        user_id,
                        gym_id,
                        branch_id,
                        shift_id,
                        role_type,
                        attendance_date,
                        total_sessions,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (
                        :user_id,
                        :gym_id,
                        :branch_id,
                        :shift_id,
                        :role_type,
                        :attendance_date,
                        1,
                        :status,
                        :created_at,
                        :updated_at
                    )
                ");

                $stmt->execute([
                    'user_id' => $data['user_id'],
                    'gym_id' => $data['gym_id'],
                    'branch_id' => $data['branch_id'],
                    'shift_id' => $data['shift_id'],
                    'role_type' => $data['role_type'] ?? 'MEMBER',
                    'attendance_date' => $attendanceDate,
                    'status' => $data['status'] ?? 'ON_TIME',
                    'created_at' => $now,
                    'updated_at' => $now
                ]);

                $attendanceId = (int) $this->db->lastInsertId();
                $sessionNo = 1;

            }
            /* ========= MULTIPLE SESSIONS ========= */ else {

                $attendanceId = (int) $attendance['attendance_id'];
                $sessionNo = (int) $attendance['total_sessions'] + 1;

                $stmt = $this->db->prepare("
                    UPDATE attendance_logs
                    SET total_sessions = total_sessions + 1,
                        updated_at = :updated_at
                    WHERE attendance_id = :attendance_id
                ");

                $stmt->execute([
                    'attendance_id' => $attendanceId,
                    'updated_at' => $now
                ]);
            }

            /* ========= INSERT SESSION ========= */
            $stmt = $this->db->prepare("
                INSERT INTO attendance_sessions (
                    attendance_id,
                    user_id,
                    gym_id,
                    branch_id,
                    shift_id,
                    device_id,
                    session_no,
                    check_in_time,
                    source,
                    remarks,
                    created_at,
                    updated_at
                ) VALUES (
                    :attendance_id,
                    :user_id,
                    :gym_id,
                    :branch_id,
                    :shift_id,
                    :device_id,
                    :session_no,
                    :check_in_time,
                    :source,
                    :remarks,
                    :created_at,
                    :updated_at
                )
            ");

            $stmt->execute([
                'attendance_id' => $attendanceId,
                'user_id' => $data['user_id'],
                'gym_id' => $data['gym_id'],
                'branch_id' => $data['branch_id'],
                'shift_id' => $data['shift_id'],
                'device_id' => $data['device_id'] ?? null,
                'session_no' => $sessionNo,
                'check_in_time' => $now,
                'source' => $data['source'] ?? 'DEVICE',
                'remarks' => $data['remarks'] ?? null,
                'created_at' => $now,
                'updated_at' => $now
            ]);

            $this->db->commit();

        } catch (\Exception $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
    public function checkOutAttendance(array $data): bool
    {
        $this->db->beginTransaction();

        try {
            date_default_timezone_set('Asia/Kolkata');
            $now = date('Y-m-d H:i:s');
            $today = date('Y-m-d');

            /* ========= FIND TODAY'S OPEN SESSION ========= */
            $stmt = $this->db->prepare("
                SELECT 
                    s.session_id,
                    s.attendance_id,
                    s.check_in_time
                FROM attendance_sessions s
                JOIN attendance_logs l 
                    ON l.attendance_id = s.attendance_id
                WHERE s.user_id = :user_id
                AND l.attendance_date = :attendance_date
                AND s.check_out_time IS NULL
                ORDER BY s.check_in_time DESC
                LIMIT 1
                FOR UPDATE
            ");

            $stmt->execute([
                'user_id' => $data['user_id'],
                'attendance_date' => $today
            ]);

            $session = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$session) {
                $this->db->rollBack();
                return false;
            }

            /* ========= CALCULATE DURATION ========= */
            $checkIn = new DateTime($session['check_in_time']);
            $checkOut = new DateTime($now);

            $duration = floor(
                ($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60
            );
            $duration = max(0, $duration);

            /* ========= UPDATE SESSION ========= */
            $stmt = $this->db->prepare("
                UPDATE attendance_sessions
                SET 
                    check_out_time = :check_out_time,
                    updated_at     = :updated_at
                WHERE session_id = :session_id
            ");

            $stmt->execute([
                'check_out_time' => $now,
                'updated_at' => $now,
                'session_id' => $session['session_id']
            ]);

            /* ========= UPDATE DAILY TOTAL ========= */
            $stmt = $this->db->prepare("
                UPDATE attendance_logs
                SET 
                    total_duration_min = total_duration_min + :duration,
                    updated_at         = :updated_at
                WHERE attendance_id = :attendance_id
            ");

            $stmt->execute([
                'duration' => $duration,
                'updated_at' => $now,
                'attendance_id' => $session['attendance_id']
            ]);

            $this->db->commit();
            return true;

        } catch (\Exception $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
    public function getAttendanceList(array $filters): array
    {
        $offset = ((int) $filters['page'] - 1) * (int) $filters['limit'];

        $where = [];
        $params = [];

        if (!empty($filters['from_date'])) {
            $where[] = "al.attendance_date >= :from_date";
            $params['from_date'] = $filters['from_date'];
        }

        if (!empty($filters['to_date'])) {
            $where[] = "al.attendance_date <= :to_date";
            $params['to_date'] = $filters['to_date'];
        }

        if (!empty($filters['branch_id'])) {
            $where[] = "al.branch_id = :branch_id";
            $params['branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['district_id'])) {
            $where[] = "d.id = :district_id";
            $params['district_id'] = $filters['district_id'];
        }

        if (!empty($filters['state_id'])) {
            $where[] = "s.id = :state_id";
            $params['state_id'] = $filters['state_id'];
        }

        $whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        $sql = "
            SELECT
                al.attendance_id,
                al.attendance_date,
                al.total_sessions,
                al.total_duration_min,
                al.status,

                u.user_id,
                u.name AS user_name,
                u.phone,
                u.role,

                up.gender,
                up.date_of_birth,

                b.branch_name,
                d.district_name,
                s.state_name,
                gs.shift_name

            FROM attendance_logs al

            JOIN users u ON u.user_id = al.user_id
            LEFT JOIN users_profile up ON up.user_id = u.user_id
            LEFT JOIN gym_branches b ON b.branch_id = al.branch_id
            LEFT JOIN districts d ON d.district_id = b.district_id
            LEFT JOIN states s ON s.state_id = d.state_id
            LEFT JOIN gym_shifts gs ON gs.shift_id = al.shift_id

            $whereSql
            ORDER BY al.attendance_date DESC
            LIMIT :limit OFFSET :offset
        ";

        $stmt = $this->db->prepare($sql);

        foreach ($params as $key => $value) {
            $stmt->bindValue(":$key", $value);
        }

        $stmt->bindValue(':limit', (int) $filters['limit'], PDO::PARAM_INT);
        $stmt->bindValue(':offset', (int) $offset, PDO::PARAM_INT);

        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    public function getUserAttendanceSummary(int $userId, string $date): ?array
    {
        $sql = "
            SELECT
                al.attendance_id,
                al.attendance_date,
                al.total_sessions,
                al.total_duration_min,
                al.status,

                u.name AS user_name,
                u.email,
                u.phone,
                u.role,

                b.branch_name

            FROM attendance_logs al
            JOIN users u ON u.user_id = al.user_id
            LEFT JOIN gym_branches b ON b.branch_id = al.branch_id

            WHERE al.user_id = :user_id
            AND al.attendance_date = :attendance_date
            LIMIT 1
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'user_id' => $userId,
            'attendance_date' => $date
        ]);

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data ?: null;
    }
    public function getAttendanceSessions(int $attendanceId): array
    {
        $sql = "
            SELECT
                session_no,
                device_id,
                check_in_time,
                check_out_time,
                duration_min,
                source
            FROM attendance_sessions
            WHERE attendance_id = :attendance_id
            ORDER BY session_no ASC
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'attendance_id' => $attendanceId
        ]);

        return array_map(function ($s) {
            return [
                "session_no" => (int) $s['session_no'],
                "device" => $s['source'],
                "check_in" => date('h:i a', strtotime($s['check_in_time'])),
                "check_out" => $s['check_out_time']
                    ? date('h:i a', strtotime($s['check_out_time']))
                    : null,
                "duration" => $s['duration_min']
                    ? floor($s['duration_min'] / 60) . "h " . ($s['duration_min'] % 60) . "m"
                    : null
            ];
        }, $stmt->fetchAll(PDO::FETCH_ASSOC));
    }
    public function insertContactForm(array $data): bool
    {
        $stmt = $this->db->prepare("
            INSERT INTO contact_forms (
                name, email, phone, service, message, created_at
            ) VALUES (
                :name, :email, :phone, :service, :message, NOW()
            )
        ");

        return $stmt->execute([
            "name" => $data['name'],
            "email" => $data['email'],
            "phone" => $data['phone'],
            "service" => $data['service'],
            "message" => $data['message']
        ]);
    }
    public function fetchContactList(int $limit, int $offset): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                id,
                name,
                email,
                phone,
                service,
                message,
                created_at
            FROM contact_forms
            ORDER BY id DESC
            LIMIT :limit OFFSET :offset
        ");

        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function countContactList(): int
    {
        $stmt = $this->db->query("SELECT COUNT(*) FROM contact_forms");
        return (int) $stmt->fetchColumn();
    }
    public function insertTrainer(array $data): int
    {
        $employeeCode = "EMP-" . str_pad($data['user_id'], 5, '0', STR_PAD_LEFT);
        
        $stmtEmp = $this->db->prepare("
            INSERT INTO employees (
                user_id, gym_id, branch_id, employee_code, full_name, email, phone,
                designation, employment_type, salary_type, salary_amount, joining_date,
                profile_photo, status, created_at, updated_at, created_by
            ) VALUES (
                :user_id, :gym_id, :branch_id, :employee_code, :full_name, :email, :phone,
                'TRAINER', 'FULL_TIME', 'MONTHLY', 0.00, :joining_date,
                :profile_photo, 'ACTIVE', NOW(), NOW(), :user_id
            )
        ");
        $stmtEmp->execute([
            'user_id' => $data['user_id'],
            'gym_id' => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'employee_code' => $employeeCode,
            'full_name' => $data['name'],
            'email' => $data['email'],
            'phone' => $data['phone'],
            'joining_date' => $data['joining_date'] ?? $data['join_date'] ?? date('Y-m-d'),
            'profile_photo' => $data['profile_photo'] ?? null
        ]);
        
        $employeeId = (int)$this->db->lastInsertId();
        
        $stmtTp = $this->db->prepare("
            INSERT INTO trainer_profiles (
                employee_id, specialization, experience, certifications, bio,
                showcase_photo, availability_status, rating, created_at, updated_at
            ) VALUES (
                :employee_id, :specialization, :experience, :certifications, :bio,
                :showcase_photo, :availability_status, 0.0, NOW(), NOW()
            )
        ");
        
        $stmtTp->execute([
            'employee_id' => $employeeId,
            'specialization' => $data['specialization'] ?? null,
            'experience' => isset($data['experience']) ? (float)$data['experience'] : null,
            'certifications' => $data['certifications'] ?? null,
            'bio' => $data['bio'] ?? null,
            'showcase_photo' => $data['profile_photo'] ?? null,
            'availability_status' => $data['availability'] ?? 'AVAILABLE'
        ]);
        
        return $employeeId;
    }
    public function fetchTrainers(array $filters, int $limit, int $offset): array
    {
        $sql = "
            SELECT tp.*, e.*,
                   COALESCE(e.full_name, u.name) as name, 
                   COALESCE(e.email, u.email) as email, 
                   COALESCE(e.phone, u.phone) as phone, 
                   u.role, 
                   tp.trainer_profile_id AS trainer_id,
                   e.joining_date AS join_date,
                   e.profile_photo AS profile_photo_url
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            JOIN users u ON u.user_id = e.user_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND e.gym_id = :gym_id";
            $params[':gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND e.branch_id = :branch_id";
            $params[':branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND e.status = :status";
            $params[':status'] = ($filters['status'] === 'Active' || $filters['status'] === 'ACTIVE' || $filters['status'] === 1 || $filters['status'] === '1') ? 'ACTIVE' : 'INACTIVE';
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (e.full_name LIKE :search OR e.phone LIKE :search OR e.email LIKE :search)";
            $params[':search'] = '%' . $filters['search'] . '%';
        }

        $sql .= " ORDER BY tp.trainer_profile_id DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->db->prepare($sql);

        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }

        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    public function countTrainers(array $filters): int
    {
        $sql = "
            SELECT COUNT(*)
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            JOIN users u ON u.user_id = e.user_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND e.gym_id = :gym_id";
            $params[':gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND e.branch_id = :branch_id";
            $params[':branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND e.status = :status";
            $params[':status'] = ($filters['status'] === 'Active' || $filters['status'] === 'ACTIVE' || $filters['status'] === 1 || $filters['status'] === '1') ? 'ACTIVE' : 'INACTIVE';
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (e.full_name LIKE :search OR e.phone LIKE :search OR e.email LIKE :search)";
            $params[':search'] = '%' . $filters['search'] . '%';
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int) $stmt->fetchColumn();
    }
    public function fetchTrainerById(int $trainerId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT tp.*, e.*,
                   COALESCE(e.full_name, u.name) as name, 
                   COALESCE(e.email, u.email) as email, 
                   COALESCE(e.phone, u.phone) as phone, 
                   u.role, 
                   tp.trainer_profile_id AS trainer_id,
                   e.joining_date AS join_date,
                   e.profile_photo AS profile_photo_url
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            JOIN users u ON u.user_id = e.user_id
            WHERE tp.trainer_profile_id = :id LIMIT 1
        ");

        $stmt->execute([':id' => $trainerId]);

        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }
    public function updateTrainer(int $trainerId, array $data): bool
    {
        $stmt = $this->db->prepare("SELECT employee_id FROM trainer_profiles WHERE trainer_profile_id = :trainer_id LIMIT 1");
        $stmt->execute([':trainer_id' => $trainerId]);
        $employeeId = $stmt->fetchColumn();
        if (!$employeeId) {
            return false;
        }

        $tpFields = [];
        $tpParams = [':trainer_id' => $trainerId];
        
        $tpAllowed = [
            'specialization' => 'specialization',
            'experience' => 'experience',
            'certifications' => 'certifications',
            'bio' => 'bio',
            'profile_photo' => 'showcase_photo',
            'showcase_photo' => 'showcase_photo',
            'availability' => 'availability_status',
            'availability_status' => 'availability_status'
        ];

        foreach ($tpAllowed as $key => $column) {
            if (isset($data[$key])) {
                $tpFields[] = "$column = :$column";
                if ($key === 'experience') {
                    $tpParams[":$column"] = (float)$data[$key];
                } else {
                    $tpParams[":$column"] = $data[$key];
                }
            }
        }

        if (!empty($tpFields)) {
            $sqlTp = "UPDATE trainer_profiles SET " . implode(', ', $tpFields) . ", updated_at = NOW() WHERE trainer_profile_id = :trainer_id";
            $stmtTp = $this->db->prepare($sqlTp);
            $stmtTp->execute($tpParams);
        }

        $empFields = [];
        $empParams = [':employee_id' => $employeeId];

        $empAllowed = [
            'gym_id' => 'gym_id',
            'branch_id' => 'branch_id',
            'name' => 'full_name',
            'email' => 'email',
            'phone' => 'phone',
            'profile_photo' => 'profile_photo',
            'join_date' => 'joining_date',
            'joining_date' => 'joining_date',
            'status' => 'status'
        ];

        foreach ($empAllowed as $key => $column) {
            if (isset($data[$key])) {
                $empFields[] = "$column = :$column";
                if ($key === 'status') {
                    $empParams[":$column"] = (strtoupper((string)$data[$key]) === 'ACTIVE' || $data[$key] === 1 || $data[$key] === '1') ? 'ACTIVE' : 'INACTIVE';
                } else {
                    $empParams[":$column"] = $data[$key];
                }
            }
        }

        if (!empty($empFields)) {
            $sqlEmp = "UPDATE employees SET " . implode(', ', $empFields) . ", updated_at = NOW() WHERE employee_id = :employee_id";
            $stmtEmp = $this->db->prepare($sqlEmp);
            $stmtEmp->execute($empParams);
        }

        return true;
    }
    public function insertStaff(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO staffs (
                user_id,
                gym_id,
                branch_id,
                shift_id,
                designation,
                department,
                salary_monthly,
                salary_type,
                joining_date,
                access_level,
                status,
                created_at
            ) VALUES (
                :user_id,
                :gym_id,
                :branch_id,
                :shift_id,
                :designation,
                :department,
                :salary_monthly,
                :salary_type,
                :joining_date,
                :access_level,
                :status,
                NOW()
            )
        ");

        $stmt->execute([
            'user_id' => $data['user_id'],
            'gym_id' => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'shift_id' => $data['shift_id'],
            'designation' => $data['designation'],
            'department' => $data['department'],
            'salary_monthly' => $data['salary_monthly'],
            'salary_type' => $data['salary_type'], // FULL_TIME, PART_TIME
            'joining_date' => $data['joining_date'],
            'access_level' => $data['access_level'], // LOW, MEDIUM, HIGH
            'status' => $data['status'] // ACTIVE, INACTIVE
        ]);

        return (int) $this->db->lastInsertId();
    }
    public function fetchStaff(array $filters, int $limit, int $offset): array
    {
        $sql = "
            SELECT 
                s.*,
                u.name,
                u.email,
                u.phone
            FROM staffs s
            LEFT JOIN users u ON u.user_id = s.user_id
            WHERE 1=1
        ";

        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND s.gym_id = :gym_id";
            $params[':gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND s.branch_id = :branch_id";
            $params[':branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND s.status = :status";
            $params[':status'] = strtoupper($filters['status']);
        }

        if (!empty($filters['department'])) {
            $sql .= " AND s.department = :department";
            $params[':department'] = $filters['department'];
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (u.name LIKE :search OR u.phone LIKE :search)";
            $params[':search'] = '%' . $filters['search'] . '%';
        }

        $sql .= " ORDER BY s.staff_id DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->db->prepare($sql);

        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }

        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);

        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    public function countStaff(array $filters): int
    {
        $sql = "SELECT COUNT(*) FROM staffs WHERE 1=1";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND gym_id = :gym_id";
            $params[':gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND branch_id = :branch_id";
            $params[':branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND status = :status";
            $params[':status'] = strtoupper($filters['status']);
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return (int) $stmt->fetchColumn();
    }
    public function fetchStaffById(int $staffId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT 
                s.*,
                u.name,
                u.email,
                u.phone
            FROM staffs s
            LEFT JOIN users u ON u.user_id = s.user_id
            WHERE s.staff_id = :id
            LIMIT 1
        ");

        $stmt->execute([':id' => $staffId]);

        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }
    public function updateStaff(int $staffId, array $data): bool
    {
        $fields = [];
        $params = [];

        $allowed = [
            'gym_id',
            'branch_id',
            'shift_id',
            'designation',
            'department',
            'salary_monthly',
            'salary_type',
            'joining_date',
            'access_level',
            'status'
        ];

        foreach ($allowed as $field) {
            if (isset($data[$field])) {

                // Handle ENUM values (force uppercase)
                if (in_array($field, ['salary_type', 'access_level', 'status'])) {
                    $params[":$field"] = strtoupper($data[$field]);
                } else {
                    $params[":$field"] = $data[$field];
                }

                $fields[] = "$field = :$field";
            }
        }

        if (empty($fields)) {
            return false;
        }

        $params[':staff_id'] = $staffId;

        $sql = "
            UPDATE staffs
            SET " . implode(', ', $fields) . ",
                updated_at = NOW()
            WHERE staff_id = :staff_id
        ";

        $stmt = $this->db->prepare($sql);

        return $stmt->execute($params);
    }

    public function fetchTrainerByUserId(int $userId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT tp.*, e.*,
                   COALESCE(e.full_name, u.name) as name, 
                   COALESCE(e.email, u.email) as email, 
                   COALESCE(e.phone, u.phone) as phone, 
                   u.role, 
                   tp.trainer_profile_id AS trainer_id,
                   e.joining_date AS join_date,
                   e.profile_photo AS profile_photo_url
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            JOIN users u ON u.user_id = e.user_id
            WHERE u.user_id = :user_id LIMIT 1
        ");
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function fetchAssignedTrainees(int $trainerId): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                u.user_id,
                up.profile_id AS member_id,
                u.name,
                u.email,
                u.phone,
                u.status,
                up.date_of_joining,
                up.gender,
                up.fitness_level,
                up.goal_focus,
                sub.start_date,
                sub.end_date,
                sub.status AS subscription_status
            FROM member_trainer_assignments mta
            JOIN users_profile up ON up.profile_id = mta.member_id
            JOIN users u ON u.user_id = up.user_id
            LEFT JOIN subscriptions sub ON sub.user_id = u.user_id AND sub.status = 1
            WHERE mta.trainer_id = :trainer_id AND mta.status = 1
        ");
        $stmt->execute([':trainer_id' => $trainerId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) {
            $row['user_id'] = (int)$row['user_id'];
            $row['member_id'] = (int)$row['member_id'];
            $row['status'] = (int)$row['status'];
            $row['subscription_status'] = $row['subscription_status'] !== null ? (int)$row['subscription_status'] : null;
        }
        return $rows;
    }

    public function fetchShifts(int $gymId, int $branchId): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                shift_id AS id,
                gym_id,
                branch_id,
                shift_name,
                start_time,
                end_time,
                status AS is_active,
                shift_type AS description
            FROM gym_shifts
            WHERE gym_id = :gym_id AND branch_id = :branch_id
        ");
        $stmt->execute([
            ':gym_id' => $gymId,
            ':branch_id' => $branchId
        ]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $results = [];
        foreach ($rows as $row) {
            $startTime = date("h:i A", strtotime($row['start_time']));
            $endTime = date("h:i A", strtotime($row['end_time']));

            $stmtCount = $this->db->prepare("
                SELECT COUNT(*) FROM users 
                WHERE branch_id = :branch_id AND status = 1
            ");
            $stmtCount->execute([':branch_id' => $branchId]);
            $enrolled = (int) $stmtCount->fetchColumn();

            $results[] = [
                'id' => (int) $row['id'],
                'gym_id' => (int) $row['gym_id'],
                'branch_id' => (int) $row['branch_id'],
                'shift_name' => $row['shift_name'],
                'start_time' => $startTime,
                'end_time' => $endTime,
                'capacity' => 50,
                'enrolled' => $enrolled,
                'is_active' => (bool) $row['is_active'],
                'description' => $row['description']
            ];
        }

        return $results;
    }

    public function getUserActiveBaseMembership(int $userId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT s.* 
            FROM subscriptions s
            JOIN membership_plans mp ON s.plan_id = mp.plan_id
            WHERE s.user_id = :user_id 
              AND s.status = 1 
              AND mp.plan_type = 'BASE_MEMBERSHIP'
              AND s.end_date >= CURDATE()
            LIMIT 1
        ");
        $stmt->execute(['user_id' => $userId]);
        $sub = $stmt->fetch(PDO::FETCH_ASSOC);
        return $sub ?: null;
    }

    public function getTaxRatesForGym(int $gymId, string $appliesTo = 'ALL'): array
    {
        $stmt = $this->db->prepare("
            SELECT tax_name, percentage 
            FROM tax_rates 
            WHERE gym_id = :gym_id 
              AND applies_to IN (:applies_to, 'ALL') 
              AND status = 1
        ");
        $stmt->execute([
            'gym_id' => $gymId,
            'applies_to' => $appliesTo
        ]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getMembershipPlanById(int $planId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM membership_plans WHERE plan_id = :id LIMIT 1");
        $stmt->execute(['id' => $planId]);
        $plan = $stmt->fetch(PDO::FETCH_ASSOC);
        return $plan ?: null;
    }

    public function createInvoice(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO invoices (
                user_id,
                invoice_number,
                total_amount,
                tax_amount,
                tax_breakdown,
                final_amount,
                status,
                issued_at,
                due_date
            ) VALUES (
                :user_id,
                :invoice_number,
                :total_amount,
                :tax_amount,
                :tax_breakdown,
                :final_amount,
                :status,
                NOW(),
                CURDATE()
            )
        ");

        $stmt->execute([
            'user_id' => (int) ($data['user_id'] ?? 0),
            'invoice_number' => $data['invoice_number'],
            'total_amount' => (float) $data['total_amount'],
            'tax_amount' => (float) ($data['tax_amount'] ?? 0.0),
            'tax_breakdown' => isset($data['tax_breakdown']) ? (is_array($data['tax_breakdown']) ? json_encode($data['tax_breakdown']) : $data['tax_breakdown']) : null,
            'final_amount' => (float) $data['final_amount'],
            'status' => $data['status'] ?? 'UNPAID'
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function createInvoiceItem(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO invoice_items (
                invoice_id,
                item_type,
                reference_id,
                item_name,
                quantity,
                unit_price,
                tax_percentage,
                tax_amount,
                tax_breakdown,
                total_price
            ) VALUES (
                :invoice_id,
                :item_type,
                :reference_id,
                :item_name,
                :quantity,
                :unit_price,
                :tax_percentage,
                :tax_amount,
                :tax_breakdown,
                :total_price
            )
        ");

        $stmt->execute([
            'invoice_id' => (int) $data['invoice_id'],
            'item_type' => $data['item_type'], // SUBSCRIPTION or PRODUCT or PT_PACKAGE
            'reference_id' => (int) $data['reference_id'],
            'item_name' => trim($data['item_name']),
            'quantity' => (int) ($data['quantity'] ?? 1),
            'unit_price' => (float) $data['unit_price'],
            'tax_percentage' => (float) ($data['tax_percentage'] ?? 0.0),
            'tax_amount' => (float) ($data['tax_amount'] ?? 0.0),
            'tax_breakdown' => isset($data['tax_breakdown']) ? (is_array($data['tax_breakdown']) ? json_encode($data['tax_breakdown']) : $data['tax_breakdown']) : null,
            'total_price' => (float) $data['total_price']
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function createPaymentTransaction(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO payment_transactions (
                gym_id,
                branch_id,
                invoice_id,
                paid_by_user_id,
                amount,
                payment_mode,
                payment_status,
                transaction_ref,
                payment_date,
                status,
                createdDate,
                createdTime
            ) VALUES (
                :gym_id,
                :branch_id,
                :invoice_id,
                :paid_by_user_id,
                :amount,
                :payment_mode,
                :payment_status,
                :transaction_ref,
                CURDATE(),
                1,
                CURDATE(),
                CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id' => (int) $data['gym_id'],
            'branch_id' => (int) $data['branch_id'],
            'invoice_id' => (int) $data['invoice_id'],
            'paid_by_user_id' => isset($data['paid_by_user_id']) && (int) $data['paid_by_user_id'] > 0 ? (int) $data['paid_by_user_id'] : null,
            'amount' => (float) $data['amount'],
            'payment_mode' => trim($data['payment_mode']),
            'payment_status' => $data['payment_status'] ?? 'PENDING',
            'transaction_ref' => isset($data['transaction_ref']) ? trim($data['transaction_ref']) : null
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function createFinancialLedgerEntry(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO financial_ledger (
                gym_id,
                branch_id,
                transaction_type,
                category,
                amount,
                reference_table,
                reference_id,
                payment_method,
                created_at
            ) VALUES (
                :gym_id,
                :branch_id,
                :transaction_type,
                :category,
                :amount,
                :reference_table,
                :reference_id,
                :payment_method,
                NOW()
            )
        ");

        $stmt->execute([
            'gym_id' => (int) $data['gym_id'],
            'branch_id' => (int) $data['branch_id'],
            'transaction_type' => strtoupper(trim($data['transaction_type'])),
            'category' => strtoupper(trim($data['category'])),
            'amount' => (float) $data['amount'],
            'reference_table' => trim($data['reference_table']),
            'reference_id' => (int) $data['reference_id'],
            'payment_method' => strtoupper(trim($data['payment_method']))
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function createTrainerCommission(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO trainer_commissions (
                gym_id,
                branch_id,
                trainer_id,
                invoice_id,
                commission_amount,
                status,
                created_at
            ) VALUES (
                :gym_id,
                :branch_id,
                :trainer_id,
                :invoice_id,
                :commission_amount,
                'UNPAID',
                NOW()
            )
        ");

        $stmt->execute([
            'gym_id' => (int) $data['gym_id'],
            'branch_id' => (int) $data['branch_id'],
            'trainer_id' => (int) $data['trainer_id'],
            'invoice_id' => (int) $data['invoice_id'],
            'commission_amount' => (float) $data['commission_amount']
        ]);

        return (int) $this->db->lastInsertId();
    }
}


