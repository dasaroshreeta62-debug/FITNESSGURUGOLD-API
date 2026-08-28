<?php

require_once __DIR__ . '/../config/database.php';

class AttendanceModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
        $this->createTableIfNotExists();
    }

    private function createTableIfNotExists(): void
    {
        $sql = "
        CREATE TABLE IF NOT EXISTS `daily_attendance` (
          `attendance_id` int(11) NOT NULL AUTO_INCREMENT,
          `user_id` int(11) NOT NULL,
          `gym_id` int(11) NOT NULL,
          `branch_id` int(11) NOT NULL,
          `attendance_date` date NOT NULL,
          `check_in_time` datetime NOT NULL,
          `check_out_time` datetime DEFAULT NULL,
          `duration_min` int(11) DEFAULT NULL,
          `source` enum('DEVICE','WEB','MOBILE','DESKTOP','ADMIN') DEFAULT 'DEVICE',
          `remarks` text DEFAULT NULL,
          `created_at` datetime DEFAULT current_timestamp(),
          `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
          PRIMARY KEY (`attendance_id`),
          UNIQUE KEY `unique_daily_visit` (`user_id`, `attendance_date`),
          KEY `idx_branch_date` (`branch_id`, `attendance_date`),
          KEY `idx_user_date` (`user_id`, `attendance_date`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
        ";
        try {
            $this->db->exec($sql);
        } catch (\PDOException $e) {
            // Table creation fails silently if restricted
        }
    }

    public function checkIn(array $data): array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');
        $attendanceDate = $data['attendance_date'] ?? date('Y-m-d');
        $checkInTime = $data['check_in_time'] ?? $now;
        $source = $data['source'] ?? 'DEVICE';
        $remarks = $data['remarks'] ?? null;

        $gymId = !empty($data['gym_id']) ? (int)$data['gym_id'] : 0;
        $branchId = !empty($data['branch_id']) ? (int)$data['branch_id'] : 0;

        if (!$gymId || !$branchId) {
            $userStmt = $this->db->prepare("SELECT gym_id, branch_id FROM users WHERE user_id = :user_id LIMIT 1");
            $userStmt->execute(['user_id' => $data['user_id']]);
            $userRow = $userStmt->fetch(PDO::FETCH_ASSOC);
            if ($userRow) {
                if (!$gymId) $gymId = (int)($userRow['gym_id'] ?? 1);
                if (!$branchId) $branchId = (int)($userRow['branch_id'] ?? 1);
            }
            if (!$gymId) $gymId = 1;
            if (!$branchId) $branchId = 1;
        }

        $checkStmt = $this->db->prepare("
            SELECT * FROM daily_attendance 
            WHERE user_id = :user_id AND attendance_date = :attendance_date 
            LIMIT 1
        ");
        $checkStmt->execute([
            'user_id' => $data['user_id'],
            'attendance_date' => $attendanceDate
        ]);
        $existing = $checkStmt->fetch(PDO::FETCH_ASSOC);

        if ($existing) {
            return [
                "success" => false,
                "already_exists" => true,
                "record" => $existing
            ];
        }

        $stmt = $this->db->prepare("
            INSERT INTO daily_attendance (
                user_id, gym_id, branch_id, attendance_date, check_in_time, source, remarks, created_at, updated_at
            ) VALUES (
                :user_id, :gym_id, :branch_id, :attendance_date, :check_in_time, :source, :remarks, :created_at, :updated_at
            )
        ");

        $stmt->execute([
            'user_id'         => $data['user_id'],
            'gym_id'          => $gymId,
            'branch_id'       => $branchId,
            'attendance_date' => $attendanceDate,
            'check_in_time'   => $checkInTime,
            'source'          => $source,
            'remarks'         => $remarks,
            'created_at'      => $now,
            'updated_at'      => $now
        ]);

        $attendanceId = (int)$this->db->lastInsertId();
        $record = $this->getAttendanceById($attendanceId);

        return [
            "success" => true,
            "already_exists" => false,
            "record" => $record
        ];
    }

    public function checkOut(array $data): ?array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');
        $checkOutTime = $data['check_out_time'] ?? $now;

        $record = null;

        if (!empty($data['attendance_id'])) {
            $record = $this->getAttendanceById((int)$data['attendance_id']);
        } else if (!empty($data['user_id'])) {
            $attendanceDate = $data['attendance_date'] ?? date('Y-m-d');
            $stmt = $this->db->prepare("
                SELECT * FROM daily_attendance 
                WHERE user_id = :user_id AND attendance_date = :attendance_date 
                ORDER BY attendance_id DESC 
                LIMIT 1
            ");
            $stmt->execute([
                'user_id' => $data['user_id'],
                'attendance_date' => $attendanceDate
            ]);
            $record = $stmt->fetch(PDO::FETCH_ASSOC);
        }

        if (!$record) {
            return null;
        }

        $checkIn = new DateTime($record['check_in_time']);
        $checkOut = new DateTime($checkOutTime);
        $durationMin = floor(($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60);
        $durationMin = max(0, (int)$durationMin);

        $remarks = !empty($data['remarks']) ? $data['remarks'] : $record['remarks'];

        $updateStmt = $this->db->prepare("
            UPDATE daily_attendance
            SET check_out_time = :check_out_time,
                duration_min = :duration_min,
                remarks = :remarks,
                updated_at = :updated_at
            WHERE attendance_id = :attendance_id
        ");

        $updateStmt->execute([
            'check_out_time' => $checkOutTime,
            'duration_min'   => $durationMin,
            'remarks'        => $remarks,
            'updated_at'     => $now,
            'attendance_id'  => $record['attendance_id']
        ]);

        return $this->getAttendanceById((int)$record['attendance_id']);
    }

    public function listAttendance(array $filters): array
    {
        $page = isset($filters['page']) ? max(1, (int)$filters['page']) : 1;
        $limit = isset($filters['limit']) ? max(1, (int)$filters['limit']) : 20;
        $offset = ($page - 1) * $limit;

        // Resolve regd_no → user_id (member registration_number or employee_code)
        if (!empty($filters['regd_no']) && empty($filters['user_id'])) {
            $resolvedId = $this->resolveUserIdByRegdNo((string)$filters['regd_no']);
            if ($resolvedId) {
                $filters['user_id'] = $resolvedId;
            }
        }

        $where = [];
        $params = [];

        if (!empty($filters['user_id'])) {
            $where[] = "da.user_id = :user_id";
            $params['user_id'] = $filters['user_id'];
        }

        if (!empty($filters['gym_id'])) {
            $where[] = "da.gym_id = :gym_id";
            $params['gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $where[] = "da.branch_id = :branch_id";
            $params['branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['from_date'])) {
            $where[] = "da.attendance_date >= :from_date";
            $params['from_date'] = $filters['from_date'];
        }

        if (!empty($filters['to_date'])) {
            $where[] = "da.attendance_date <= :to_date";
            $params['to_date'] = $filters['to_date'];
        }

        if (!empty($filters['date'])) {
            $where[] = "da.attendance_date = :date";
            $params['date'] = $filters['date'];
        }

        if (!empty($filters['source'])) {
            $where[] = "da.source = :source";
            $params['source'] = $filters['source'];
        }

        if (!empty($filters['status'])) {
            if ($filters['status'] === 'checked_in') {
                $where[] = "da.check_out_time IS NULL";
            } else if ($filters['status'] === 'checked_out') {
                $where[] = "da.check_out_time IS NOT NULL";
            }
        }

        if (!empty($filters['search'])) {
            $where[] = "(u.name LIKE :search OR u.phone LIKE :search OR u.email LIKE :search)";
            $params['search'] = '%' . $filters['search'] . '%';
        }

        $whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        $countSql = "
            SELECT COUNT(*) AS total
            FROM daily_attendance da
            LEFT JOIN users u ON u.user_id = da.user_id
            $whereSql
        ";
        $countStmt = $this->db->prepare($countSql);
        foreach ($params as $k => $v) {
            $countStmt->bindValue(":$k", $v);
        }
        $countStmt->execute();
        $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['total'];

        $sql = "
            SELECT
                da.attendance_id,
                da.user_id,
                da.gym_id,
                da.branch_id,
                da.attendance_date,
                da.check_in_time,
                da.check_out_time,
                da.duration_min,
                da.source,
                da.remarks,
                da.created_at,
                da.updated_at,
                u.name AS user_name,
                u.email AS user_email,
                u.phone AS user_phone,
                u.role AS user_role,
                b.branch_name,
                g.gym_name
            FROM daily_attendance da
            LEFT JOIN users u ON u.user_id = da.user_id
            LEFT JOIN gym_branches b ON b.branch_id = da.branch_id
            LEFT JOIN gyms g ON g.gym_id = da.gym_id
            $whereSql
            ORDER BY da.attendance_date DESC, da.check_in_time DESC
            LIMIT :limit OFFSET :offset
        ";

        $stmt = $this->db->prepare($sql);
        foreach ($params as $k => $v) {
            $stmt->bindValue(":$k", $v);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            "total" => $total,
            "page" => $page,
            "limit" => $limit,
            "total_pages" => (int)ceil($total / max(1, $limit)),
            "records" => $rows
        ];
    }

    public function getAttendanceDetails(?int $userId = null, ?string $date = null, ?int $attendanceId = null): ?array
    {
        $where = [];
        $params = [];

        if ($attendanceId) {
            $where[] = "da.attendance_id = :attendance_id";
            $params['attendance_id'] = $attendanceId;
        } else {
            if ($userId) {
                $where[] = "da.user_id = :user_id";
                $params['user_id'] = $userId;
            }
            if ($date) {
                $where[] = "da.attendance_date = :date";
                $params['date'] = $date;
            }
        }

        if (empty($where)) {
            return null;
        }

        $whereSql = 'WHERE ' . implode(' AND ', $where);

        $sql = "
            SELECT
                da.attendance_id,
                da.user_id,
                da.gym_id,
                da.branch_id,
                da.attendance_date,
                da.check_in_time,
                da.check_out_time,
                da.duration_min,
                da.source,
                da.remarks,
                da.created_at,
                da.updated_at,
                u.name AS user_name,
                u.email AS user_email,
                u.phone AS user_phone,
                u.role AS user_role,
                b.branch_name,
                g.gym_name
            FROM daily_attendance da
            LEFT JOIN users u ON u.user_id = da.user_id
            LEFT JOIN gym_branches b ON b.branch_id = da.branch_id
            LEFT JOIN gyms g ON g.gym_id = da.gym_id
            $whereSql
            ORDER BY da.attendance_id DESC
            LIMIT 1
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        return $result ?: null;
    }

    public function getAttendanceById(int $attendanceId): ?array
    {
        return $this->getAttendanceDetails(null, null, $attendanceId);
    }

    /**
     * Resolve a registration number / employee code to a user_id.
     *
     * Resolution order:
     *   1. member_profiles.registration_number  (numeric)
     *   2. employees.registration_number         (numeric)
     *   3. employees.employee_code               (string)
     *
     * @param  string $regdNo  The registration number or employee code to look up.
     * @return int|null        The resolved user_id, or null if not found.
     */
    public function resolveUserIdByRegdNo(string $regdNo): ?int
    {
        // 1. Try member_profiles.registration_number (numeric match)
        if (is_numeric($regdNo)) {
            $stmt = $this->db->prepare("
                SELECT user_id FROM member_profiles
                WHERE registration_number = :regd_no
                LIMIT 1
            ");
            $stmt->execute(['regd_no' => (int)$regdNo]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                return (int)$row['user_id'];
            }

            // 2. Try employees.registration_number (numeric match)
            $stmt = $this->db->prepare("
                SELECT user_id FROM employees
                WHERE registration_number = :regd_no
                LIMIT 1
            ");
            $stmt->execute(['regd_no' => (int)$regdNo]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row) {
                return (int)$row['user_id'];
            }
        }

        // 3. Try employees.employee_code (string match)
        $stmt = $this->db->prepare("
            SELECT user_id FROM employees
            WHERE employee_code = :regd_no
            LIMIT 1
        ");
        $stmt->execute(['regd_no' => $regdNo]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            return (int)$row['user_id'];
        }

        return null;
    }

    public function markOrUpdateAttendance(array $data): array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');

        $attendanceId = $data['attendance_id'] ?? null;

        if ($attendanceId) {
            $existing = $this->getAttendanceById((int)$attendanceId);
            if (!$existing) {
                return ["success" => false, "message" => "Attendance record not found"];
            }

            $checkInTime = $data['check_in_time'] ?? $existing['check_in_time'];
            $checkOutTime = array_key_exists('check_out_time', $data) ? $data['check_out_time'] : $existing['check_out_time'];

            $durationMin = null;
            if ($checkInTime && $checkOutTime) {
                $checkIn = new DateTime($checkInTime);
                $checkOut = new DateTime($checkOutTime);
                $durationMin = floor(($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60);
                $durationMin = max(0, (int)$durationMin);
            } else if (isset($data['duration_min'])) {
                $durationMin = (int)$data['duration_min'];
            } else {
                $durationMin = $existing['duration_min'];
            }

            $source = $data['source'] ?? $existing['source'];
            $remarks = $data['remarks'] ?? $existing['remarks'];

            $stmt = $this->db->prepare("
                UPDATE daily_attendance
                SET check_in_time = :check_in_time,
                    check_out_time = :check_out_time,
                    duration_min = :duration_min,
                    source = :source,
                    remarks = :remarks,
                    updated_at = :updated_at
                WHERE attendance_id = :attendance_id
            ");

            $stmt->execute([
                'check_in_time'  => $checkInTime,
                'check_out_time' => $checkOutTime,
                'duration_min'   => $durationMin,
                'source'         => $source,
                'remarks'        => $remarks,
                'updated_at'     => $now,
                'attendance_id'  => $attendanceId
            ]);

            return [
                "success" => true,
                "message" => "Attendance record updated successfully",
                "record"  => $this->getAttendanceById((int)$attendanceId)
            ];
        }

        $attendanceDate = $data['attendance_date'] ?? date('Y-m-d');
        $checkInTime = $data['check_in_time'] ?? $now;
        $checkOutTime = $data['check_out_time'] ?? null;
        $source = $data['source'] ?? 'ADMIN';
        $remarks = $data['remarks'] ?? null;

        $gymId = !empty($data['gym_id']) ? (int)$data['gym_id'] : 0;
        $branchId = !empty($data['branch_id']) ? (int)$data['branch_id'] : 0;

        if (!$gymId || !$branchId) {
            $userStmt = $this->db->prepare("SELECT gym_id, branch_id FROM users WHERE user_id = :user_id LIMIT 1");
            $userStmt->execute(['user_id' => $data['user_id']]);
            $userRow = $userStmt->fetch(PDO::FETCH_ASSOC);
            if ($userRow) {
                if (!$gymId) $gymId = (int)($userRow['gym_id'] ?? 1);
                if (!$branchId) $branchId = (int)($userRow['branch_id'] ?? 1);
            }
            if (!$gymId) $gymId = 1;
            if (!$branchId) $branchId = 1;
        }

        $durationMin = null;
        if ($checkInTime && $checkOutTime) {
            $checkIn = new DateTime($checkInTime);
            $checkOut = new DateTime($checkOutTime);
            $durationMin = floor(($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60);
            $durationMin = max(0, (int)$durationMin);
        } else if (isset($data['duration_min'])) {
            $durationMin = (int)$data['duration_min'];
        }

        $stmt = $this->db->prepare("
            INSERT INTO daily_attendance (
                user_id, gym_id, branch_id, attendance_date, check_in_time, check_out_time, duration_min, source, remarks, created_at, updated_at
            ) VALUES (
                :user_id, :gym_id, :branch_id, :attendance_date, :check_in_time, :check_out_time, :duration_min, :source, :remarks, :created_at, :updated_at
            )
            ON DUPLICATE KEY UPDATE
                check_in_time = VALUES(check_in_time),
                check_out_time = VALUES(check_out_time),
                duration_min = VALUES(duration_min),
                source = VALUES(source),
                remarks = VALUES(remarks),
                updated_at = VALUES(updated_at)
        ");

        $stmt->execute([
            'user_id'         => $data['user_id'],
            'gym_id'          => $gymId,
            'branch_id'       => $branchId,
            'attendance_date' => $attendanceDate,
            'check_in_time'   => $checkInTime,
            'check_out_time'  => $checkOutTime,
            'duration_min'    => $durationMin,
            'source'          => $source,
            'remarks'         => $remarks,
            'created_at'      => $now,
            'updated_at'      => $now
        ]);

        $record = $this->getAttendanceDetails((int)$data['user_id'], $attendanceDate);

        return [
            "success" => true,
            "message" => "Attendance record saved successfully",
            "record"  => $record
        ];
    }

    public function deleteAttendance(int $attendanceId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM daily_attendance WHERE attendance_id = :attendance_id");
        return $stmt->execute(['attendance_id' => $attendanceId]);
    }

    public function adminManualEntry(array $data): array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');

        $userId         = (int)($data['user_id'] ?? 0);
        $gymId          = !empty($data['gym_id']) ? (int)$data['gym_id'] : 0;
        $branchId       = !empty($data['branch_id']) ? (int)$data['branch_id'] : 0;
        $attendanceDate = $data['attendance_date'] ?? date('Y-m-d');
        $checkInTime    = $data['check_in_time'] ?? "$attendanceDate " . date('H:i:s');
        $checkOutTime   = !empty($data['check_out_time']) ? $data['check_out_time'] : null;
        $source         = !empty($data['source']) ? strtoupper($data['source']) : 'ADMIN';
        $remarks        = $data['remarks'] ?? null;

        if (!$userId) {
            return ["success" => false, "code" => "INVALID_USER", "message" => "user_id is required."];
        }

        $userStmt = $this->db->prepare("SELECT user_id, role, gym_id, branch_id FROM users WHERE user_id = :user_id LIMIT 1");
        $userStmt->execute(['user_id' => $userId]);
        $user = $userStmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return ["success" => false, "code" => "USER_NOT_FOUND", "message" => "Target user not found."];
        }

        if (!$gymId) $gymId = (int)($user['gym_id'] ?? 1);
        if (!$branchId) $branchId = (int)($user['branch_id'] ?? 1);
        if (!$gymId) $gymId = 1;
        if (!$branchId) $branchId = 1;

        if (strtoupper($user['role'] ?? '') === 'MEMBER') {
            $checkStmt = $this->db->prepare("
                SELECT * FROM daily_attendance 
                WHERE user_id = :user_id AND attendance_date = :attendance_date 
                LIMIT 1
            ");
            $checkStmt->execute(['user_id' => $userId, 'attendance_date' => $attendanceDate]);
            $existing = $checkStmt->fetch(PDO::FETCH_ASSOC);

            if ($existing && !empty($existing['check_out_time'])) {
                return [
                    "success" => false,
                    "code"    => "VISIT_ALREADY_COMPLETED",
                    "message" => "A completed visit already exists for member on " . $attendanceDate,
                    "data"    => $existing
                ];
            }
        }

        $durationMin = null;
        if ($checkInTime && $checkOutTime) {
            $checkIn  = new DateTime($checkInTime);
            $checkOut = new DateTime($checkOutTime);
            $durationMin = floor(($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60);
            $durationMin = max(0, (int)$durationMin);
        }

        $stmt = $this->db->prepare("
            INSERT INTO daily_attendance (
                user_id, gym_id, branch_id, attendance_date, check_in_time, check_out_time, duration_min, source, remarks, created_at, updated_at
            ) VALUES (
                :user_id, :gym_id, :branch_id, :attendance_date, :check_in_time, :check_out_time, :duration_min, :source, :remarks, :created_at, :updated_at
            )
            ON DUPLICATE KEY UPDATE
                check_in_time = VALUES(check_in_time),
                check_out_time = COALESCE(VALUES(check_out_time), check_out_time),
                duration_min = COALESCE(VALUES(duration_min), duration_min),
                source = VALUES(source),
                remarks = VALUES(remarks),
                updated_at = VALUES(updated_at)
        ");

        $stmt->execute([
            'user_id'         => $userId,
            'gym_id'          => $gymId,
            'branch_id'       => $branchId,
            'attendance_date' => $attendanceDate,
            'check_in_time'   => $checkInTime,
            'check_out_time'  => $checkOutTime,
            'duration_min'    => $durationMin,
            'source'          => $source,
            'remarks'         => $remarks,
            'created_at'      => $now,
            'updated_at'      => $now
        ]);

        $record = $this->getAttendanceDetails($userId, $attendanceDate);

        return [
            "success" => true,
            "code"    => "ATTENDANCE_RECORDED",
            "message" => "Manual attendance logged successfully.",
            "data"    => [
                "attendance_id"   => (int)($record['attendance_id'] ?? 0),
                "user_id"         => (int)$userId,
                "branch_id"       => (int)$branchId,
                "attendance_date" => $attendanceDate,
                "check_in_time"   => $record['check_in_time'] ?? $checkInTime,
                "check_out_time"  => $record['check_out_time'] ?? $checkOutTime,
                "duration_min"    => isset($record['duration_min']) ? (int)$record['duration_min'] : $durationMin,
                "source"          => $record['source'] ?? $source,
                "remarks"         => $record['remarks'] ?? $remarks
            ]
        ];
    }

    public function memberManualEntry(int $userId, array $data): array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');
        $attendanceDate = date('Y-m-d');
        $timestamp = !empty($data['timestamp']) ? $data['timestamp'] : $now;

        $userStmt = $this->db->prepare("SELECT user_id, gym_id, branch_id FROM users WHERE user_id = :user_id LIMIT 1");
        $userStmt->execute(['user_id' => $userId]);
        $user = $userStmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            return ["success" => false, "code" => "USER_NOT_FOUND", "message" => "Member account not found."];
        }

        $branchId  = !empty($data['branch_id']) ? (int)$data['branch_id'] : (int)($user['branch_id'] ?? 1);
        $gymId     = (int)($user['gym_id'] ?? 1);
        $punchType = strtoupper($data['punch_type'] ?? 'CHECK_IN');
        $remarks   = $data['remarks'] ?? null;

        $checkStmt = $this->db->prepare("
            SELECT * FROM daily_attendance 
            WHERE user_id = :user_id AND attendance_date = :attendance_date 
            LIMIT 1
        ");
        $checkStmt->execute(['user_id' => $userId, 'attendance_date' => $attendanceDate]);
        $existing = $checkStmt->fetch(PDO::FETCH_ASSOC);

        if ($punchType === 'CHECK_IN') {
            if ($existing) {
                return [
                    "success" => false,
                    "code"    => "DUPLICATE_CHECK_IN",
                    "message" => "Member already checked in for today (" . $attendanceDate . ").",
                    "data"    => [
                        "attendance_id"   => (int)$existing['attendance_id'],
                        "user_id"         => $userId,
                        "branch_id"       => (int)$existing['branch_id'],
                        "check_in_time"   => $existing['check_in_time'],
                        "check_out_time"  => $existing['check_out_time'],
                        "source"          => $existing['source']
                    ]
                ];
            }

            $stmt = $this->db->prepare("
                INSERT INTO daily_attendance (
                    user_id, gym_id, branch_id, attendance_date, check_in_time, source, remarks, created_at, updated_at
                ) VALUES (
                    :user_id, :gym_id, :branch_id, :attendance_date, :check_in_time, 'MOBILE', :remarks, :created_at, :updated_at
                )
            ");
            $stmt->execute([
                'user_id'         => $userId,
                'gym_id'          => $gymId,
                'branch_id'       => $branchId,
                'attendance_date' => $attendanceDate,
                'check_in_time'   => $timestamp,
                'remarks'         => $remarks,
                'created_at'      => $now,
                'updated_at'      => $now
            ]);

            $attendanceId = (int)$this->db->lastInsertId();

            return [
                "success" => true,
                "code"    => "CHECK_IN_SUCCESS",
                "message" => "Member check-in registered.",
                "data"    => [
                    "attendance_id"  => $attendanceId,
                    "user_id"        => $userId,
                    "branch_id"      => $branchId,
                    "check_in_time"  => $timestamp,
                    "check_out_time" => null,
                    "source"         => "MOBILE"
                ]
            ];
        } else {
            // CHECK_OUT
            if (!$existing) {
                return [
                    "success" => false,
                    "code"    => "NO_ACTIVE_CHECK_IN",
                    "message" => "No active check-in record found for member today."
                ];
            }

            $checkIn = new DateTime($existing['check_in_time']);
            $checkOut = new DateTime($timestamp);
            $durationMin = floor(($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60);
            $durationMin = max(0, (int)$durationMin);

            $updateStmt = $this->db->prepare("
                UPDATE daily_attendance
                SET check_out_time = :check_out_time,
                    duration_min = :duration_min,
                    remarks = COALESCE(:remarks, remarks),
                    updated_at = :updated_at
                WHERE attendance_id = :attendance_id
            ");
            $updateStmt->execute([
                'check_out_time' => $timestamp,
                'duration_min'   => $durationMin,
                'remarks'        => $remarks,
                'updated_at'     => $now,
                'attendance_id'  => $existing['attendance_id']
            ]);

            return [
                "success" => true,
                "code"    => "CHECK_OUT_SUCCESS",
                "message" => "Member check-out registered.",
                "data"    => [
                    "attendance_id"  => (int)$existing['attendance_id'],
                    "user_id"        => $userId,
                    "branch_id"      => (int)$existing['branch_id'],
                    "check_in_time"  => $existing['check_in_time'],
                    "check_out_time" => $timestamp,
                    "duration_min"   => $durationMin,
                    "source"         => $existing['source']
                ]
            ];
        }
    }

    public function getAttendanceLogs(array $filters): array
    {
        $page   = isset($filters['page']) ? max(1, (int)$filters['page']) : 1;
        $limit  = isset($filters['limit']) ? max(1, (int)$filters['limit']) : 20;
        $offset = ($page - 1) * $limit;

        // Resolve regd_no → user_id (member registration_number or employee_code)
        if (!empty($filters['regd_no']) && empty($filters['user_id'])) {
            $resolvedId = $this->resolveUserIdByRegdNo((string)$filters['regd_no']);
            if ($resolvedId) {
                $filters['user_id'] = $resolvedId;
            }
        }

        $where  = [];
        $params = [];

        if (!empty($filters['branch_id'])) {
            $where[] = "da.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        if (!empty($filters['user_id'])) {
            $where[] = "da.user_id = :user_id";
            $params['user_id'] = (int)$filters['user_id'];
        }

        if (!empty($filters['start_date'])) {
            $where[] = "da.attendance_date >= :start_date";
            $params['start_date'] = $filters['start_date'];
        }

        if (!empty($filters['end_date'])) {
            $where[] = "da.attendance_date <= :end_date";
            $params['end_date'] = $filters['end_date'];
        }

        if (!empty($filters['source'])) {
            $where[] = "da.source = :source";
            $params['source'] = strtoupper($filters['source']);
        }

        $whereSql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

        $countSql = "SELECT COUNT(*) AS total FROM daily_attendance da $whereSql";
        $countStmt = $this->db->prepare($countSql);
        foreach ($params as $k => $v) {
            $countStmt->bindValue(":$k", $v);
        }
        $countStmt->execute();
        $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['total'];

        $sql = "
            SELECT
                da.attendance_id,
                da.user_id,
                da.branch_id,
                da.attendance_date,
                da.check_in_time,
                da.check_out_time,
                da.duration_min,
                da.source,
                da.remarks
            FROM daily_attendance da
            $whereSql
            ORDER BY da.attendance_date DESC, da.check_in_time DESC
            LIMIT :limit OFFSET :offset
        ";

        $stmt = $this->db->prepare($sql);
        foreach ($params as $k => $v) {
            $stmt->bindValue(":$k", $v);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $formattedRecords = array_map(function($row) {
            return [
                "attendance_id"   => (int)$row['attendance_id'],
                "user_id"         => (int)$row['user_id'],
                "branch_id"       => (int)$row['branch_id'],
                "attendance_date" => $row['attendance_date'],
                "check_in_time"   => $row['check_in_time'],
                "check_out_time"  => $row['check_out_time'],
                "duration_min"    => $row['duration_min'] !== null ? (int)$row['duration_min'] : null,
                "source"          => $row['source'],
                "remarks"         => $row['remarks']
            ];
        }, $rows);

        return [
            "total"   => $total,
            "records" => $formattedRecords
        ];
    }

    public function processRealtimePunch(string $sn, array $punch): bool
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');

        $userId      = (int)($punch['pin'] ?? 0);
        $timestamp   = $punch['time'] ?? $now;
        $inOutStatus = (int)($punch['inoutstatus'] ?? 0);
        $attendanceDate = date('Y-m-d', strtotime($timestamp));

        if (!$userId) {
            return false;
        }

        $userStmt = $this->db->prepare("SELECT gym_id, branch_id FROM users WHERE user_id = :user_id LIMIT 1");
        $userStmt->execute(['user_id' => $userId]);
        $user = $userStmt->fetch(PDO::FETCH_ASSOC);

        $gymId    = (int)($user['gym_id'] ?? 1);
        $branchId = (int)($user['branch_id'] ?? 1);

        if ($inOutStatus === 0) {
            $stmt = $this->db->prepare("
                INSERT INTO daily_attendance (
                    user_id, gym_id, branch_id, attendance_date, check_in_time, source, remarks, created_at, updated_at
                ) VALUES (
                    :user_id, :gym_id, :branch_id, :attendance_date, :check_in_time, 'DEVICE', :remarks, :created_at, :updated_at
                )
                ON DUPLICATE KEY UPDATE
                    check_in_time = VALUES(check_in_time),
                    source = 'DEVICE',
                    updated_at = VALUES(updated_at)
            ");

            return $stmt->execute([
                'user_id'         => $userId,
                'gym_id'          => $gymId,
                'branch_id'       => $branchId,
                'attendance_date' => $attendanceDate,
                'check_in_time'   => $timestamp,
                'remarks'         => "ZKTeco Punch (SN: $sn)",
                'created_at'      => $now,
                'updated_at'      => $now
            ]);
        } else {
            $checkStmt = $this->db->prepare("
                SELECT attendance_id, check_in_time FROM daily_attendance 
                WHERE user_id = :user_id AND attendance_date = :attendance_date 
                ORDER BY attendance_id DESC LIMIT 1
            ");
            $checkStmt->execute(['user_id' => $userId, 'attendance_date' => $attendanceDate]);
            $record = $checkStmt->fetch(PDO::FETCH_ASSOC);

            if ($record) {
                $checkIn = new DateTime($record['check_in_time']);
                $checkOut = new DateTime($timestamp);
                $durationMin = floor(($checkOut->getTimestamp() - $checkIn->getTimestamp()) / 60);
                $durationMin = max(0, (int)$durationMin);

                $updateStmt = $this->db->prepare("
                    UPDATE daily_attendance
                    SET check_out_time = :check_out_time,
                        duration_min = :duration_min,
                        updated_at = :updated_at
                    WHERE attendance_id = :attendance_id
                ");

                return $updateStmt->execute([
                    'check_out_time' => $timestamp,
                    'duration_min'   => $durationMin,
                    'updated_at'     => $now,
                    'attendance_id'  => $record['attendance_id']
                ]);
            } else {
                $stmt = $this->db->prepare("
                    INSERT INTO daily_attendance (
                        user_id, gym_id, branch_id, attendance_date, check_in_time, check_out_time, duration_min, source, remarks, created_at, updated_at
                    ) VALUES (
                        :user_id, :gym_id, :branch_id, :attendance_date, :check_in_time, :check_out_time, 0, 'DEVICE', :remarks, :created_at, :updated_at
                    )
                ");

                return $stmt->execute([
                    'user_id'         => $userId,
                    'gym_id'          => $gymId,
                    'branch_id'       => $branchId,
                    'attendance_date' => $attendanceDate,
                    'check_in_time'   => $timestamp,
                    'check_out_time'  => $timestamp,
                    'remarks'         => "ZKTeco Checkout Direct Punch (SN: $sn)",
                    'created_at'      => $now,
                    'updated_at'      => $now
                ]);
            }
        }
    }

    public function getTodayAttendance(int $userId): ?array
    {
        date_default_timezone_set('Asia/Kolkata');
        $today = date('Y-m-d');

        $stmt = $this->db->prepare("
            SELECT
                da.attendance_id,
                da.user_id,
                da.gym_id,
                da.branch_id,
                da.attendance_date,
                da.check_in_time,
                da.check_out_time,
                da.duration_min,
                da.source,
                da.remarks,
                da.created_at,
                da.updated_at,
                b.branch_name,
                g.gym_name
            FROM daily_attendance da
            LEFT JOIN gym_branches b ON b.branch_id = da.branch_id
            LEFT JOIN gyms g ON g.gym_id = da.gym_id
            WHERE da.user_id = :user_id AND da.attendance_date = :today
            LIMIT 1
        ");
        $stmt->execute(['user_id' => $userId, 'today' => $today]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return null;
        }

        $status = !empty($row['check_out_time']) ? 'checked_out' : 'checked_in';

        return [
            "attendance_id"   => (int)$row['attendance_id'],
            "user_id"         => (int)$row['user_id'],
            "gym_id"          => (int)$row['gym_id'],
            "branch_id"       => (int)$row['branch_id'],
            "attendance_date" => $row['attendance_date'],
            "check_in_time"   => $row['check_in_time'],
            "check_out_time"  => $row['check_out_time'],
            "duration_min"    => $row['duration_min'] !== null ? (int)$row['duration_min'] : null,
            "status"          => $status,
            "source"          => $row['source'],
            "remarks"         => $row['remarks'],
            "branch_name"     => $row['branch_name'] ?? '',
            "gym_name"        => $row['gym_name'] ?? ''
        ];
    }
}

