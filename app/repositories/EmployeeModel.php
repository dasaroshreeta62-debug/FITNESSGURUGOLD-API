<?php

require_once __DIR__ . '/../config/database.php';

class EmployeeModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    public function beginTransaction(): bool
    {
        return $this->db->beginTransaction();
    }

    public function commit(): bool
    {
        return $this->db->commit();
    }

    public function rollBack(): bool
    {
        return $this->db->rollBack();
    }

    public function inTransaction(): bool
    {
        return $this->db->inTransaction();
    }

    public function emailExists(string $email, ?int $excludeUserId = null): bool
    {
        $sql = "SELECT COUNT(*) FROM users WHERE email = :email";
        $params = ['email' => $email];
        if ($excludeUserId !== null) {
            $sql .= " AND user_id != :exclude_id";
            $params['exclude_id'] = $excludeUserId;
        }
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn() > 0;
    }

    public function insertEmployeeUser(array $data): int
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
                :status,
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
            'role'      => $data['role'],
            'status'    => $data['status'] ?? 1
        ]);

        return (int)$this->db->lastInsertId();
    }

    public function insertEmployee(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO employees (
                user_id, gym_id, branch_id, employee_code, full_name, email, phone,
                designation, employment_type, salary_type, salary_amount, joining_date,
                profile_photo, emergency_contact_name, emergency_contact_phone, address,
                remarks, status, created_at, updated_at, created_by
            ) VALUES (
                :user_id, :gym_id, :branch_id, :employee_code, :full_name, :email, :phone,
                :designation, :employment_type, :salary_type, :salary_amount, :joining_date,
                :profile_photo, :emergency_contact_name, :emergency_contact_phone, :address,
                :remarks, :status, NOW(), NOW(), :created_by
            )
        ");

        $stmt->execute([
            'user_id'                 => $data['user_id'],
            'gym_id'                  => $data['gym_id'],
            'branch_id'               => $data['branch_id'],
            'employee_code'           => $data['employee_code'],
            'full_name'               => $data['full_name'],
            'email'                   => $data['email'] ?? null,
            'phone'                   => $data['phone'],
            'designation'             => $data['designation'],
            'employment_type'         => $data['employment_type'] ?? 'FULL_TIME',
            'salary_type'             => $data['salary_type'] ?? 'MONTHLY',
            'salary_amount'           => $data['salary_amount'] ?? 0.00,
            'joining_date'            => $data['joining_date'],
            'profile_photo'           => $data['profile_photo'] ?? null,
            'emergency_contact_name'  => $data['emergency_contact_name'] ?? null,
            'emergency_contact_phone' => $data['emergency_contact_phone'] ?? null,
            'address'                 => $data['address'] ?? null,
            'remarks'                 => $data['remarks'] ?? null,
            'status'                  => $data['status'] ?? 'ACTIVE',
            'created_by'              => $data['created_by']
        ]);

        return (int)$this->db->lastInsertId();
    }

    public function insertTrainerProfile(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO trainer_profiles (
                employee_id, specialization, experience, certifications, bio,
                showcase_photo, availability_status, rating, instagram_url,
                facebook_url, linkedin_url, created_at, updated_at
            ) VALUES (
                :employee_id, :specialization, :experience, :certifications, :bio,
                :showcase_photo, :availability_status, :rating, :instagram_url,
                :facebook_url, :linkedin_url, NOW(), NOW()
            )
        ");

        $stmt->execute([
            'employee_id'         => $data['employee_id'],
            'specialization'      => $data['specialization'] ?? null,
            'experience'          => $data['experience'] ?? null,
            'certifications'      => $data['certifications'] ?? null,
            'bio'                 => $data['bio'] ?? null,
            'showcase_photo'      => $data['showcase_photo'] ?? null,
            'availability_status' => $data['availability_status'] ?? 'AVAILABLE',
            'rating'              => $data['rating'] ?? 0.0,
            'instagram_url'       => $data['instagram_url'] ?? null,
            'facebook_url'        => $data['facebook_url'] ?? null,
            'linkedin_url'        => $data['linkedin_url'] ?? null
        ]);

        return (int)$this->db->lastInsertId();
    }

    public function insertEmployeeDocument(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO employee_documents (
                employee_id, document_type, document_name, document_number, document_url,
                issued_by, issued_date, expiry_date, verification_status, remarks,
                uploaded_at, uploaded_by
            ) VALUES (
                :employee_id, :document_type, :document_name, :document_number, :document_url,
                :issued_by, :issued_date, :expiry_date, :verification_status, :remarks,
                NOW(), :uploaded_by
            )
        ");

        $stmt->execute([
            'employee_id'         => $data['employee_id'],
            'document_type'       => $data['document_type'],
            'document_name'       => $data['document_name'],
            'document_number'     => $data['document_number'] ?? null,
            'document_url'        => $data['document_url'],
            'issued_by'           => $data['issued_by'] ?? null,
            'issued_date'         => !empty($data['issued_date']) ? $data['issued_date'] : null,
            'expiry_date'         => !empty($data['expiry_date']) ? $data['expiry_date'] : null,
            'verification_status' => $data['verification_status'] ?? 'PENDING',
            'remarks'             => $data['remarks'] ?? null,
            'uploaded_by'         => $data['uploaded_by']
        ]);

        return (int)$this->db->lastInsertId();
    }

    public function fetchEmployeeById(int $employeeId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT e.*, u.role, u.status AS user_status, u.last_login
            FROM employees e
            JOIN users u ON u.user_id = e.user_id
            WHERE e.employee_id = :id LIMIT 1
        ");
        $stmt->execute(['id' => $employeeId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;

        $row['employee_id'] = (int)$row['employee_id'];
        $row['user_id'] = (int)$row['user_id'];
        $row['gym_id'] = (int)$row['gym_id'];
        $row['branch_id'] = (int)$row['branch_id'];
        $row['salary_amount'] = (float)$row['salary_amount'];
        $row['created_by'] = $row['created_by'] !== null ? (int)$row['created_by'] : null;
        return $row;
    }

    public function fetchTrainerByEmployeeId(int $employeeId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT * FROM trainer_profiles WHERE employee_id = :employee_id LIMIT 1
        ");
        $stmt->execute(['employee_id' => $employeeId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;

        $row['trainer_profile_id'] = (int)$row['trainer_profile_id'];
        $row['employee_id'] = (int)$row['employee_id'];
        $row['experience'] = $row['experience'] !== null ? (float)$row['experience'] : null;
        $row['rating'] = (float)$row['rating'];
        return $row;
    }

    public function fetchEmployeeDocuments(int $employeeId): array
    {
        $stmt = $this->db->prepare("
            SELECT * FROM employee_documents WHERE employee_id = :employee_id
        ");
        $stmt->execute(['employee_id' => $employeeId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) {
            $row['document_id'] = (int)$row['document_id'];
            $row['employee_id'] = (int)$row['employee_id'];
            $row['uploaded_by'] = $row['uploaded_by'] !== null ? (int)$row['uploaded_by'] : null;
        }
        return $rows;
    }

    public function updateEmployee(int $employeeId, array $data): bool
    {
        $fields = [];
        $params = ['employee_id' => $employeeId];

        $allowed = [
            'branch_id', 'full_name', 'email', 'phone', 'designation',
            'employment_type', 'salary_type', 'salary_amount', 'joining_date',
            'profile_photo', 'emergency_contact_name', 'emergency_contact_phone',
            'address', 'remarks', 'status'
        ];

        foreach ($allowed as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[$field] = $data[$field];
            }
        }

        if (empty($fields)) return false;

        $sql = "UPDATE employees SET " . implode(", ", $fields) . ", updated_at = NOW() WHERE employee_id = :employee_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function updateUser(int $userId, array $data): bool
    {
        $fields = [];
        $params = ['user_id' => $userId];

        $allowed = ['branch_id', 'name', 'email', 'phone', 'status', 'role'];

        foreach ($allowed as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[$field] = $data[$field];
            }
        }

        if (empty($fields)) return false;

        $sql = "UPDATE users SET " . implode(", ", $fields) . " WHERE user_id = :user_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function updateTrainerProfile(int $employeeId, array $data): bool
    {
        $fields = [];
        $params = ['employee_id' => $employeeId];

        $allowed = [
            'specialization', 'experience', 'certifications', 'bio',
            'showcase_photo', 'availability_status', 'rating', 'instagram_url',
            'facebook_url', 'linkedin_url'
        ];

        foreach ($allowed as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[$field] = $data[$field];
            }
        }

        if (empty($fields)) return false;

        $sql = "UPDATE trainer_profiles SET " . implode(", ", $fields) . ", updated_at = NOW() WHERE employee_id = :employee_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function deleteEmployeeDocument(int $documentId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM employee_documents WHERE document_id = :id");
        return $stmt->execute(['id' => $documentId]);
    }

    public function updateEmployeeDocument(int $documentId, array $data): bool
    {
        $fields = [];
        $params = ['document_id' => $documentId];

        $allowed = [
            'document_type', 'document_name', 'document_number', 'document_url',
            'issued_by', 'issued_date', 'expiry_date', 'verification_status', 'remarks'
        ];

        foreach ($allowed as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[$field] = $data[$field];
            }
        }

        if (empty($fields)) return false;

        $sql = "UPDATE employee_documents SET " . implode(", ", $fields) . " WHERE document_id = :document_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function fetchEmployees(array $filters, int $limit, int $offset): array
    {
        $sql = "
            SELECT e.*, u.role, u.status AS user_status, u.last_login
            FROM employees e
            JOIN users u ON u.user_id = e.user_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND e.gym_id = :gym_id";
            $params['gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND e.branch_id = :branch_id";
            $params['branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['designation'])) {
            $sql .= " AND e.designation = :designation";
            $params['designation'] = $filters['designation'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND e.status = :status";
            $params['status'] = $filters['status'];
        }

        if (!empty($filters['employment_type'])) {
            $sql .= " AND e.employment_type = :employment_type";
            $params['employment_type'] = $filters['employment_type'];
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (e.full_name LIKE :search OR e.email LIKE :search OR e.phone LIKE :search OR e.employee_code LIKE :search)";
            $params['search'] = '%' . $filters['search'] . '%';
        }

        $sql .= " ORDER BY e.employee_id DESC LIMIT :limit OFFSET :offset";
        
        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        foreach ($params as $key => $val) {
            $stmt->bindValue(':' . $key, $val);
        }
        $stmt->execute();

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) {
            $row['employee_id'] = (int)$row['employee_id'];
            $row['user_id'] = (int)$row['user_id'];
            $row['gym_id'] = (int)$row['gym_id'];
            $row['branch_id'] = (int)$row['branch_id'];
            $row['salary_amount'] = (float)$row['salary_amount'];
            $row['created_by'] = $row['created_by'] !== null ? (int)$row['created_by'] : null;
        }
        return $rows;
    }

    public function countEmployees(array $filters): int
    {
        $sql = "
            SELECT COUNT(*)
            FROM employees e
            JOIN users u ON u.user_id = e.user_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND e.gym_id = :gym_id";
            $params['gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND e.branch_id = :branch_id";
            $params['branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['designation'])) {
            $sql .= " AND e.designation = :designation";
            $params['designation'] = $filters['designation'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND e.status = :status";
            $params['status'] = $filters['status'];
        }

        if (!empty($filters['employment_type'])) {
            $sql .= " AND e.employment_type = :employment_type";
            $params['employment_type'] = $filters['employment_type'];
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (e.full_name LIKE :search OR e.email LIKE :search OR e.phone LIKE :search OR e.employee_code LIKE :search)";
            $params['search'] = '%' . $filters['search'] . '%';
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }

    public function fetchTrainers(array $filters, int $limit, int $offset): array
    {
        $sql = "
            SELECT e.*, tp.trainer_profile_id, tp.specialization, tp.experience, tp.certifications,
                   tp.bio, tp.showcase_photo, tp.availability_status, tp.rating,
                   tp.instagram_url, tp.facebook_url, tp.linkedin_url,
                   u.status AS user_status, u.last_login
            FROM employees e
            JOIN users u ON u.user_id = e.user_id
            JOIN trainer_profiles tp ON tp.employee_id = e.employee_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND e.gym_id = :gym_id";
            $params['gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND e.branch_id = :branch_id";
            $params['branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND e.status = :status";
            $params['status'] = $filters['status'];
        }

        if (!empty($filters['availability_status'])) {
            $sql .= " AND tp.availability_status = :availability_status";
            $params['availability_status'] = $filters['availability_status'];
        }

        if (!empty($filters['specialization'])) {
            $sql .= " AND tp.specialization LIKE :specialization";
            $params['specialization'] = '%' . $filters['specialization'] . '%';
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (e.full_name LIKE :search OR e.email LIKE :search OR e.phone LIKE :search OR e.employee_code LIKE :search)";
            $params['search'] = '%' . $filters['search'] . '%';
        }

        if (isset($filters['rating'])) {
            $sql .= " AND tp.rating >= :rating";
            $params['rating'] = (float)$filters['rating'];
        }

        $sql .= " ORDER BY e.employee_id DESC LIMIT :limit OFFSET :offset";

        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        foreach ($params as $key => $val) {
            $stmt->bindValue(':' . $key, $val);
        }
        $stmt->execute();

        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) {
            $row['employee_id'] = (int)$row['employee_id'];
            $row['user_id'] = (int)$row['user_id'];
            $row['gym_id'] = (int)$row['gym_id'];
            $row['branch_id'] = (int)$row['branch_id'];
            $row['salary_amount'] = (float)$row['salary_amount'];
            $row['trainer_profile_id'] = (int)$row['trainer_profile_id'];
            $row['experience'] = $row['experience'] !== null ? (float)$row['experience'] : null;
            $row['rating'] = (float)$row['rating'];
            $row['created_by'] = $row['created_by'] !== null ? (int)$row['created_by'] : null;
        }
        return $rows;
    }

    public function countTrainers(array $filters): int
    {
        $sql = "
            SELECT COUNT(*)
            FROM employees e
            JOIN users u ON u.user_id = e.user_id
            JOIN trainer_profiles tp ON tp.employee_id = e.employee_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $sql .= " AND e.gym_id = :gym_id";
            $params['gym_id'] = $filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND e.branch_id = :branch_id";
            $params['branch_id'] = $filters['branch_id'];
        }

        if (!empty($filters['status'])) {
            $sql .= " AND e.status = :status";
            $params['status'] = $filters['status'];
        }

        if (!empty($filters['availability_status'])) {
            $sql .= " AND tp.availability_status = :availability_status";
            $params['availability_status'] = $filters['availability_status'];
        }

        if (!empty($filters['specialization'])) {
            $sql .= " AND tp.specialization LIKE :specialization";
            $params['specialization'] = '%' . $filters['specialization'] . '%';
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (e.full_name LIKE :search OR e.email LIKE :search OR e.phone LIKE :search OR e.employee_code LIKE :search)";
            $params['search'] = '%' . $filters['search'] . '%';
        }

        if (isset($filters['rating'])) {
            $sql .= " AND tp.rating >= :rating";
            $params['rating'] = (float)$filters['rating'];
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }
}
