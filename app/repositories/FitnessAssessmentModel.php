<?php

require_once __DIR__ . '/../config/database.php';

class FitnessAssessmentModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    /**
     * Get or create a record in members table for a user_id.
     */
    public function getOrCreateMemberId(int $userId): int
    {
        $stmt = $this->db->prepare("SELECT member_id FROM members WHERE user_id = :uid LIMIT 1");
        $stmt->execute(['uid' => $userId]);
        $memberId = $stmt->fetchColumn();

        if ($memberId !== false) {
            return (int)$memberId;
        }

        // Get details from users
        $stmtProf = $this->db->prepare("SELECT gym_id, branch_id FROM users WHERE user_id = :uid LIMIT 1");
        $stmtProf->execute(['uid' => $userId]);
        $profile = $stmtProf->fetch(PDO::FETCH_ASSOC);

        $gymId = $profile ? (int)$profile['gym_id'] : 1;
        $branchId = $profile ? (int)$profile['branch_id'] : 1;

        // Insert new member record manually since primary key isn't auto-incremented
        $stmtIns = $this->db->prepare("
            INSERT INTO members (member_id, user_id, gym_id, branch_id, join_date, status, createdDate, createdTime, updatedDate, updatedTime)
            VALUES (:uid, :uid, :gym_id, :branch_id, CURDATE(), 1, CURDATE(), CURTIME(), CURDATE(), CURTIME())
        ");
        $stmtIns->execute([
            'uid' => $userId,
            'gym_id' => $gymId,
            'branch_id' => $branchId
        ]);

        return $userId;
    }

    /**
     * Retrieve the gender of a member from their profile.
     */
    public function getGenderByUserId(int $userId): string
    {
        $stmt = $this->db->prepare("SELECT gender FROM users_profile WHERE user_id = :uid LIMIT 1");
        $stmt->execute(['uid' => $userId]);
        $gender = $stmt->fetchColumn();
        return $gender ? strtoupper(trim($gender)) : 'MALE';
    }

    /**
     * Resolve trainer user ID to trainer_profile_id.
     */
    public function getTrainerProfileIdByUserId(int $trainerUserId): ?int
    {
        $stmt = $this->db->prepare("
            SELECT tp.trainer_profile_id 
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            WHERE e.user_id = :uid LIMIT 1
        ");
        $stmt->execute(['uid' => $trainerUserId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int)$val : null;
    }

    /**
     * Insert a new member fitness assessment.
     */
    public function insertAssessment(array $data): int
    {
        $sql = "
            INSERT INTO member_fitness_assessments (
                member_id, trainer_id, assessment_date, assessment_type,
                height_cm, weight_kg, major_health_issues, recent_surgery,
                blood_pressure_systolic, blood_pressure_diastolic, resting_heart_rate,
                body_fat_percent, muscle_mass_kg, sit_and_reach_cm, shoulder_flexibility_cm,
                mid_waist_circumference_cm, lower_waist_circumference_cm, hip_circumference_cm,
                chest_circumference_cm, arm_circumference_cm, thigh_circumference_cm, shoulder_width_cm,
                body_composition_score, vital_signs_score, flexibility_score,
                body_measurement_score, trainer_assessment_score, overall_fitness_score,
                trainer_comments, next_assessment_date, created_at, updated_at
            ) VALUES (
                :member_id, :trainer_id, :assessment_date, :assessment_type,
                :height_cm, :weight_kg, :major_health_issues, :recent_surgery,
                :blood_pressure_systolic, :blood_pressure_diastolic, :resting_heart_rate,
                :body_fat_percent, :muscle_mass_kg, :sit_and_reach_cm, :shoulder_flexibility_cm,
                :mid_waist_circumference_cm, :lower_waist_circumference_cm, :hip_circumference_cm,
                :chest_circumference_cm, :arm_circumference_cm, :thigh_circumference_cm, :shoulder_width_cm,
                :body_composition_score, :vital_signs_score, :flexibility_score,
                :body_measurement_score, :trainer_assessment_score, :overall_fitness_score,
                :trainer_comments, :next_assessment_date, NOW(), NOW()
            )
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([
            'member_id'                    => $data['member_id'],
            'trainer_id'                   => $data['trainer_id'],
            'assessment_date'              => $data['assessment_date'] ?? date('Y-m-d'),
            'assessment_type'              => $data['assessment_type'] ?? 'INITIAL',
            'height_cm'                    => $data['height_cm'] ?? null,
            'weight_kg'                    => $data['weight_kg'] ?? null,
            'major_health_issues'          => $data['major_health_issues'] ?? null,
            'recent_surgery'               => $data['recent_surgery'] ?? null,
            'blood_pressure_systolic'      => $data['blood_pressure_systolic'] ?? null,
            'blood_pressure_diastolic'     => $data['blood_pressure_diastolic'] ?? null,
            'resting_heart_rate'           => $data['resting_heart_rate'] ?? null,
            'body_fat_percent'             => $data['body_fat_percent'] ?? null,
            'muscle_mass_kg'               => $data['muscle_mass_kg'] ?? null,
            'sit_and_reach_cm'             => $data['sit_and_reach_cm'] ?? null,
            'shoulder_flexibility_cm'      => $data['shoulder_flexibility_cm'] ?? null,
            'mid_waist_circumference_cm'   => $data['mid_waist_circumference_cm'] ?? null,
            'lower_waist_circumference_cm' => $data['lower_waist_circumference_cm'] ?? null,
            'hip_circumference_cm'         => $data['hip_circumference_cm'] ?? null,
            'chest_circumference_cm'       => $data['chest_circumference_cm'] ?? null,
            'arm_circumference_cm'         => $data['arm_circumference_cm'] ?? null,
            'thigh_circumference_cm'       => $data['thigh_circumference_cm'] ?? null,
            'shoulder_width_cm'            => $data['shoulder_width_cm'] ?? null,
            'body_composition_score'       => $data['body_composition_score'],
            'vital_signs_score'            => $data['vital_signs_score'],
            'flexibility_score'            => $data['flexibility_score'],
            'body_measurement_score'       => $data['body_measurement_score'],
            'trainer_assessment_score'     => $data['trainer_assessment_score'],
            'overall_fitness_score'        => $data['overall_fitness_score'],
            'trainer_comments'             => $data['trainer_comments'] ?? null,
            'next_assessment_date'         => $data['next_assessment_date'] ?? null
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Get a single assessment by ID.
     */
    public function getAssessmentById(int $assessmentId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT fa.*, m.user_id AS member_user_id, u.name AS member_name
            FROM member_fitness_assessments fa
            JOIN members m ON m.member_id = fa.member_id
            JOIN users u ON u.user_id = m.user_id
            WHERE fa.assessment_id = :id LIMIT 1
        ");
        $stmt->execute(['id' => $assessmentId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * Get all assessments for a specific member user ID.
     */
    public function getMemberAssessments(int $memberUserId): array
    {
        $stmt = $this->db->prepare("
            SELECT fa.*
            FROM member_fitness_assessments fa
            JOIN members m ON m.member_id = fa.member_id
            WHERE m.user_id = :uid
            ORDER BY fa.assessment_date DESC, fa.assessment_id DESC
        ");
        $stmt->execute(['uid' => $memberUserId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get the latest assessment for a specific member user ID.
     */
    public function getLatestMemberAssessment(int $memberUserId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT fa.*
            FROM member_fitness_assessments fa
            JOIN members m ON m.member_id = fa.member_id
            WHERE m.user_id = :uid
            ORDER BY fa.assessment_date DESC, fa.assessment_id DESC LIMIT 1
        ");
        $stmt->execute(['uid' => $memberUserId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * Get the member's profile mapping info for authorization.
     */
    public function getMemberUserIdByMemberId(int $memberId): ?int
    {
        $stmt = $this->db->prepare("SELECT user_id FROM members WHERE member_id = :id LIMIT 1");
        $stmt->execute(['id' => $memberId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int)$val : null;
    }
}
