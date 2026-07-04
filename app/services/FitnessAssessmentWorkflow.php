<?php

require_once __DIR__ . '/../repositories/FitnessAssessmentModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class FitnessAssessmentWorkflow
{
    private FitnessAssessmentModel $model;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->model = new FitnessAssessmentModel();
    }

    /**
     * Decode JWT and verify user belongs to allowed roles.
     */
    private function verifyRole(string $accessToken, array $allowedRoles): object
    {
        try {
            $decoded = JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));
        } catch (\Throwable $e) {
            throw new Exception("Invalid or expired token", 401);
        }

        $role = str_replace(['_', '-'], '', strtoupper($decoded->role ?? ''));
        $allowedNormalized = array_map(function ($r) {
            return str_replace(['_', '-'], '', strtoupper($r));
        }, $allowedRoles);

        if (!in_array($role, $allowedNormalized)) {
            throw new Exception("Access denied. Authorized role required.", 403);
        }
        return $decoded;
    }

    /**
     * SAPI-aware header helper.
     */
    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    /**
     * Create/Insert a new member fitness assessment.
     */
    public function createAssessment(string $accessToken, array $data): array
    {
        try {
            // Verify caller is Trainer or Admin
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER']);
            $callerUserId = (int)$decoded->sub;
            $role = strtoupper($decoded->role);

            // Validate required inputs
            $required = ['member_id', 'height_cm', 'weight_kg', 'blood_pressure_systolic', 'blood_pressure_diastolic', 'resting_heart_rate', 'body_fat_percent', 'sit_and_reach_cm', 'shoulder_flexibility_cm', 'mid_waist_circumference_cm', 'hip_circumference_cm'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || trim((string)$data[$field]) === '') {
                    throw new Exception("Field '$field' is required", 400);
                }
            }

            $memberUserId = (int)$data['member_id'];

            // Resolve or create members.member_id
            $memberId = $this->model->getOrCreateMemberId($memberUserId);

            // Resolve trainer_id
            $trainerId = null;
            if ($role === 'TRAINER') {
                $trainerId = $this->model->getTrainerProfileIdByUserId($callerUserId);
                if (!$trainerId) {
                    throw new Exception("Trainer profile not found in database for user $callerUserId", 400);
                }
            } else {
                // If Admin inserts, optional trainer_id can be passed in payload
                if (!empty($data['trainer_id'])) {
                    $trainerId = (int)$data['trainer_id'];
                }
            }

            // Retrieve Member's Gender
            $gender = $this->model->getGenderByUserId($memberUserId);

            // Extract inputs
            $heightCm = (float)$data['height_cm'];
            $weightKg = (float)$data['weight_kg'];
            $bodyFat = (float)$data['body_fat_percent'];
            $systolic = (int)$data['blood_pressure_systolic'];
            $diastolic = (int)$data['blood_pressure_diastolic'];
            $rhr = (int)$data['resting_heart_rate'];
            $sitAndReach = (float)$data['sit_and_reach_cm'];
            $shoulderFlex = (float)$data['shoulder_flexibility_cm'];
            $waistCm = (float)$data['mid_waist_circumference_cm'];
            $hipCm = (float)$data['hip_circumference_cm'];
            $trainerScoreInput = isset($data['trainer_assessment_score']) ? (float)$data['trainer_assessment_score'] : 0.0;

            if ($heightCm <= 0.0) {
                throw new Exception("Height must be a positive number", 400);
            }
            if ($hipCm <= 0.0) {
                throw new Exception("Hip circumference must be a positive number", 400);
            }

            // 1. BMI Calculation
            $heightM = $heightCm / 100.0;
            $bmi = $weightKg / ($heightM * $heightM);

            // 2. Body Composition Score (Max 40)
            // Ideal Body Fat: 14-20 for Men, 21-25 for Women
            $idealFatMidpoint = ($gender === 'FEMALE') ? 23.0 : 17.0;
            $bodyFatPoints = 25.0 - (abs($bodyFat - $idealFatMidpoint) * 1.5);
            $bmiPoints = 15.0 - (abs($bmi - 22.0) * 1.2);

            $bodyCompositionScore = max(0.00, min($bodyFatPoints + $bmiPoints, 40.00));

            // 3. Vital Signs Score (Max 20)
            // RHR Points
            if ($rhr <= 60) {
                $rhrPoints = 10.0;
            } elseif ($rhr <= 70) {
                $rhrPoints = 8.0;
            } elseif ($rhr <= 80) {
                $rhrPoints = 6.0;
            } else {
                $rhrPoints = 3.0;
            }

            // Blood Pressure Points
            $bpVariancePenalty = (abs($systolic - 120) / 10.0) + (abs($diastolic - 80) / 5.0);
            $bpPoints = max(0.00, 10.0 - $bpVariancePenalty);

            $vitalSignsScore = max(0.00, min($rhrPoints + $bpPoints, 20.00));

            // 4. Flexibility Score (Max 20)
            $flexibilityScore = (($sitAndReach / 40.0) * 10.0) + (($shoulderFlex / 30.0) * 10.0);
            $flexibilityScore = max(0.00, min($flexibilityScore, 20.00));

            // 5. Body Measurement Score (Max 10)
            $whr = $waistCm / $hipCm;
            if ($gender === 'FEMALE') {
                if ($whr <= 0.85) {
                    $whrPoints = 10.0;
                } elseif ($whr <= 0.89) {
                    $whrPoints = 6.0;
                } else {
                    $whrPoints = 2.0;
                }
            } else {
                // MALE or OTHER
                if ($whr <= 0.90) {
                    $whrPoints = 10.0;
                } elseif ($whr <= 0.99) {
                    $whrPoints = 6.0;
                } else {
                    $whrPoints = 2.0;
                }
            }

            $bodyMeasurementScore = max(0.00, min($whrPoints, 10.00));

            // 6. Trainer Assessment Score (Max 10)
            $trainerAssessmentScore = max(0.00, min($trainerScoreInput, 10.00));

            // 7. Master Overall Fitness Score (Max 100)
            $overallFitnessScore = $bodyCompositionScore + $vitalSignsScore + $flexibilityScore + $bodyMeasurementScore + $trainerAssessmentScore;
            $overallFitnessScore = max(0.00, min($overallFitnessScore, 100.00));

            // Prep insert data (rounded to 2 decimals)
            $insertData = [
                'member_id'                    => $memberId,
                'trainer_id'                   => $trainerId,
                'assessment_date'              => $data['assessment_date'] ?? date('Y-m-d'),
                'assessment_type'              => $data['assessment_type'] ?? 'INITIAL',
                'height_cm'                    => round($heightCm, 2),
                'weight_kg'                    => round($weightKg, 2),
                'major_health_issues'          => $data['major_health_issues'] ?? null,
                'recent_surgery'               => $data['recent_surgery'] ?? null,
                'blood_pressure_systolic'      => $systolic,
                'blood_pressure_diastolic'     => $diastolic,
                'resting_heart_rate'           => $rhr,
                'body_fat_percent'             => round($bodyFat, 2),
                'muscle_mass_kg'               => isset($data['muscle_mass_kg']) ? round((float)$data['muscle_mass_kg'], 2) : null,
                'sit_and_reach_cm'             => round($sitAndReach, 2),
                'shoulder_flexibility_cm'      => round($shoulderFlex, 2),
                'mid_waist_circumference_cm'   => round($waistCm, 2),
                'lower_waist_circumference_cm' => isset($data['lower_waist_circumference_cm']) ? round((float)$data['lower_waist_circumference_cm'], 2) : null,
                'hip_circumference_cm'         => round($hipCm, 2),
                'chest_circumference_cm'       => isset($data['chest_circumference_cm']) ? round((float)$data['chest_circumference_cm'], 2) : null,
                'arm_circumference_cm'         => isset($data['arm_circumference_cm']) ? round((float)$data['arm_circumference_cm'], 2) : null,
                'thigh_circumference_cm'       => isset($data['thigh_circumference_cm']) ? round((float)$data['thigh_circumference_cm'], 2) : null,
                'shoulder_width_cm'            => isset($data['shoulder_width_cm']) ? round((float)$data['shoulder_width_cm'], 2) : null,
                'body_composition_score'       => round($bodyCompositionScore, 2),
                'vital_signs_score'            => round($vitalSignsScore, 2),
                'flexibility_score'            => round($flexibilityScore, 2),
                'body_measurement_score'       => round($bodyMeasurementScore, 2),
                'trainer_assessment_score'     => round($trainerAssessmentScore, 2),
                'overall_fitness_score'        => round($overallFitnessScore, 2),
                'trainer_comments'             => $data['trainer_comments'] ?? null,
                'next_assessment_date'         => $data['next_assessment_date'] ?? null
            ];

            $assessmentId = $this->model->insertAssessment($insertData);

            return [
                "status"                => "success",
                "message"               => "Fitness assessment saved successfully",
                "assessment_id"         => $assessmentId,
                "overall_fitness_score" => round($overallFitnessScore, 2)
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Fetch details of a specific assessment.
     */
    public function getAssessment(string $accessToken, int $assessmentId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER', 'MEMBER']);
            $callerUserId = (int)$decoded->sub;
            $role = strtoupper($decoded->role);

            $assessment = $this->model->getAssessmentById($assessmentId);
            if (!$assessment) {
                throw new Exception("Fitness assessment not found", 404);
            }

            // Security: Members can only view their own assessments
            if ($role === 'MEMBER' && (int)$assessment['member_user_id'] !== $callerUserId) {
                throw new Exception("Access denied: You do not have permission to view this assessment.", 403);
            }

            return ["status" => "success", "data" => $assessment];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Fetch assessments history for a member.
     */
    public function getMemberAssessments(string $accessToken, int $memberUserId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER', 'MEMBER']);
            $callerUserId = (int)$decoded->sub;
            $role = strtoupper($decoded->role);

            // Security: Members can only view their own history
            if ($role === 'MEMBER' && $memberUserId !== $callerUserId) {
                throw new Exception("Access denied: You do not have permission to view these assessments.", 403);
            }

            $history = $this->model->getMemberAssessments($memberUserId);
            return ["status" => "success", "data" => $history];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Fetch the latest assessment for a member.
     */
    public function getLatestMemberAssessment(string $accessToken, int $memberUserId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER', 'MEMBER']);
            $callerUserId = (int)$decoded->sub;
            $role = strtoupper($decoded->role);

            // Security: Members can only view their own history
            if ($role === 'MEMBER' && $memberUserId !== $callerUserId) {
                throw new Exception("Access denied: You do not have permission to view these assessments.", 403);
            }

            $latest = $this->model->getLatestMemberAssessment($memberUserId);
            return ["status" => "success", "data" => $latest];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}
