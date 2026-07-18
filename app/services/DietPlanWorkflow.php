<?php

require_once __DIR__ . '/../repositories/DietPlanModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class DietPlanWorkflow
{
    private DietPlanModel $model;

    private const JWT_SECRET  = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';
    private const ACCESS_EXP  = 604800;

    private const ALLOWED_GOALS = [
        'WEIGHT_LOSS', 'MUSCLE_GAIN', 'STRENGTH', 'ENDURANCE', 'GENERAL_FITNESS'
    ];
    private const ALLOWED_STATUSES = [
        'DRAFT', 'ACTIVE', 'COMPLETED', 'CANCELLED'
    ];

    public function __construct()
    {
        $this->model = new DietPlanModel();
    }

    private function verifyRole(string $accessToken, array $allowedRoles): object
    {
        $decoded = JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));
        $role = str_replace('_', '-', strtoupper($decoded->role ?? ''));
        if (!in_array($role, $allowedRoles)) {
            throw new Exception("Access denied. Authorized role required.", 403);
        }
        return $decoded;
    }

    private function getTrainerIdFromUser(int $userId): int
    {
        $trainer = $this->model->getTrainerByUserId($userId);
        if (!$trainer) {
            throw new Exception("Trainer profile not found for user ID $userId", 400);
        }
        return (int)$trainer['trainer_id'];
    }

    /* ========================================================================= */
    /* ========================= ADMIN WORKFLOWS =============================== */
    /* ========================================================================= */

    public function createDietPlan(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            $required = ['member_id', 'trainer_id', 'goal', 'duration_days', 'start_date'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || trim((string)$data[$field]) === '') {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Field '$field' is required"];
                }
            }

            if (!$this->model->memberExists((int)$data['member_id'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Member with ID " . $data['member_id'] . " does not exist"];
            }

            if (!$this->model->checkDietPlanAccess((int)$data['member_id'])) {
                @http_response_code(400);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Cannot assign diet plan. This member does not have Diet Plan access in their active wallet package."
                ];
            }

            if (!$this->model->trainerExists((int)$data['trainer_id'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Trainer with ID " . $data['trainer_id'] . " does not exist"];
            }

            $goal = strtoupper(trim($data['goal']));
            if (!in_array($goal, self::ALLOWED_GOALS)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid goal. Allowed goals: " . implode(', ', self::ALLOWED_GOALS)];
            }

            $duration = (int)$data['duration_days'];
            if ($duration <= 0) {
                http_response_code(400);
                return ["status" => "error", "message" => "Duration days must be a positive number"];
            }

            $status = isset($data['status']) ? strtoupper(trim($data['status'])) : 'DRAFT';
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            $recommendations = null;
            if (isset($data['recommendations'])) {
                if (is_array($data['recommendations'])) {
                    $recommendations = json_encode($data['recommendations']);
                } else {
                    json_decode($data['recommendations']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Recommendations must be a valid JSON array or object"];
                    }
                    $recommendations = $data['recommendations'];
                }
            }

            $startDate = trim($data['start_date']);
            $endDate = date('Y-m-d', strtotime($startDate . " + $duration days"));

            $planData = [
                'member_id' => (int)$data['member_id'],
                'trainer_id' => (int)$data['trainer_id'],
                'goal' => $goal,
                'duration_days' => $duration,
                'water_intake_l' => isset($data['water_intake_l']) ? (float)$data['water_intake_l'] : null,
                'sleep_hours' => isset($data['sleep_hours']) ? (float)$data['sleep_hours'] : null,
                'recommendations' => $recommendations,
                'trainer_comments' => $data['trainer_comments'] ?? null,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'status' => $status,
                'created_by' => $adminUserId
            ];

            if ($status === 'ACTIVE') {
                $this->model->deactivateMemberActivePlans((int)$data['member_id']);
            }

            $dietPlanId = $this->model->createDietPlan($planData);

            return [
                "status" => "success",
                "message" => "Diet plan created successfully",
                "diet_plan_id" => $dietPlanId
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function createDietPlanWithMeals(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            $required = ['member_id', 'trainer_id', 'goal', 'duration_days', 'start_date', 'meals'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || (is_string($data[$field]) && trim($data[$field]) === '') || (is_array($data[$field]) && empty($data[$field]))) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Field '$field' is required"];
                }
            }

            if (!is_array($data['meals'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Meals must be a non-empty array"];
            }

            if (!$this->model->memberExists((int)$data['member_id'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Member with ID " . $data['member_id'] . " does not exist"];
            }

            if (!$this->model->checkDietPlanAccess((int)$data['member_id'])) {
                @http_response_code(400);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Cannot assign diet plan. This member does not have Diet Plan access in their active wallet package."
                ];
            }

            if (!$this->model->trainerExists((int)$data['trainer_id'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Trainer with ID " . $data['trainer_id'] . " does not exist"];
            }

            $goal = strtoupper(trim($data['goal']));
            if (!in_array($goal, self::ALLOWED_GOALS)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid goal. Allowed goals: " . implode(', ', self::ALLOWED_GOALS)];
            }

            $duration = (int)$data['duration_days'];
            if ($duration <= 0) {
                http_response_code(400);
                return ["status" => "error", "message" => "Duration days must be a positive number"];
            }

            $status = isset($data['status']) ? strtoupper(trim($data['status'])) : 'DRAFT';
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            $recommendations = null;
            if (isset($data['recommendations'])) {
                if (is_array($data['recommendations'])) {
                    $recommendations = json_encode($data['recommendations']);
                } else {
                    json_decode($data['recommendations']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Recommendations must be a valid JSON array or object"];
                    }
                    $recommendations = $data['recommendations'];
                }
            }

            $startDate = trim($data['start_date']);
            $endDate = date('Y-m-d', strtotime($startDate . " + $duration days"));

            $planData = [
                'member_id' => (int)$data['member_id'],
                'trainer_id' => (int)$data['trainer_id'],
                'goal' => $goal,
                'duration_days' => $duration,
                'water_intake_l' => isset($data['water_intake_l']) ? (float)$data['water_intake_l'] : null,
                'sleep_hours' => isset($data['sleep_hours']) ? (float)$data['sleep_hours'] : null,
                'recommendations' => $recommendations,
                'trainer_comments' => $data['trainer_comments'] ?? null,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'status' => $status,
                'created_by' => $adminUserId
            ];

            if ($status === 'ACTIVE') {
                $this->model->deactivateMemberActivePlans((int)$data['member_id']);
            }

            $dietPlanId = $this->model->createDietPlanWithMeals($planData, $data['meals']);

            return [
                "status" => "success",
                "message" => "Diet plan and associated meals created successfully",
                "diet_plan_id" => $dietPlanId
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 403 ? 403 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function createMeal(string $accessToken, int $dietPlanId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (empty($data['meal_title'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Meal title is required"];
            }

            if (!isset($data['meal_items'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Meal items is required"];
            }

            $mealItems = null;
            if (is_array($data['meal_items'])) {
                $mealItems = json_encode($data['meal_items']);
            } else {
                json_decode($data['meal_items']);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Meal items must be a valid JSON array or object"];
                }
                $mealItems = $data['meal_items'];
            }

            $mealData = [
                'meal_title' => trim($data['meal_title']),
                'meal_time' => !empty($data['meal_time']) ? trim($data['meal_time']) : null,
                'meal_items' => $mealItems,
                'notes' => $data['notes'] ?? null
            ];

            if (isset($data['meal_order'])) {
                $mealData['meal_order'] = (int)$data['meal_order'];
            }

            $mealId = $this->model->createMeal($dietPlanId, $mealData);

            return [
                "status" => "success",
                "message" => "Meal created successfully",
                "meal_id" => $mealId
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function listDietPlans(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $plans = $this->model->getAllDietPlans($filters);
            return ["status" => "success", "data" => $plans];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getDietPlanDetails(string $accessToken, int $dietPlanId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $plan = $this->model->getDietPlan($dietPlanId);
            if (!$plan) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }
            return ["status" => "success", "data" => $plan];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateDietPlan(string $accessToken, int $dietPlanId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            $updateData = [];

            if (isset($data['member_id'])) {
                if (!$this->model->memberExists((int)$data['member_id'])) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Member with ID " . $data['member_id'] . " does not exist"];
                }
                $updateData['member_id'] = (int)$data['member_id'];
            }

            if (isset($data['trainer_id'])) {
                if (!$this->model->trainerExists((int)$data['trainer_id'])) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Trainer with ID " . $data['trainer_id'] . " does not exist"];
                }
                $updateData['trainer_id'] = (int)$data['trainer_id'];
            }

            if (isset($data['goal'])) {
                $goal = strtoupper(trim($data['goal']));
                if (!in_array($goal, self::ALLOWED_GOALS)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid goal. Allowed goals: " . implode(', ', self::ALLOWED_GOALS)];
                }
                $updateData['goal'] = $goal;
            }

            if (isset($data['duration_days'])) {
                $duration = (int)$data['duration_days'];
                if ($duration <= 0) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Duration days must be a positive number"];
                }
                $updateData['duration_days'] = $duration;
            }

            if (isset($data['water_intake_l'])) {
                $updateData['water_intake_l'] = (float)$data['water_intake_l'];
            }

            if (isset($data['sleep_hours'])) {
                $updateData['sleep_hours'] = (float)$data['sleep_hours'];
            }

            if (isset($data['trainer_comments'])) {
                $updateData['trainer_comments'] = $data['trainer_comments'];
            }

            if (isset($data['start_date'])) {
                $updateData['start_date'] = trim($data['start_date']);
            }

            $newStartDate = $updateData['start_date'] ?? $existing['start_date'];
            $newDuration = $updateData['duration_days'] ?? $existing['duration_days'];
            $updateData['end_date'] = date('Y-m-d', strtotime($newStartDate . " + $newDuration days"));

            if (isset($data['recommendations'])) {
                if (is_array($data['recommendations'])) {
                    $updateData['recommendations'] = json_encode($data['recommendations']);
                } else {
                    json_decode($data['recommendations']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Recommendations must be a valid JSON array or object"];
                    }
                    $updateData['recommendations'] = $data['recommendations'];
                }
            }

            if (isset($data['status'])) {
                $status = strtoupper(trim($data['status']));
                if (!in_array($status, self::ALLOWED_STATUSES)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
                }
                $updateData['status'] = $status;

                if ($status === 'ACTIVE' && $existing['status'] !== 'ACTIVE') {
                    $targetMemberId = $updateData['member_id'] ?? $existing['member_id'];
                    $this->model->deactivateMemberActivePlans($targetMemberId, $dietPlanId);
                }
            }

            $this->model->updateDietPlan($dietPlanId, $updateData);

            return ["status" => "success", "message" => "Diet plan updated successfully"];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function deleteDietPlan(string $accessToken, int $dietPlanId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            $this->model->deleteDietPlan($dietPlanId);

            return ["status" => "success", "message" => "Diet plan deleted successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function activateDietPlan(string $accessToken, int $dietPlanId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            $this->model->deactivateMemberActivePlans($existing['member_id'], $dietPlanId);
            $this->model->updateDietPlanStatus($dietPlanId, 'ACTIVE');

            return ["status" => "success", "message" => "Diet plan activated successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function changeDietPlanStatus(string $accessToken, int $dietPlanId, string $status): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            $status = strtoupper(trim($status));
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            if ($status === 'ACTIVE') {
                $this->model->deactivateMemberActivePlans($existing['member_id'], $dietPlanId);
            }

            $this->model->updateDietPlanStatus($dietPlanId, $status);

            return ["status" => "success", "message" => "Diet plan status updated to $status successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function cloneDietPlan(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            $newPlanId = $this->model->cloneDietPlan($dietPlanId, $adminUserId);
            if ($newPlanId === false) {
                http_response_code(500);
                return ["status" => "error", "message" => "Failed to clone diet plan"];
            }

            return [
                "status" => "success",
                "message" => "Diet plan cloned successfully",
                "cloned_diet_plan_id" => $newPlanId
            ];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /* ========================================================================= */
    /* ========================= TRAINER WORKFLOWS ============================= */
    /* ========================================================================= */

    public function listTrainerAssignedMembers(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            $members = $this->model->fetchAssignedTrainees($trainerId);
            return ["status" => "success", "data" => $members];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getTrainerAssignedMemberDetails(string $accessToken, int $memberId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            $member = $this->model->getTrainerAssignedMemberDetails($trainerId, $memberId);
            if (!$member) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
            }
            return ["status" => "success", "data" => $member];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function createDietPlanByTrainer(string $accessToken, int $memberId, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            // Access check: must be assigned
            if (!$this->model->isMemberAssignedToTrainer($memberId, $trainerId)) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
            }

            $memberUserId = $this->model->getUserIdFromProfileId($memberId);
            if (!$memberUserId) {
                throw new Exception("Member user ID not found for profile ID $memberId", 404);
            }

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(400);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Cannot assign diet plan. This member does not have Diet Plan access in their active wallet package."
                ];
            }

            $required = ['goal', 'duration_days', 'start_date'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || trim((string)$data[$field]) === '') {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Field '$field' is required"];
                }
            }

            $goal = strtoupper(trim($data['goal']));
            if (!in_array($goal, self::ALLOWED_GOALS)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid goal. Allowed goals: " . implode(', ', self::ALLOWED_GOALS)];
            }

            $duration = (int)$data['duration_days'];
            if ($duration <= 0) {
                http_response_code(400);
                return ["status" => "error", "message" => "Duration days must be a positive number"];
            }

            $status = isset($data['status']) ? strtoupper(trim($data['status'])) : 'DRAFT';
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            $recommendations = null;
            if (isset($data['recommendations'])) {
                if (is_array($data['recommendations'])) {
                    $recommendations = json_encode($data['recommendations']);
                } else {
                    json_decode($data['recommendations']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Recommendations must be a valid JSON array or object"];
                    }
                    $recommendations = $data['recommendations'];
                }
            }

            $startDate = trim($data['start_date']);
            $endDate = date('Y-m-d', strtotime($startDate . " + $duration days"));

            $planData = [
                'member_id' => $memberUserId,
                'trainer_id' => $trainerId,
                'goal' => $goal,
                'duration_days' => $duration,
                'water_intake_l' => isset($data['water_intake_l']) ? (float)$data['water_intake_l'] : null,
                'sleep_hours' => isset($data['sleep_hours']) ? (float)$data['sleep_hours'] : null,
                'recommendations' => $recommendations,
                'trainer_comments' => $data['trainer_comments'] ?? null,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'status' => $status,
                'created_by' => $trainerUserId
            ];

            if ($status === 'ACTIVE') {
                $this->model->deactivateMemberActivePlans($memberUserId);
            }

            $dietPlanId = $this->model->createDietPlan($planData);

            return [
                "status" => "success",
                "message" => "Diet plan created successfully",
                "diet_plan_id" => $dietPlanId
            ];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function createDietPlanWithMealsByTrainer(string $accessToken, int $memberId, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            // Access check: must be assigned
            if (!$this->model->isMemberAssignedToTrainer($memberId, $trainerId)) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
            }

            $memberUserId = $this->model->getUserIdFromProfileId($memberId);
            if (!$memberUserId) {
                throw new Exception("Member user ID not found for profile ID $memberId", 404);
            }

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(400);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Cannot assign diet plan. This member does not have Diet Plan access in their active wallet package."
                ];
            }

            $required = ['goal', 'duration_days', 'start_date', 'meals'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || (is_string($data[$field]) && trim($data[$field]) === '') || (is_array($data[$field]) && empty($data[$field]))) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Field '$field' is required"];
                }
            }

            if (!is_array($data['meals'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Meals must be a non-empty array"];
            }

            $goal = strtoupper(trim($data['goal']));
            if (!in_array($goal, self::ALLOWED_GOALS)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid goal. Allowed goals: " . implode(', ', self::ALLOWED_GOALS)];
            }

            $duration = (int)$data['duration_days'];
            if ($duration <= 0) {
                http_response_code(400);
                return ["status" => "error", "message" => "Duration days must be a positive number"];
            }

            $status = isset($data['status']) ? strtoupper(trim($data['status'])) : 'DRAFT';
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            $recommendations = null;
            if (isset($data['recommendations'])) {
                if (is_array($data['recommendations'])) {
                    $recommendations = json_encode($data['recommendations']);
                } else {
                    json_decode($data['recommendations']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Recommendations must be a valid JSON array or object"];
                    }
                    $recommendations = $data['recommendations'];
                }
            }

            $startDate = trim($data['start_date']);
            $endDate = date('Y-m-d', strtotime($startDate . " + $duration days"));

            $planData = [
                'member_id' => $memberUserId,
                'trainer_id' => $trainerId,
                'goal' => $goal,
                'duration_days' => $duration,
                'water_intake_l' => isset($data['water_intake_l']) ? (float)$data['water_intake_l'] : null,
                'sleep_hours' => isset($data['sleep_hours']) ? (float)$data['sleep_hours'] : null,
                'recommendations' => $recommendations,
                'trainer_comments' => $data['trainer_comments'] ?? null,
                'start_date' => $startDate,
                'end_date' => $endDate,
                'status' => $status,
                'created_by' => $trainerUserId
            ];

            if ($status === 'ACTIVE') {
                $this->model->deactivateMemberActivePlans($memberUserId);
            }

            $dietPlanId = $this->model->createDietPlanWithMeals($planData, $data['meals']);

            return [
                "status" => "success",
                "message" => "Diet plan and associated meals created successfully",
                "diet_plan_id" => $dietPlanId
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 400 ? 400 : ($e->getCode() === 403 ? 403 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function listTrainerDietPlans(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            $plans = $this->model->getAllDietPlans(['trainer_id' => $trainerId]);
            return ["status" => "success", "data" => $plans];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getDietPlanDetailsByTrainer(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            $plan = $this->model->getDietPlan($dietPlanId);
            if (!$plan) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Access check: trainer owns it, or member is assigned to this trainer
            $isOwner = ((int)$plan['trainer_id'] === $trainerId);
            $isAssigned = $this->model->isMemberAssignedToTrainer((int)$plan['member_id'], $trainerId);

            if (!$isOwner && !$isAssigned) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You do not have access to this diet plan."];
            }

            return ["status" => "success", "data" => $plan];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateDietPlanByTrainer(string $accessToken, int $dietPlanId, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Edit boundaries: "Edit plans created by them"
            if ((int)$existing['created_by'] !== $trainerUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You can only update plans created by you."];
            }

            $updateData = [];

            // Trainer shouldn't change the member_id or trainer_id after creation normally, but if passed validate
            if (isset($data['member_id'])) {
                $trainerId = $this->getTrainerIdFromUser($trainerUserId);
                if (!$this->model->isMemberAssignedToTrainer((int)$data['member_id'], $trainerId)) {
                    http_response_code(403);
                    return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
                }
                $updateData['member_id'] = (int)$data['member_id'];
            }

            if (isset($data['goal'])) {
                $goal = strtoupper(trim($data['goal']));
                if (!in_array($goal, self::ALLOWED_GOALS)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid goal. Allowed goals: " . implode(', ', self::ALLOWED_GOALS)];
                }
                $updateData['goal'] = $goal;
            }

            if (isset($data['duration_days'])) {
                $duration = (int)$data['duration_days'];
                if ($duration <= 0) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Duration days must be a positive number"];
                }
                $updateData['duration_days'] = $duration;
            }

            if (isset($data['water_intake_l'])) {
                $updateData['water_intake_l'] = (float)$data['water_intake_l'];
            }

            if (isset($data['sleep_hours'])) {
                $updateData['sleep_hours'] = (float)$data['sleep_hours'];
            }

            if (isset($data['trainer_comments'])) {
                $updateData['trainer_comments'] = $data['trainer_comments'];
            }

            if (isset($data['start_date'])) {
                $updateData['start_date'] = trim($data['start_date']);
            }

            $newStartDate = $updateData['start_date'] ?? $existing['start_date'];
            $newDuration = $updateData['duration_days'] ?? $existing['duration_days'];
            $updateData['end_date'] = date('Y-m-d', strtotime($newStartDate . " + $newDuration days"));

            if (isset($data['recommendations'])) {
                if (is_array($data['recommendations'])) {
                    $updateData['recommendations'] = json_encode($data['recommendations']);
                } else {
                    json_decode($data['recommendations']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Recommendations must be a valid JSON array or object"];
                    }
                    $updateData['recommendations'] = $data['recommendations'];
                }
            }

            if (isset($data['status'])) {
                $status = strtoupper(trim($data['status']));
                if (!in_array($status, self::ALLOWED_STATUSES)) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
                }
                $updateData['status'] = $status;

                if ($status === 'ACTIVE' && $existing['status'] !== 'ACTIVE') {
                    $targetMemberId = $updateData['member_id'] ?? $existing['member_id'];
                    $this->model->deactivateMemberActivePlans($targetMemberId, $dietPlanId);
                }
            }

            $this->model->updateDietPlan($dietPlanId, $updateData);

            return ["status" => "success", "message" => "Diet plan updated successfully"];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function deleteDietPlanByTrainer(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Edit boundaries: "Edit plans created by them"
            if ((int)$existing['created_by'] !== $trainerUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You can only delete plans created by you."];
            }

            $this->model->deleteDietPlan($dietPlanId);

            return ["status" => "success", "message" => "Diet plan deleted successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function activateDietPlanByTrainer(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Edit boundaries: "Edit plans created by them"
            if ((int)$existing['created_by'] !== $trainerUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You can only activate plans created by you."];
            }

            $this->model->deactivateMemberActivePlans($existing['member_id'], $dietPlanId);
            $this->model->updateDietPlanStatus($dietPlanId, 'ACTIVE');

            return ["status" => "success", "message" => "Diet plan activated successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function changeDietPlanStatusByTrainer(string $accessToken, int $dietPlanId, string $status): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Edit boundaries: "Edit plans created by them"
            if ((int)$existing['created_by'] !== $trainerUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You can only modify plans created by you."];
            }

            $status = strtoupper(trim($status));
            if (!in_array($status, self::ALLOWED_STATUSES)) {
                http_response_code(400);
                return ["status" => "error", "message" => "Invalid status. Allowed statuses: " . implode(', ', self::ALLOWED_STATUSES)];
            }

            if ($status === 'ACTIVE') {
                $this->model->deactivateMemberActivePlans($existing['member_id'], $dietPlanId);
            }

            $this->model->updateDietPlanStatus($dietPlanId, $status);

            return ["status" => "success", "message" => "Diet plan status updated to $status successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function cloneDietPlanByTrainer(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            $existing = $this->model->getDietPlan($dietPlanId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Access check: must be owned or member assigned
            $isOwner = ((int)$existing['trainer_id'] === $trainerId);
            $isAssigned = $this->model->isMemberAssignedToTrainer((int)$existing['member_id'], $trainerId);

            if (!$isOwner && !$isAssigned) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You do not have access to this diet plan."];
            }

            $newPlanId = $this->model->cloneDietPlan($dietPlanId, $trainerUserId);
            if ($newPlanId === false) {
                http_response_code(500);
                return ["status" => "error", "message" => "Failed to clone diet plan"];
            }

            return [
                "status" => "success",
                "message" => "Diet plan cloned successfully",
                "cloned_diet_plan_id" => $newPlanId
            ];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    // Meals write validation for Trainer
    private function verifyDietPlanOwnership(int $dietPlanId, int $trainerUserId): void
    {
        $plan = $this->model->getDietPlan($dietPlanId);
        if (!$plan) {
            throw new Exception("Diet plan not found", 404);
        }
        if ((int)$plan['created_by'] !== $trainerUserId) {
            throw new Exception("Access denied. You do not own this diet plan.", 403);
        }
    }

    // Meals read validation for Trainer
    private function verifyDietPlanAccess(int $dietPlanId, int $trainerUserId): void
    {
        $plan = $this->model->getDietPlan($dietPlanId);
        if (!$plan) {
            throw new Exception("Diet plan not found", 404);
        }
        $trainerId = $this->getTrainerIdFromUser($trainerUserId);
        $isOwner = ((int)$plan['trainer_id'] === $trainerId);
        $isAssigned = $this->model->isMemberAssignedToTrainer((int)$plan['member_id'], $trainerId);

        if (!$isOwner && !$isAssigned) {
            throw new Exception("Access denied. You do not have access to this diet plan.", 403);
        }
    }

    public function createMealByTrainer(string $accessToken, int $dietPlanId, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            // Verify trainer owns the plan
            $this->verifyDietPlanOwnership($dietPlanId, $trainerUserId);

            if (empty($data['meal_title'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Meal title is required"];
            }

            if (!isset($data['meal_items'])) {
                http_response_code(400);
                return ["status" => "error", "message" => "Meal items is required"];
            }

            $mealItems = null;
            if (is_array($data['meal_items'])) {
                $mealItems = json_encode($data['meal_items']);
            } else {
                json_decode($data['meal_items']);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    http_response_code(400);
                    return ["status" => "error", "message" => "Meal items must be a valid JSON array or object"];
                }
                $mealItems = $data['meal_items'];
            }

            $mealData = [
                'meal_title' => trim($data['meal_title']),
                'meal_time' => !empty($data['meal_time']) ? trim($data['meal_time']) : null,
                'meal_items' => $mealItems,
                'notes' => $data['notes'] ?? null
            ];

            if (isset($data['meal_order'])) {
                $mealData['meal_order'] = (int)$data['meal_order'];
            }

            $mealId = $this->model->createMeal($dietPlanId, $mealData);

            return [
                "status" => "success",
                "message" => "Meal created successfully",
                "meal_id" => $mealId
            ];

        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function listDietPlanMealsByTrainer(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            // Verify access
            $this->verifyDietPlanAccess($dietPlanId, $trainerUserId);

            $meals = $this->model->getDietPlanMeals($dietPlanId);
            return ["status" => "success", "data" => $meals];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getMealDetailsByTrainer(string $accessToken, int $mealId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $meal = $this->model->getMeal($mealId);
            if (!$meal) {
                http_response_code(404);
                return ["status" => "error", "message" => "Meal not found"];
            }

            // Verify access to plan
            $this->verifyDietPlanAccess((int)$meal['diet_plan_id'], $trainerUserId);

            return ["status" => "success", "data" => $meal];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function updateMealByTrainer(string $accessToken, int $mealId, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $existing = $this->model->getMeal($mealId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Meal not found"];
            }

            // Verify ownership
            $this->verifyDietPlanOwnership((int)$existing['diet_plan_id'], $trainerUserId);

            $updateData = [];
            if (isset($data['meal_title'])) $updateData['meal_title'] = trim($data['meal_title']);
            if (isset($data['meal_time'])) $updateData['meal_time'] = !empty($data['meal_time']) ? trim($data['meal_time']) : null;
            if (isset($data['meal_order'])) $updateData['meal_order'] = (int)$data['meal_order'];
            if (isset($data['notes'])) $updateData['notes'] = $data['notes'];
            
            if (isset($data['meal_items'])) {
                if (is_array($data['meal_items'])) {
                    $updateData['meal_items'] = json_encode($data['meal_items']);
                } else {
                    json_decode($data['meal_items']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        http_response_code(400);
                        return ["status" => "error", "message" => "Meal items must be a valid JSON array or object"];
                    }
                    $updateData['meal_items'] = $data['meal_items'];
                }
            }

            $this->model->updateMeal($mealId, $updateData);

            return ["status" => "success", "message" => "Meal updated successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function deleteMealByTrainer(string $accessToken, int $mealId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            $existing = $this->model->getMeal($mealId);
            if (!$existing) {
                http_response_code(404);
                return ["status" => "error", "message" => "Meal not found"];
            }

            // Verify ownership
            $this->verifyDietPlanOwnership((int)$existing['diet_plan_id'], $trainerUserId);

            $this->model->deleteMeal($mealId);

            return ["status" => "success", "message" => "Meal deleted successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function reorderMealsByTrainer(string $accessToken, int $dietPlanId, array $mealIds): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;

            // Verify ownership
            $this->verifyDietPlanOwnership($dietPlanId, $trainerUserId);

            $success = $this->model->reorderMeals($dietPlanId, $mealIds);
            if (!$success) {
                http_response_code(400);
                return ["status" => "error", "message" => "Failed to reorder meals. Verify that all meal IDs belong to this plan."];
            }

            return ["status" => "success", "message" => "Meals reordered successfully"];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    // Member Diet Plan views for Trainer
    public function getMemberDietPlansByTrainer(string $accessToken, int $memberId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            // Access check: member assigned
            if (!$this->model->isMemberAssignedToTrainer($memberId, $trainerId)) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
            }

            $memberUserId = $this->model->getUserIdFromProfileId($memberId);
            if (!$memberUserId) {
                throw new Exception("Member user ID not found for profile ID $memberId", 404);
            }

            $plans = $this->model->getMemberDietPlans($memberUserId);
            return ["status" => "success", "data" => $plans];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getMemberActiveDietPlanByTrainer(string $accessToken, int $memberId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            if (!$this->model->isMemberAssignedToTrainer($memberId, $trainerId)) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
            }

            $memberUserId = $this->model->getUserIdFromProfileId($memberId);
            if (!$memberUserId) {
                throw new Exception("Member user ID not found for profile ID $memberId", 404);
            }

            $plan = $this->model->getMemberActiveDietPlan($memberUserId);
            if ($plan) {
                $plan['meals'] = $this->model->getDietPlanMeals($plan['diet_plan_id']);
            }

            return ["status" => "success", "data" => $plan];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getMemberDietPlansHistoryByTrainer(string $accessToken, int $memberId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int)$decoded->sub;
            $trainerId = $this->getTrainerIdFromUser($trainerUserId);

            if (!$this->model->isMemberAssignedToTrainer($memberId, $trainerId)) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. Member is not assigned to you."];
            }

            $memberUserId = $this->model->getUserIdFromProfileId($memberId);
            if (!$memberUserId) {
                throw new Exception("Member user ID not found for profile ID $memberId", 404);
            }

            $history = $this->model->getMemberDietPlansHistory($memberUserId);
            return ["status" => "success", "data" => $history];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /* ========================================================================= */
    /* ========================= MEMBER WORKFLOWS ============================== */
    /* ========================================================================= */

    public function getMyActiveDietPlan(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(403);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Access Denied. Your current plan does not include personalized diet plans."
                ];
            }

            $plan = $this->model->getMemberActiveDietPlan($memberUserId);
            if ($plan) {
                $plan['meals'] = $this->model->getDietPlanMeals($plan['diet_plan_id']);
            }

            return ["status" => "success", "data" => $plan];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getMyDietPlansHistory(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(403);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Access Denied. Your current plan does not include personalized diet plans."
                ];
            }

            $history = $this->model->getMemberDietPlansHistory($memberUserId);
            return ["status" => "success", "data" => $history];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getMyDietPlans(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(403);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Access Denied. Your current plan does not include personalized diet plans."
                ];
            }

            $plans = $this->model->getMemberDietPlans($memberUserId);
            return ["status" => "success", "data" => $plans];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : 401);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getDietPlanDetailsByMember(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(403);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Access Denied. Your current plan does not include personalized diet plans."
                ];
            }

            $plan = $this->model->getDietPlan($dietPlanId);
            if (!$plan) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            // Security check: must belong to this member
            if ((int)$plan['member_id'] !== $memberUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You do not have access to this diet plan."];
            }

            return ["status" => "success", "data" => $plan];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getDietPlanMealsByMember(string $accessToken, int $dietPlanId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(403);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Access Denied. Your current plan does not include personalized diet plans."
                ];
            }

            $plan = $this->model->getDietPlan($dietPlanId);
            if (!$plan) {
                http_response_code(404);
                return ["status" => "error", "message" => "Diet plan not found"];
            }

            if ((int)$plan['member_id'] !== $memberUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You do not have access to this diet plan."];
            }

            $meals = $this->model->getDietPlanMeals($dietPlanId);
            return ["status" => "success", "data" => $meals];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    public function getMealDetailsByMember(string $accessToken, int $mealId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            if (!$this->model->checkDietPlanAccess($memberUserId)) {
                @http_response_code(403);
                return [
                    "success" => false,
                    "status" => "error",
                    "message" => "Access Denied. Your current plan does not include personalized diet plans."
                ];
            }

            $meal = $this->model->getMeal($mealId);
            if (!$meal) {
                http_response_code(404);
                return ["status" => "error", "message" => "Meal not found"];
            }

            // Verify access to plan
            $plan = $this->model->getDietPlan((int)$meal['diet_plan_id']);
            if (!$plan || (int)$plan['member_id'] !== $memberUserId) {
                http_response_code(403);
                return ["status" => "error", "message" => "Access denied. You do not have access to this meal."];
            }

            return ["status" => "success", "data" => $meal];
        } catch (\Throwable $e) {
            http_response_code($e->getCode() === 403 ? 403 : ($e->getCode() === 404 ? 404 : 401));
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}
