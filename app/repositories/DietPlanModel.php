<?php

require_once __DIR__ . '/model.php';

class DietPlanModel extends Model
{
    protected PDO $db;

    public function __construct()
    {
        parent::__construct();
        $this->db = Database::getConnection();
    }

    public function trainerExists(int $trainerId): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM trainer_profiles WHERE trainer_profile_id = :id");
        $stmt->execute(['id' => $trainerId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    public function memberExists(int $memberId): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM users WHERE user_id = :id AND role = 'MEMBER'");
        $stmt->execute(['id' => $memberId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    public function getTrainerByUserId(int $userId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT 
                tp.trainer_profile_id AS trainer_id,
                e.user_id,
                e.employee_id,
                e.gym_id,
                e.branch_id,
                e.full_name AS name,
                e.email,
                e.phone,
                u.role
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            JOIN users u ON u.user_id = e.user_id
            WHERE e.user_id = :user_id LIMIT 1
        ");
        $stmt->execute([':user_id' => $userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function isMemberAssignedToTrainer(int $memberProfileId, int $trainerId): bool
    {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) 
            FROM member_trainer_assignments 
            WHERE member_id = :member_id AND trainer_id = :trainer_id AND status = 1
        ");
        $stmt->execute([
            'member_id' => $memberProfileId,
            'trainer_id' => $trainerId
        ]);
        return (int)$stmt->fetchColumn() > 0;
    }

    public function getTrainerAssignedMemberDetails(int $trainerId, int $memberProfileId): ?array
    {
        if (!$this->isMemberAssignedToTrainer($memberProfileId, $trainerId)) {
            return null;
        }
        $userId = $this->getUserIdFromProfileId($memberProfileId);
        if (!$userId) {
            return null;
        }
        return $this->fetchMemberDetails($userId);
    }

    public function deactivateMemberActivePlans(int $memberId, ?int $exceptPlanId = null): bool
    {
        $sql = "UPDATE member_diet_plans 
                SET status = 'COMPLETED' 
                WHERE member_id = :member_id AND status = 'ACTIVE'";
        $params = ['member_id' => $memberId];
        if ($exceptPlanId !== null) {
            $sql .= " AND diet_plan_id != :except_id";
            $params['except_id'] = $exceptPlanId;
        }
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function createDietPlan(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO member_diet_plans (
                member_id, trainer_id, goal, duration_days,
                water_intake_l, sleep_hours, recommendations, trainer_comments,
                start_date, end_date, status, created_by, created_at, updated_at
            ) VALUES (
                :member_id, :trainer_id, :goal, :duration_days,
                :water_intake_l, :sleep_hours, :recommendations, :trainer_comments,
                :start_date, :end_date, :status, :created_by, NOW(), NOW()
            )
        ");
        $stmt->execute([
            'member_id' => $data['member_id'],
            'trainer_id' => $data['trainer_id'],
            'goal' => $data['goal'],
            'duration_days' => $data['duration_days'],
            'water_intake_l' => $data['water_intake_l'] ?? null,
            'sleep_hours' => $data['sleep_hours'] ?? null,
            'recommendations' => $data['recommendations'] ?? null,
            'trainer_comments' => $data['trainer_comments'] ?? null,
            'start_date' => $data['start_date'],
            'end_date' => $data['end_date'] ?? null,
            'status' => $data['status'] ?? 'DRAFT',
            'created_by' => $data['created_by']
        ]);
        return (int)$this->db->lastInsertId();
    }

    public function getDietPlan(int $dietPlanId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT dp.*, 
                   u_member.name AS member_name, u_member.email AS member_email,
                   u_creator.name AS creator_name,
                   t.full_name AS trainer_name
            FROM member_diet_plans dp
            JOIN member_profiles up ON up.profile_id = dp.member_id
            JOIN users u_member ON u_member.user_id = up.user_id
            JOIN users u_creator ON u_creator.user_id = dp.created_by
            JOIN trainer_profiles tp ON tp.trainer_profile_id = dp.trainer_id
            JOIN employees t ON t.employee_id = tp.employee_id
            WHERE dp.diet_plan_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $dietPlanId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;

        $row['diet_plan_id'] = (int)$row['diet_plan_id'];
        $row['member_id'] = (int)$row['member_id'];
        $row['trainer_id'] = (int)$row['trainer_id'];
        $row['duration_days'] = (int)$row['duration_days'];
        $row['water_intake_l'] = $row['water_intake_l'] !== null ? (float)$row['water_intake_l'] : null;
        $row['sleep_hours'] = $row['sleep_hours'] !== null ? (float)$row['sleep_hours'] : null;
        $row['created_by'] = (int)$row['created_by'];
        $row['recommendations'] = $row['recommendations'] ? json_decode($row['recommendations'], true) : null;
        
        return $row;
    }

    public function getAllDietPlans(array $filters = []): array
    {
        $sql = "SELECT dp.*, 
                       u_member.name AS member_name, u_member.email AS member_email,
                       u_creator.name AS creator_name,
                       t.full_name AS trainer_name
                FROM member_diet_plans dp
                JOIN member_profiles up ON up.profile_id = dp.member_id
                JOIN users u_member ON u_member.user_id = up.user_id
                JOIN users u_creator ON u_creator.user_id = dp.created_by
                JOIN trainer_profiles tp ON tp.trainer_profile_id = dp.trainer_id
                JOIN employees t ON t.employee_id = tp.employee_id";
        
        $where = [];
        $params = [];
        
        if (!empty($filters['member_id'])) {
            $where[] = "dp.member_id = :member_id";
            $params['member_id'] = (int)$filters['member_id'];
        }
        if (!empty($filters['trainer_id'])) {
            $where[] = "dp.trainer_id = :trainer_id";
            $params['trainer_id'] = (int)$filters['trainer_id'];
        }
        if (!empty($filters['goal'])) {
            $where[] = "dp.goal = :goal";
            $params['goal'] = $filters['goal'];
        }
        if (!empty($filters['status'])) {
            $where[] = "dp.status = :status";
            $params['status'] = $filters['status'];
        }
        
        if ($where) {
            $sql .= " WHERE " . implode(" AND ", $where);
        }
        
        $sql .= " ORDER BY dp.created_at DESC";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($rows as &$row) {
            $row['diet_plan_id'] = (int)$row['diet_plan_id'];
            $row['member_id'] = (int)$row['member_id'];
            $row['trainer_id'] = (int)$row['trainer_id'];
            $row['duration_days'] = (int)$row['duration_days'];
            $row['water_intake_l'] = $row['water_intake_l'] !== null ? (float)$row['water_intake_l'] : null;
            $row['sleep_hours'] = $row['sleep_hours'] !== null ? (float)$row['sleep_hours'] : null;
            $row['created_by'] = (int)$row['created_by'];
            $row['recommendations'] = $row['recommendations'] ? json_decode($row['recommendations'], true) : null;
        }
        return $rows;
    }

    public function updateDietPlan(int $dietPlanId, array $data): bool
    {
        $fields = [];
        $params = ['diet_plan_id' => $dietPlanId];
        
        $allowed = [
            'member_id', 'trainer_id', 'goal', 'duration_days',
            'water_intake_l', 'sleep_hours', 'recommendations', 'trainer_comments',
            'start_date', 'end_date', 'status'
        ];
        
        foreach ($allowed as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[$field] = $data[$field];
            }
        }
        
        if (empty($fields)) return false;
        
        $sql = "UPDATE member_diet_plans 
                SET " . implode(", ", $fields) . ", updated_at = NOW() 
                WHERE diet_plan_id = :diet_plan_id";
                
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function deleteDietPlan(int $dietPlanId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM member_diet_plans WHERE diet_plan_id = :id");
        return $stmt->execute(['id' => $dietPlanId]);
    }

    public function updateDietPlanStatus(int $dietPlanId, string $status): bool
    {
        $stmt = $this->db->prepare("
            UPDATE member_diet_plans 
            SET status = :status, updated_at = NOW() 
            WHERE diet_plan_id = :id
        ");
        return $stmt->execute(['status' => $status, 'id' => $dietPlanId]);
    }

    public function cloneDietPlan(int $dietPlanId, int $createdById): int|false
    {
        try {
            $this->db->beginTransaction();
            
            $orig = $this->getDietPlan($dietPlanId);
            if (!$orig) {
                $this->db->rollBack();
                return false;
            }
            
            $startDate = date('Y-m-d');
            $endDate = date('Y-m-d', strtotime("+" . $orig['duration_days'] . " days"));
            
            $stmt = $this->db->prepare("
                INSERT INTO member_diet_plans (
                    member_id, trainer_id, goal, duration_days,
                    water_intake_l, sleep_hours, recommendations, trainer_comments,
                    start_date, end_date, status, created_by, created_at, updated_at
                ) VALUES (
                    :member_id, :trainer_id, :goal, :duration_days,
                    :water_intake_l, :sleep_hours, :recommendations, :trainer_comments,
                    :start_date, :end_date, 'DRAFT', :created_by, NOW(), NOW()
                )
            ");
            $stmt->execute([
                'member_id' => $orig['member_id'],
                'trainer_id' => $orig['trainer_id'],
                'goal' => $orig['goal'],
                'duration_days' => $orig['duration_days'],
                'water_intake_l' => $orig['water_intake_l'],
                'sleep_hours' => $orig['sleep_hours'],
                'recommendations' => $orig['recommendations'] ? json_encode($orig['recommendations']) : null,
                'trainer_comments' => $orig['trainer_comments'],
                'start_date' => $startDate,
                'end_date' => $endDate,
                'created_by' => $createdById
            ]);
            
            $newPlanId = (int)$this->db->lastInsertId();
            
            $meals = $this->getDietPlanMeals($dietPlanId);
            foreach ($meals as $meal) {
                $stmtMeal = $this->db->prepare("
                    INSERT INTO member_diet_plan_meals (
                        diet_plan_id, meal_order, meal_title, meal_time, meal_items, notes, created_at
                    ) VALUES (
                        :diet_plan_id, :meal_order, :meal_title, :meal_time, :meal_items, :notes, NOW()
                    )
                ");
                $stmtMeal->execute([
                    'diet_plan_id' => $newPlanId,
                    'meal_order' => $meal['meal_order'],
                    'meal_title' => $meal['meal_title'],
                    'meal_time' => $meal['meal_time'],
                    'meal_items' => json_encode($meal['meal_items']),
                    'notes' => $meal['notes']
                ]);
            }
            
            $this->db->commit();
            return $newPlanId;
            
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Clone Diet Plan Error: " . $e->getMessage());
            return false;
        }
    }

    public function createMeal(int $dietPlanId, array $data): int
    {
        if (!isset($data['meal_order'])) {
            $stmt = $this->db->prepare("SELECT COALESCE(MAX(meal_order), 0) + 1 FROM member_diet_plan_meals WHERE diet_plan_id = :id");
            $stmt->execute(['id' => $dietPlanId]);
            $data['meal_order'] = (int)$stmt->fetchColumn();
        }
        
        $stmt = $this->db->prepare("
            INSERT INTO member_diet_plan_meals (
                diet_plan_id, meal_order, meal_title, meal_time, meal_items, notes, created_at
            ) VALUES (
                :diet_plan_id, :meal_order, :meal_title, :meal_time, :meal_items, :notes, NOW()
            )
        ");
        $stmt->execute([
            'diet_plan_id' => $dietPlanId,
            'meal_order' => $data['meal_order'],
            'meal_title' => $data['meal_title'],
            'meal_time' => $data['meal_time'] ?? null,
            'meal_items' => $data['meal_items'],
            'notes' => $data['notes'] ?? null
        ]);
        return (int)$this->db->lastInsertId();
    }

    public function getMeal(int $mealId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM member_diet_plan_meals WHERE meal_id = :id LIMIT 1");
        $stmt->execute(['id' => $mealId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;
        
        $row['meal_id'] = (int)$row['meal_id'];
        $row['diet_plan_id'] = (int)$row['diet_plan_id'];
        $row['meal_order'] = (int)$row['meal_order'];
        $row['meal_items'] = json_decode($row['meal_items'], true);
        return $row;
    }

    public function getDietPlanMeals(int $dietPlanId): array
    {
        $stmt = $this->db->prepare("
            SELECT * FROM member_diet_plan_meals 
            WHERE diet_plan_id = :id 
            ORDER BY meal_order ASC
        ");
        $stmt->execute(['id' => $dietPlanId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) {
            $row['meal_id'] = (int)$row['meal_id'];
            $row['diet_plan_id'] = (int)$row['diet_plan_id'];
            $row['meal_order'] = (int)$row['meal_order'];
            $row['meal_items'] = json_decode($row['meal_items'], true);
        }
        return $rows;
    }

    public function updateMeal(int $mealId, array $data): bool
    {
        $fields = [];
        $params = ['meal_id' => $mealId];
        
        $allowed = ['meal_order', 'meal_title', 'meal_time', 'meal_items', 'notes'];
        
        foreach ($allowed as $field) {
            if (array_key_exists($field, $data)) {
                $fields[] = "$field = :$field";
                $params[$field] = $data[$field];
            }
        }
        
        if (empty($fields)) return false;
        
        $sql = "UPDATE member_diet_plan_meals 
                SET " . implode(", ", $fields) . " 
                WHERE meal_id = :meal_id";
                
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    public function deleteMeal(int $mealId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM member_diet_plan_meals WHERE meal_id = :id");
        return $stmt->execute(['id' => $mealId]);
    }

    public function reorderMeals(int $dietPlanId, array $mealIds): bool
    {
        try {
            $this->db->beginTransaction();
            
            $stmt = $this->db->prepare("SELECT meal_id FROM member_diet_plan_meals WHERE diet_plan_id = :id");
            $stmt->execute(['id' => $dietPlanId]);
            $existingIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            foreach ($mealIds as $mealId) {
                if (!in_array($mealId, $existingIds)) {
                    throw new Exception("Meal ID $mealId does not belong to Diet Plan $dietPlanId");
                }
            }
            
            $stmtUpdate = $this->db->prepare("UPDATE member_diet_plan_meals SET meal_order = :order WHERE meal_id = :meal_id AND diet_plan_id = :diet_plan_id");
            foreach ($mealIds as $index => $mealId) {
                $stmtUpdate->execute([
                    'order' => $index + 1,
                    'meal_id' => $mealId,
                    'diet_plan_id' => $dietPlanId
                ]);
            }
            
            $this->db->commit();
            return true;
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log("Reorder Meals Error: " . $e->getMessage());
            return false;
        }
    }

    public function getMemberDietPlans(int $memberId): array
    {
        return $this->getAllDietPlans(['member_id' => $memberId]);
    }

    public function getMemberActiveDietPlan(int $memberId): ?array
    {
        $plans = $this->getAllDietPlans(['member_id' => $memberId, 'status' => 'ACTIVE']);
        return !empty($plans) ? $plans[0] : null;
    }

    public function getMemberDietPlansHistory(int $memberId): array
    {
        $sql = "SELECT dp.*, 
                       u_member.name AS member_name, u_member.email AS member_email,
                       u_creator.name AS creator_name,
                       t.full_name AS trainer_name
                FROM member_diet_plans dp
                JOIN member_profiles up ON up.profile_id = dp.member_id
                JOIN users u_member ON u_member.user_id = up.user_id
                JOIN users u_creator ON u_creator.user_id = dp.created_by
                JOIN trainer_profiles tp ON tp.trainer_profile_id = dp.trainer_id
                JOIN employees t ON t.employee_id = tp.employee_id
                WHERE dp.member_id = :member_id AND dp.status != 'ACTIVE'
                ORDER BY dp.created_at DESC";
        
        $stmt = $this->db->prepare($sql);       
        $stmt->execute(['member_id' => $memberId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($rows as &$row) {
            $row['diet_plan_id'] = (int)$row['diet_plan_id'];
            $row['member_id'] = (int)$row['member_id'];
            $row['trainer_id'] = (int)$row['trainer_id'];
            $row['duration_days'] = (int)$row['duration_days'];
            $row['water_intake_l'] = $row['water_intake_l'] !== null ? (float)$row['water_intake_l'] : null;
            $row['sleep_hours'] = $row['sleep_hours'] !== null ? (float)$row['sleep_hours'] : null;
            $row['created_by'] = (int)$row['created_by'];
            $row['recommendations'] = $row['recommendations'] ? json_decode($row['recommendations'], true) : null;
        }
        return $rows;
    }

    public function createDietPlanWithMeals(array $planData, array $meals): int
    {
        try {
            $this->db->beginTransaction();

            // 1. Create the Diet Plan
            $planId = $this->createDietPlan($planData);

            // 2. Add Each Meal
            foreach ($meals as $index => $meal) {
                if (empty($meal['meal_title'])) {
                    throw new Exception("Meal title is required for all meals.", 400);
                }
                if (!isset($meal['meal_items'])) {
                    throw new Exception("Meal items is required for all meals.", 400);
                }

                $mealItems = null;
                if (is_array($meal['meal_items'])) {
                    $mealItems = json_encode($meal['meal_items']);
                } else {
                    json_decode($meal['meal_items']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        throw new Exception("Meal items must be a valid JSON array or object.", 400);
                    }
                    $mealItems = $meal['meal_items'];
                }

                $mealData = [
                    'meal_title' => trim($meal['meal_title']),
                    'meal_time' => !empty($meal['meal_time']) ? trim($meal['meal_time']) : null,
                    'meal_items' => $mealItems,
                    'notes' => $meal['notes'] ?? null,
                    'meal_order' => isset($meal['meal_order']) ? (int)$meal['meal_order'] : ($index + 1)
                ];

                $this->createMeal($planId, $mealData);
            }

            $this->db->commit();
            return $planId;
        } catch (\Exception $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    public function updateDietPlanWithMeals(int $dietPlanId, array $planData, array $meals): bool
    {
        try {
            $this->db->beginTransaction();

            if (!empty($planData)) {
                $this->updateDietPlan($dietPlanId, $planData);
            }

            $stmt = $this->db->prepare("DELETE FROM member_diet_plan_meals WHERE diet_plan_id = :id");
            $stmt->execute(['id' => $dietPlanId]);

            foreach ($meals as $index => $meal) {
                if (empty($meal['meal_title'])) {
                    throw new Exception("Meal title is required for all meals.", 400);
                }
                if (!isset($meal['meal_items'])) {
                    throw new Exception("Meal items is required for all meals.", 400);
                }

                $mealItems = null;
                if (is_array($meal['meal_items'])) {
                    $mealItems = json_encode($meal['meal_items']);
                } else {
                    json_decode($meal['meal_items']);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        throw new Exception("Meal items must be a valid JSON array or object.", 400);
                    }
                    $mealItems = $meal['meal_items'];
                }

                $mealData = [
                    'meal_title' => trim($meal['meal_title']),
                    'meal_time' => !empty($meal['meal_time']) ? trim($meal['meal_time']) : null,
                    'meal_items' => $mealItems,
                    'notes' => $meal['notes'] ?? null,
                    'meal_order' => isset($meal['meal_order']) ? (int)$meal['meal_order'] : ($index + 1)
                ];

                $this->createMeal($dietPlanId, $mealData);
            }

            $this->db->commit();
            return true;
        } catch (\Exception $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Check if a member has active diet plan access credits.
     */
    public function checkDietPlanAccess(int $userId): bool
    {
        $sql = "
            SELECT COUNT(*) 
            FROM client_wallet_credits 
            WHERE user_id = :user_id 
              AND entitlement_type = 'ACCESS_DIET_PLANS' 
              AND status = 1 
              AND remaining_quantity > 0 
              AND expiration_date >= CURDATE()
        ";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['user_id' => $userId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    /**
     * Resolve user_id from profile_id.
     */
    public function getUserIdFromProfileId(int $profileId): ?int
    {
        $stmt = $this->db->prepare("SELECT user_id FROM member_profiles WHERE profile_id = :id LIMIT 1");
        $stmt->execute(['id' => $profileId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int)$val : null;
    }

    /**
     * Resolve profile_id from user_id.
     */
    public function getProfileIdFromUserId(int $userId): ?int
    {
        $stmt = $this->db->prepare("SELECT profile_id FROM member_profiles WHERE user_id = :id LIMIT 1");
        $stmt->execute(['id' => $userId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int)$val : null;
    }

    /**
     * Return 2 static diet plans for normal members without a PT plan.
     */
    public function getStaticDietPlans(): array
    {
        $fatLossPlan = [
            'diet_plan_id'     => 901,
            'member_id'        => 0,
            'trainer_id'       => 0,
            'goal'             => 'FAT_LOSS',
            'plan_title'       => 'Standard Fat Loss Diet Plan',
            'duration_days'    => 30,
            'water_intake_l'   => 3.5,
            'sleep_hours'      => 8.0,
            'recommendations'  => [
                "Drink at least 3.5 Liters of water daily",
                "Avoid refined sugars, sodas, and fried foods",
                "Maintain a slight calorie deficit",
                "Perform 30 minutes of cardio daily alongside weight training"
            ],
            'trainer_comments' => "Standard Fat Loss Nutrition Guide for general gym members without personal training.",
            'start_date'       => "2026-01-01",
            'end_date'         => "2026-12-31",
            'status'           => "ACTIVE",
            'created_by'       => 1,
            'created_at'       => "2026-01-01 00:00:00",
            'updated_at'       => "2026-01-01 00:00:00",
            'member_name'      => "Member",
            'member_email'     => "",
            'creator_name'     => "Fitness Guru System",
            'trainer_name'     => "Fitness Guru Certified Trainer",
            'is_static'        => true,
            'meals'            => [
                [
                    'meal_id'      => 9001,
                    'diet_plan_id' => 901,
                    'meal_order'   => 1,
                    'meal_title'   => "Breakfast",
                    'meal_time'    => "08:00 AM",
                    'meal_items'   => [
                        ['name' => 'Oats with Skimmed Milk', 'quantity' => '1 bowl (50g oats)'],
                        ['name' => 'Boiled Egg Whites', 'quantity' => '4 whites'],
                        ['name' => 'Raw Almonds', 'quantity' => '5 pieces']
                    ],
                    'notes'        => "Drink 1 glass of warm water before breakfast."
                ],
                [
                    'meal_id'      => 9002,
                    'diet_plan_id' => 901,
                    'meal_order'   => 2,
                    'meal_title'   => "Mid-Morning Snack",
                    'meal_time'    => "11:00 AM",
                    'meal_items'   => [
                        ['name' => 'Green Tea', 'quantity' => '1 cup'],
                        ['name' => 'Apple or Papaya', 'quantity' => '1 medium bowl']
                    ],
                    'notes'        => "No added sugar."
                ],
                [
                    'meal_id'      => 9003,
                    'diet_plan_id' => 901,
                    'meal_order'   => 3,
                    'meal_title'   => "Lunch",
                    'meal_time'    => "01:30 PM",
                    'meal_items'   => [
                        ['name' => 'Grilled Chicken / Tofu / Paneer', 'quantity' => '150g'],
                        ['name' => 'Brown Rice or Multigrain Roti', 'quantity' => '1 small bowl / 1 roti'],
                        ['name' => 'Mixed Salad (Cucumber, Tomato)', 'quantity' => '1 bowl']
                    ],
                    'notes'        => "Cook with minimal olive oil."
                ],
                [
                    'meal_id'      => 9004,
                    'diet_plan_id' => 901,
                    'meal_order'   => 4,
                    'meal_title'   => "Evening Snack",
                    'meal_time'    => "05:00 PM",
                    'meal_items'   => [
                        ['name' => 'Sprouted Moong / Roasted Chana', 'quantity' => '1 small bowl'],
                        ['name' => 'Black Coffee or Green Tea', 'quantity' => '1 cup']
                    ],
                    'notes'        => "Pre-workout energy booster."
                ],
                [
                    'meal_id'      => 9005,
                    'diet_plan_id' => 901,
                    'meal_order'   => 5,
                    'meal_title'   => "Dinner",
                    'meal_time'    => "08:00 PM",
                    'meal_items'   => [
                        ['name' => 'Steamed Fish / Low-Fat Paneer', 'quantity' => '120g'],
                        ['name' => 'Sautéed Vegetables (Broccoli, Capsicum)', 'quantity' => '1 bowl']
                    ],
                    'notes'        => "Keep dinner light at least 2 hours before sleep."
                ]
            ]
        ];

        $weightGainPlan = [
            'diet_plan_id'     => 902,
            'member_id'        => 0,
            'trainer_id'       => 0,
            'goal'             => 'WEIGHT_GAIN',
            'plan_title'       => 'Standard Weight Gain Diet Plan',
            'duration_days'    => 30,
            'water_intake_l'   => 4.0,
            'sleep_hours'      => 8.0,
            'recommendations'  => [
                "Maintain a caloric surplus with nutrient-dense foods",
                "Drink at least 4 Liters of water daily",
                "Include high-protein snacks between major meals",
                "Focus on progressive overload strength training"
            ],
            'trainer_comments' => "Standard Muscle & Weight Gain Nutrition Guide for general gym members without personal training.",
            'start_date'       => "2026-01-01",
            'end_date'         => "2026-12-31",
            'status'           => "ACTIVE",
            'created_by'       => 1,
            'created_at'       => "2026-01-01 00:00:00",
            'updated_at'       => "2026-01-01 00:00:00",
            'member_name'      => "Member",
            'member_email'     => "",
            'creator_name'     => "Fitness Guru System",
            'trainer_name'     => "Fitness Guru Certified Trainer",
            'is_static'        => true,
            'meals'            => [
                [
                    'meal_id'      => 9006,
                    'diet_plan_id' => 902,
                    'meal_order'   => 1,
                    'meal_title'   => "Breakfast",
                    'meal_time'    => "08:00 AM",
                    'meal_items'   => [
                        ['name' => 'Oatmeal with Whole Milk & Honey', 'quantity' => '1 large bowl (80g oats)'],
                        ['name' => 'Whole Eggs', 'quantity' => '3 whole + 2 whites'],
                        ['name' => 'Peanut Butter Toast', 'quantity' => '2 slices brown bread'],
                        ['name' => 'Banana', 'quantity' => '1 large']
                    ],
                    'notes'        => "High calorie energy start."
                ],
                [
                    'meal_id'      => 9007,
                    'diet_plan_id' => 902,
                    'meal_order'   => 2,
                    'meal_title'   => "Mid-Morning Shake",
                    'meal_time'    => "11:00 AM",
                    'meal_items'   => [
                        ['name' => 'Banana Peanut Butter Protein Shake', 'quantity' => '350ml'],
                        ['name' => 'Mixed Nuts (Cashews, Almonds, Walnuts)', 'quantity' => '30g']
                    ],
                    'notes'        => "Calorie-dense liquid meal."
                ],
                [
                    'meal_id'      => 9008,
                    'diet_plan_id' => 902,
                    'meal_order'   => 3,
                    'meal_title'   => "Lunch",
                    'meal_time'    => "01:30 PM",
                    'meal_items'   => [
                        ['name' => 'Chicken / Fish / Paneer Curry', 'quantity' => '200g'],
                        ['name' => 'White or Brown Rice / Rotis with Ghee', 'quantity' => '2 cups rice / 3 rotis'],
                        ['name' => 'Dal / Rajma', 'quantity' => '1 bowl'],
                        ['name' => 'Curd', 'quantity' => '1 cup']
                    ],
                    'notes'        => "Heavy protein & carb lunch."
                ],
                [
                    'meal_id'      => 9009,
                    'diet_plan_id' => 902,
                    'meal_order'   => 4,
                    'meal_title'   => "Pre-Workout Snack",
                    'meal_time'    => "05:00 PM",
                    'meal_items'   => [
                        ['name' => 'Boiled Potatoes / Sweet Potato', 'quantity' => '200g'],
                        ['name' => 'Boiled Eggs / Paneer Cubes', 'quantity' => '2 eggs / 50g paneer']
                    ],
                    'notes'        => "Fuel for intense workout."
                ],
                [
                    'meal_id'      => 9010,
                    'diet_plan_id' => 902,
                    'meal_order'   => 5,
                    'meal_title'   => "Dinner",
                    'meal_time'    => "08:30 PM",
                    'meal_items'   => [
                        ['name' => 'Grilled Chicken / Tofu / Fish', 'quantity' => '180g'],
                        ['name' => 'Multigrain Rotis', 'quantity' => '2 rotis'],
                        ['name' => 'Mixed Vegetable Sabzi', 'quantity' => '1 bowl']
                    ],
                    'notes'        => "Protein rich meal for night muscle recovery."
                ]
            ]
        ];

        return [$fatLossPlan, $weightGainPlan];
    }
}


