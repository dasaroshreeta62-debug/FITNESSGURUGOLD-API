<?php

require_once __DIR__ . '/../services/DietPlanWorkflow.php';

class DietPlanController
{
    private DietPlanWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new DietPlanWorkflow();
    }

    private function getBearerToken(): string|false
    {
        $headers = getallheaders();
        if (empty($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                "status" => "error",
                "message" => "Authorization token missing"
            ]);
            return false;
        }
        return str_replace('Bearer ', '', $headers['Authorization']);
    }

    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            parse_str(file_get_contents("php://input"), $input);
        }
        return is_array($input) ? $input : [];
    }

    /* ========================================================================= */
    /* ========================= ADMIN CONTROLLERS ============================= */
    /* ========================================================================= */

    public function createDietPlan(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->createDietPlan($token, $input);
        echo json_encode($response);
    }

    public function listDietPlans(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listDietPlans($token, $_GET);
        echo json_encode($response);
    }

    public function getDietPlanDetails(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDietPlanDetails($token, $dietPlanId);
        echo json_encode($response);
    }

    public function updateDietPlan(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateDietPlan($token, $dietPlanId, $input);
        echo json_encode($response);
    }

    public function deleteDietPlan(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->deleteDietPlan($token, $dietPlanId);
        echo json_encode($response);
    }

    public function activateDietPlan(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->activateDietPlan($token, $dietPlanId);
        echo json_encode($response);
    }

    public function changeDietPlanStatus(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $status = $input['status'] ?? '';
        if (empty($status)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Status is required"
            ]);
            return;
        }
        $response = $this->workflow->changeDietPlanStatus($token, $dietPlanId, $status);
        echo json_encode($response);
    }

    public function cloneDietPlan(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->cloneDietPlan($token, $dietPlanId);
        echo json_encode($response);
    }

    public function createMeal(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->createMeal($token, $dietPlanId, $input);
        echo json_encode($response);
    }

    public function listDietPlanMeals(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listDietPlanMeals($token, $dietPlanId);
        echo json_encode($response);
    }

    public function getMealDetails(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMealDetails($token, $mealId);
        echo json_encode($response);
    }

    public function updateMeal(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateMeal($token, $mealId, $input);
        echo json_encode($response);
    }

    public function deleteMeal(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->deleteMeal($token, $mealId);
        echo json_encode($response);
    }

    public function reorderMeals(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $mealIds = $input['meal_ids'] ?? [];
        if (empty($mealIds) || !is_array($mealIds)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "meal_ids array is required"
            ]);
            return;
        }
        $response = $this->workflow->reorderMeals($token, $dietPlanId, $mealIds);
        echo json_encode($response);
    }

    public function getMemberDietPlans(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberDietPlans($token, $memberId);
        echo json_encode($response);
    }

    public function getMemberActiveDietPlan(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberActiveDietPlan($token, $memberId);
        echo json_encode($response);
    }

    public function getMemberDietPlansHistory(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberDietPlansHistory($token, $memberId);
        echo json_encode($response);
    }

    /* ========================================================================= */
    /* ======================== TRAINER CONTROLLERS ============================ */
    /* ========================================================================= */

    public function listTrainerAssignedMembers(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listTrainerAssignedMembers($token);
        echo json_encode($response);
    }

    public function getTrainerAssignedMemberDetails(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getTrainerAssignedMemberDetails($token, $memberId);
        echo json_encode($response);
    }

    public function createDietPlanByTrainer(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->createDietPlanByTrainer($token, $memberId, $input);
        echo json_encode($response);
    }

    public function listTrainerDietPlans(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listTrainerDietPlans($token);
        echo json_encode($response);
    }

    public function getDietPlanDetailsByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDietPlanDetailsByTrainer($token, $dietPlanId);
        echo json_encode($response);
    }

    public function updateDietPlanByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateDietPlanByTrainer($token, $dietPlanId, $input);
        echo json_encode($response);
    }

    public function deleteDietPlanByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->deleteDietPlanByTrainer($token, $dietPlanId);
        echo json_encode($response);
    }

    public function activateDietPlanByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->activateDietPlanByTrainer($token, $dietPlanId);
        echo json_encode($response);
    }

    public function changeDietPlanStatusByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $status = $input['status'] ?? '';
        if (empty($status)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "Status is required"
            ]);
            return;
        }
        $response = $this->workflow->changeDietPlanStatusByTrainer($token, $dietPlanId, $status);
        echo json_encode($response);
    }

    public function cloneDietPlanByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->cloneDietPlanByTrainer($token, $dietPlanId);
        echo json_encode($response);
    }

    public function createMealByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->createMealByTrainer($token, $dietPlanId, $input);
        echo json_encode($response);
    }

    public function listDietPlanMealsByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listDietPlanMealsByTrainer($token, $dietPlanId);
        echo json_encode($response);
    }

    public function getMealDetailsByTrainer(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMealDetailsByTrainer($token, $mealId);
        echo json_encode($response);
    }

    public function updateMealByTrainer(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateMealByTrainer($token, $mealId, $input);
        echo json_encode($response);
    }

    public function deleteMealByTrainer(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->deleteMealByTrainer($token, $mealId);
        echo json_encode($response);
    }

    public function reorderMealsByTrainer(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $mealIds = $input['meal_ids'] ?? [];
        if (empty($mealIds) || !is_array($mealIds)) {
            http_response_code(400);
            echo json_encode([
                "status" => "error",
                "message" => "meal_ids array is required"
            ]);
            return;
        }
        $response = $this->workflow->reorderMealsByTrainer($token, $dietPlanId, $mealIds);
        echo json_encode($response);
    }

    public function getMemberDietPlansByTrainer(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberDietPlansByTrainer($token, $memberId);
        echo json_encode($response);
    }

    public function getMemberActiveDietPlanByTrainer(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberActiveDietPlanByTrainer($token, $memberId);
        echo json_encode($response);
    }

    public function getMemberDietPlansHistoryByTrainer(int $memberId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberDietPlansHistoryByTrainer($token, $memberId);
        echo json_encode($response);
    }

    /* ========================================================================= */
    /* ========================= MEMBER CONTROLLERS ============================ */
    /* ========================================================================= */

    public function getMyActiveDietPlan(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMyActiveDietPlan($token);
        echo json_encode($response);
    }

    public function getMyDietPlansHistory(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMyDietPlansHistory($token);
        echo json_encode($response);
    }

    public function getMyDietPlans(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMyDietPlans($token);
        echo json_encode($response);
    }

    public function getDietPlanDetailsByMember(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDietPlanDetailsByMember($token, $dietPlanId);
        echo json_encode($response);
    }

    public function getDietPlanMealsByMember(int $dietPlanId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDietPlanMealsByMember($token, $dietPlanId);
        echo json_encode($response);
    }

    public function getMealDetailsByMember(int $mealId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMealDetailsByMember($token, $mealId);
        echo json_encode($response);
    }
}
