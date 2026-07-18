<?php

require_once __DIR__ . '/../repositories/MembershipModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class MembershipWorkflow
{
    private MembershipModel $model;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';
    private const ALLOWED_PLAN_TYPES = ['BASE_MEMBERSHIP', 'PT_UPGRADE', 'ADD_ON'];

    public function __construct()
    {
        $this->model = new MembershipModel();
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
     * SAPI-aware response header helper.
     */
    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    /* ========================================================================= */
    /* ========================= MEMBERSHIP PLANS WORKFLOWS ==================== */
    /* ========================================================================= */

    /**
     * Fetch all membership plans with features. Accessible by Admin, Trainer, Member.
     */
    public function listMembershipPlans(string $accessToken, array $filters = []): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER', 'MEMBER']);
            $role = str_replace(['_', '-'], '', strtoupper($decoded->role));

            // Default status to active (1) for non-admins if not provided
            if ($role === 'MEMBER' || $role === 'TRAINER') {
                if (!isset($filters['status'])) {
                    $filters['status'] = 1;
                }
            }

            $plans = $this->model->getAllPlans($filters);
            return ["status" => "success", "data" => $plans];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Fetch single membership plan with features. Accessible by Admin, Trainer, Member.
     */
    public function getMembershipPlanDetails(string $accessToken, int $planId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER', 'MEMBER']);

            $plan = $this->model->getPlanById($planId);
            if (!$plan) {
                throw new Exception("Membership plan not found", 404);
            }

            return ["status" => "success", "data" => $plan];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Create a new membership plan with optional entitlements. Admin only.
     */
    public function createMembershipPlan(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            // Required validation
            $required = ['plan_name', 'plan_type', 'duration_months', 'price'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || (is_string($data[$field]) && trim($data[$field]) === '')) {
                    throw new Exception("Field '$field' is required", 400);
                }
            }

            $planType = strtoupper(trim($data['plan_type']));
            if (!in_array($planType, self::ALLOWED_PLAN_TYPES)) {
                throw new Exception("Invalid plan_type. Allowed types: " . implode(', ', self::ALLOWED_PLAN_TYPES), 400);
            }

            $duration = (int)$data['duration_months'];
            if ($duration <= 0) {
                throw new Exception("duration_months must be a positive integer", 400);
            }

            $price = (float)$data['price'];
            if ($price < 0) {
                throw new Exception("price cannot be negative", 400);
            }

            // Resolve gym_id & branch_id
            $gymId = isset($data['gym_id']) ? (int)$data['gym_id'] : null;
            $branchId = isset($data['branch_id']) ? (int)$data['branch_id'] : null;

            if (!$gymId || !$branchId) {
                $gymBranch = $this->model->getUserGymBranch($adminUserId);
                if ($gymBranch) {
                    $gymId = $gymId ?: $gymBranch['gym_id'];
                    $branchId = $branchId ?: $gymBranch['branch_id'];
                } else {
                    $gymId = $gymId ?: 1;
                    $branchId = $branchId ?: 1;
                }
            }

            $this->model->beginTransaction();

            $planData = [
                'gym_id'              => $gymId,
                'branch_id'           => $branchId,
                'plan_name'           => $data['plan_name'],
                'plan_type'           => $planType,
                'duration_months'     => $duration,
                'price'               => $price,
                'requires_membership' => isset($data['requires_membership']) ? (int)$data['requires_membership'] : 0,
                'status'              => isset($data['status']) ? (int)$data['status'] : 1
            ];

            $planId = $this->model->createPlan($planData);

            // Insert entitlements if provided
            if (isset($data['entitlements']) && is_array($data['entitlements'])) {
                $this->model->setPlanEntitlements($planId, $data['entitlements']);
            }

            $this->model->commit();

            return [
                "status"    => "success",
                "message"   => "Membership plan created successfully",
                "plan_id"   => $planId
            ];

        } catch (\Throwable $e) {
            $this->model->rollBack();
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Update an existing membership plan and its entitlements. Admin only.
     */
    public function updateMembershipPlan(string $accessToken, int $planId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getPlanById($planId);
            if (!$existing) {
                throw new Exception("Membership plan not found", 404);
            }

            if (isset($data['plan_type'])) {
                $planType = strtoupper(trim($data['plan_type']));
                if (!in_array($planType, self::ALLOWED_PLAN_TYPES)) {
                    throw new Exception("Invalid plan_type. Allowed types: " . implode(', ', self::ALLOWED_PLAN_TYPES), 400);
                }
            }

            $this->model->beginTransaction();

            $this->model->updatePlan($planId, $data);

            if (isset($data['entitlements']) && is_array($data['entitlements'])) {
                $this->model->setPlanEntitlements($planId, $data['entitlements']);
            }

            $this->model->commit();

            return [
                "status"  => "success",
                "message" => "Membership plan updated successfully",
                "plan_id" => $planId
            ];

        } catch (\Throwable $e) {
            $this->model->rollBack();
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Soft delete/deactivate a membership plan. Admin only.
     */
    public function deleteMembershipPlan(string $accessToken, int $planId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getPlanById($planId);
            if (!$existing) {
                throw new Exception("Membership plan not found", 404);
            }

            $this->model->deletePlan($planId);

            return [
                "status"  => "success",
                "message" => "Membership plan deactivated successfully",
                "plan_id" => $planId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Manage entitlements for a plan. Admin only.
     */
    public function managePlanEntitlements(string $accessToken, int $planId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getPlanById($planId);
            if (!$existing) {
                throw new Exception("Membership plan not found", 404);
            }

            if (!isset($data['entitlements']) || !is_array($data['entitlements'])) {
                throw new Exception("Field 'entitlements' must be an array of objects", 400);
            }

            $this->model->setPlanEntitlements($planId, $data['entitlements']);

            return [
                "status"  => "success",
                "message" => "Plan entitlements updated successfully",
                "plan_id" => $planId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Delete a single entitlement from a plan. Admin only.
     */
    public function deleteSingleEntitlement(string $accessToken, int $planId, string $entitlementType): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getPlanById($planId);
            if (!$existing) {
                throw new Exception("Membership plan not found", 404);
            }

            $this->model->deleteSingleEntitlement($planId, $entitlementType);

            return [
                "status"  => "success",
                "message" => "Entitlement '$entitlementType' removed successfully",
                "plan_id" => $planId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /* ========================================================================= */
    /* ========================= SUBSCRIPTIONS WORKFLOWS ======================= */
    /* ========================================================================= */

    /**
     * List all subscriptions. Admin only.
     */
    public function listSubscriptions(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $subscriptions = $this->model->getAllSubscriptions($filters);
            return ["status" => "success", "data" => $subscriptions];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get single subscription details. Admin only.
     */
    public function getSubscriptionDetails(string $accessToken, int $subId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $sub = $this->model->getSubscriptionById($subId);
            if (!$sub) {
                throw new Exception("Subscription not found", 404);
            }

            return ["status" => "success", "data" => $sub];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Create a new subscription for a member and provision wallet credits. Admin only.
     */
    public function createSubscription(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            if (empty($data['user_id']) || empty($data['plan_id'])) {
                throw new Exception("user_id and plan_id are required", 400);
            }

            $userId = (int)$data['user_id'];
            $planId = (int)$data['plan_id'];

            if (!$this->model->userExists($userId)) {
                throw new Exception("User with ID $userId does not exist", 404);
            }

            $plan = $this->model->getPlanById($planId);
            if (!$plan || $plan['status'] !== 1) {
                throw new Exception("Invalid or inactive membership plan", 404);
            }

            // Resolve gym & branch ID
            $gymBranch = $this->model->getUserGymBranch($userId);
            $gymId = $data['gym_id'] ?? ($gymBranch ? $gymBranch['gym_id'] : 1);
            $branchId = $data['branch_id'] ?? ($gymBranch ? $gymBranch['branch_id'] : 1);

            // Calculate start and end dates
            $startDate = !empty($data['start_date']) ? trim($data['start_date']) : date('Y-m-d');
            $durationMonths = (int)($plan['duration_months'] ?: 1);

            if (!empty($data['end_date'])) {
                $endDate = trim($data['end_date']);
            } else {
                $endDate = date('Y-m-d', strtotime($startDate . " + $durationMonths months"));
            }

            $this->model->beginTransaction();

            $subData = [
                'gym_id'     => $gymId,
                'branch_id'  => $branchId,
                'user_id'    => $userId,
                'plan_id'    => $planId,
                'start_date' => $startDate,
                'end_date'   => $endDate,
                'status'     => isset($data['status']) ? (int)$data['status'] : 1
            ];

            $subId = $this->model->createSubscription($subData);

            // Provision wallet credits based on plan entitlements
            $this->model->provisionWalletCredits($subId, $userId, $planId, $startDate, $endDate);

            $this->model->commit();

            return [
                "status"          => "success",
                "message"         => "Subscription created and wallet credits provisioned successfully",
                "subscription_id" => $subId
            ];

        } catch (\Throwable $e) {
            $this->model->rollBack();
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Update an existing subscription. Admin only.
     */
    public function updateSubscription(string $accessToken, int $subId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getSubscriptionById($subId);
            if (!$existing) {
                throw new Exception("Subscription not found", 404);
            }

            $this->model->beginTransaction();

            $this->model->updateSubscription($subId, $data);

            $this->model->commit();

            return [
                "status"          => "success",
                "message"         => "Subscription updated successfully",
                "subscription_id" => $subId
            ];

        } catch (\Throwable $e) {
            $this->model->rollBack();
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Cancel/Deactivate a subscription and its wallet credits. Admin only.
     */
    public function cancelSubscription(string $accessToken, int $subId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getSubscriptionById($subId);
            if (!$existing) {
                throw new Exception("Subscription not found", 404);
            }

            $this->model->cancelSubscription($subId);

            return [
                "status"          => "success",
                "message"         => "Subscription canceled and wallet credits revoked successfully",
                "subscription_id" => $subId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Member self-service: Fetch member's active subscription and credits.
     */
    public function getMyActiveSubscription(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            $subscription = $this->model->getMemberActiveSubscription($memberUserId);
            return ["status" => "success", "data" => $subscription];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * GET /api/member/membership-plans
     * Fetch all active membership plans for the member's gym and branch, optional filter by plan_type.
     */
    public function listMemberMembershipPlans(string $accessToken, array $filters = []): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            // Resolve gym & branch ID for this member
            $gymBranch = $this->model->getUserGymBranch($memberUserId);
            if (!$gymBranch) {
                throw new Exception("Member gym/branch context not found", 404);
            }

            $filters['gym_id'] = $gymBranch['gym_id'];
            $filters['branch_id'] = $gymBranch['branch_id'];
            $filters['status'] = 1; // Only active plans

            $plans = $this->model->getAllPlans($filters);
            return ["status" => "success", "data" => $plans];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}
