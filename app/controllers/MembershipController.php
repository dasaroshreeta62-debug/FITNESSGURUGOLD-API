<?php

require_once __DIR__ . '/../services/MembershipWorkflow.php';

class MembershipController
{
    private MembershipWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new MembershipWorkflow();
    }

    /**
     * Retrieve the Bearer Token from HTTP request headers.
     */
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

    /**
     * Get JSON or url-encoded request body inputs.
     */
    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            return [];
        }
        return $input;
    }

    /* ========================================================================= */
    /* ========================= MEMBERSHIP PLANS ============================== */
    /* ========================================================================= */

    /**
     * GET /api/membership-plans
     */
    public function listMembershipPlans(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->listMembershipPlans($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/membership-plans/(\d+)
     */
    public function getMembershipPlanDetails(int $planId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getMembershipPlanDetails($token, $planId);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/membership-plans
     */
    public function createMembershipPlan(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->createMembershipPlan($token, $input);
        echo json_encode($response);
    }

    /**
     * PUT /api/admin/membership-plans/(\d+)
     */
    public function updateMembershipPlan(int $planId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->updateMembershipPlan($token, $planId, $input);
        echo json_encode($response);
    }

    /**
     * DELETE /api/admin/membership-plans/(\d+)
     */
    public function deleteMembershipPlan(int $planId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->deleteMembershipPlan($token, $planId);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/membership-plans/(\d+)/entitlements
     */
    public function managePlanEntitlements(int $planId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->managePlanEntitlements($token, $planId, $input);
        echo json_encode($response);
    }

    /**
     * DELETE /api/admin/membership-plans/(\d+)/entitlements/([A-Z0-9_]+)
     */
    public function deleteSingleEntitlement(int $planId, string $entitlementType): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->deleteSingleEntitlement($token, $planId, $entitlementType);
        echo json_encode($response);
    }

    /* ========================================================================= */
    /* ========================= SUBSCRIPTIONS ================================= */
    /* ========================================================================= */

    /**
     * GET /api/admin/subscriptions
     */
    public function listSubscriptions(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->listSubscriptions($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/subscriptions/stats
     */
    public function getSubscriptionStats(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getSubscriptionStats($token, $_GET);
        echo json_encode($response);
    }


    /**
     * GET /api/admin/subscriptions/(\d+)
     */
    public function getSubscriptionDetails(int $subId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getSubscriptionDetails($token, $subId);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/subscriptions
     */
    public function createSubscription(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->createSubscription($token, $input);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/subscriptions/purchase
     */
    public function purchaseSubscription(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->purchaseSubscription($token, $input);
        echo json_encode($response);
    }

    /**
     * PUT /api/admin/subscriptions/(\d+)
     */
    public function updateSubscription(int $subId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->updateSubscription($token, $subId, $input);
        echo json_encode($response);
    }

    /**
     * PATCH /api/admin/subscriptions/(\d+)/cancel
     * or DELETE /api/admin/subscriptions/(\d+)
     */
    public function cancelSubscription(int $subId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->cancelSubscription($token, $subId);
        echo json_encode($response);
    }

    /**
     * GET /api/member/subscriptions/active
     */
    public function getMyActiveSubscription(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getMyActiveSubscription($token);
        echo json_encode($response);
    }

    /**
     * GET /api/member/membership-plans
     */
    public function listMemberMembershipPlans(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->listMemberMembershipPlans($token, $_GET);
        echo json_encode($response);
    }
}
