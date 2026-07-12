<?php

require_once __DIR__ . '/../config/database.php';

class MembershipModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    /* ========================================================================= */
    /* ========================= MEMBERSHIP PLANS ============================== */
    /* ========================================================================= */

    /**
     * Fetch all membership plans matching optional filters, with entitlements attached.
     */
    public function getAllPlans(array $filters = []): array
    {
        $sql = "SELECT mp.* FROM membership_plans mp WHERE 1=1";
        $params = [];

        if (isset($filters['status']) && $filters['status'] !== '') {
            $sql .= " AND mp.status = :status";
            $params['status'] = (int)$filters['status'];
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND mp.gym_id = :gym_id";
            $params['gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND mp.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        if (!empty($filters['plan_type'])) {
            $sql .= " AND mp.plan_type = :plan_type";
            $params['plan_type'] = strtoupper(trim($filters['plan_type']));
        }

        $sql .= " ORDER BY mp.plan_id DESC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $plans = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($plans as &$plan) {
            $plan['plan_id'] = (int)$plan['plan_id'];
            $plan['gym_id'] = (int)$plan['gym_id'];
            $plan['branch_id'] = (int)$plan['branch_id'];
            $plan['duration_months'] = (int)$plan['duration_months'];
            $plan['price'] = (float)$plan['price'];
            $plan['requires_membership'] = (int)$plan['requires_membership'];
            $plan['status'] = (int)$plan['status'];
            $plan['entitlements'] = $this->getPlanEntitlements($plan['plan_id']);
        }

        return $plans;
    }

    /**
     * Fetch single membership plan details by plan_id, with entitlements attached.
     */
    public function getPlanById(int $planId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM membership_plans WHERE plan_id = :id LIMIT 1");
        $stmt->execute(['id' => $planId]);
        $plan = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$plan) {
            return null;
        }

        $plan['plan_id'] = (int)$plan['plan_id'];
        $plan['gym_id'] = (int)$plan['gym_id'];
        $plan['branch_id'] = (int)$plan['branch_id'];
        $plan['duration_months'] = (int)$plan['duration_months'];
        $plan['price'] = (float)$plan['price'];
        $plan['requires_membership'] = (int)$plan['requires_membership'];
        $plan['status'] = (int)$plan['status'];
        $plan['entitlements'] = $this->getPlanEntitlements($planId);

        return $plan;
    }

    /**
     * Create a new membership plan record.
     */
    public function createPlan(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO membership_plans (
                gym_id, branch_id, plan_name, plan_type, duration_months,
                price, requires_membership, status, createdDate, createdTime
            ) VALUES (
                :gym_id, :branch_id, :plan_name, :plan_type, :duration_months,
                :price, :requires_membership, :status, CURDATE(), CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id'              => $data['gym_id'],
            'branch_id'           => $data['branch_id'],
            'plan_name'           => trim($data['plan_name']),
            'plan_type'           => strtoupper(trim($data['plan_type'])),
            'duration_months'     => (int)$data['duration_months'],
            'price'               => (float)$data['price'],
            'requires_membership' => isset($data['requires_membership']) ? (int)$data['requires_membership'] : 0,
            'status'              => isset($data['status']) ? (int)$data['status'] : 1
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Update an existing membership plan.
     */
    public function updatePlan(int $planId, array $data): bool
    {
        $fields = [];
        $params = ['plan_id' => $planId];

        if (isset($data['plan_name'])) {
            $fields[] = "plan_name = :plan_name";
            $params['plan_name'] = trim($data['plan_name']);
        }
        if (isset($data['plan_type'])) {
            $fields[] = "plan_type = :plan_type";
            $params['plan_type'] = strtoupper(trim($data['plan_type']));
        }
        if (isset($data['duration_months'])) {
            $fields[] = "duration_months = :duration_months";
            $params['duration_months'] = (int)$data['duration_months'];
        }
        if (isset($data['price'])) {
            $fields[] = "price = :price";
            $params['price'] = (float)$data['price'];
        }
        if (isset($data['requires_membership'])) {
            $fields[] = "requires_membership = :requires_membership";
            $params['requires_membership'] = (int)$data['requires_membership'];
        }
        if (isset($data['status'])) {
            $fields[] = "status = :status";
            $params['status'] = (int)$data['status'];
        }
        if (isset($data['gym_id'])) {
            $fields[] = "gym_id = :gym_id";
            $params['gym_id'] = (int)$data['gym_id'];
        }
        if (isset($data['branch_id'])) {
            $fields[] = "branch_id = :branch_id";
            $params['branch_id'] = (int)$data['branch_id'];
        }

        if (empty($fields)) {
            return true;
        }

        $fields[] = "updatedDate = CURDATE()";
        $fields[] = "updatedTime = CURTIME()";

        $sql = "UPDATE membership_plans SET " . implode(', ', $fields) . " WHERE plan_id = :plan_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    /**
     * Soft delete/deactivate a membership plan.
     */
    public function deletePlan(int $planId): bool
    {
        $stmt = $this->db->prepare("UPDATE membership_plans SET status = 0, updatedDate = CURDATE(), updatedTime = CURTIME() WHERE plan_id = :id");
        return $stmt->execute(['id' => $planId]);
    }

    /* ========================================================================= */
    /* ========================= PLAN ENTITLEMENTS ============================= */
    /* ========================================================================= */

    /**
     * Get all entitlements for a specific plan.
     */
    public function getPlanEntitlements(int $planId): array
    {
        $stmt = $this->db->prepare("SELECT entitlement_type, quantity, valid_days FROM plan_entitlements WHERE plan_id = :id");
        $stmt->execute(['id' => $planId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as &$row) {
            $row['quantity'] = (int)$row['quantity'];
            $row['valid_days'] = (int)$row['valid_days'];
        }

        return $rows;
    }

    /**
     * Replace/Set entitlements for a plan.
     */
    public function setPlanEntitlements(int $planId, array $entitlements): void
    {
        // Clear existing
        $stmtDel = $this->db->prepare("DELETE FROM plan_entitlements WHERE plan_id = :id");
        $stmtDel->execute(['id' => $planId]);

        if (empty($entitlements)) {
            return;
        }

        $stmtIns = $this->db->prepare("
            INSERT INTO plan_entitlements (plan_id, entitlement_type, quantity, valid_days)
            VALUES (:plan_id, :entitlement_type, :quantity, :valid_days)
        ");

        foreach ($entitlements as $item) {
            if (empty($item['entitlement_type'])) continue;
            $stmtIns->execute([
                'plan_id'          => $planId,
                'entitlement_type' => strtoupper(trim($item['entitlement_type'])),
                'quantity'         => isset($item['quantity']) ? (int)$item['quantity'] : 1,
                'valid_days'       => isset($item['valid_days']) ? (int)$item['valid_days'] : 30
            ]);
        }
    }

    /**
     * Delete a specific entitlement type from a plan.
     */
    public function deleteSingleEntitlement(int $planId, string $entitlementType): bool
    {
        $stmt = $this->db->prepare("DELETE FROM plan_entitlements WHERE plan_id = :id AND entitlement_type = :type");
        return $stmt->execute([
            'id'   => $planId,
            'type' => strtoupper(trim($entitlementType))
        ]);
    }

    /* ========================================================================= */
    /* ========================= SUBSCRIPTIONS ================================= */
    /* ========================================================================= */

    /**
     * Fetch subscriptions matching optional filters, with member details and wallet credits.
     */
    public function getAllSubscriptions(array $filters = []): array
    {
        $sql = "
            SELECT 
                s.*,
                u.name AS member_name,
                u.email AS member_email,
                u.phone AS member_phone,
                mp.plan_name,
                mp.plan_type,
                mp.price AS plan_price,
                mp.duration_months
            FROM subscriptions s
            JOIN users u ON u.user_id = s.user_id
            JOIN membership_plans mp ON mp.plan_id = s.plan_id
            WHERE 1=1
        ";
        $params = [];

        if (isset($filters['status']) && $filters['status'] !== '') {
            $sql .= " AND s.status = :status";
            $params['status'] = (int)$filters['status'];
        }

        if (!empty($filters['user_id'])) {
            $sql .= " AND s.user_id = :user_id";
            $params['user_id'] = (int)$filters['user_id'];
        }

        if (!empty($filters['plan_id'])) {
            $sql .= " AND s.plan_id = :plan_id";
            $params['plan_id'] = (int)$filters['plan_id'];
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND s.gym_id = :gym_id";
            $params['gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND s.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        $sql .= " ORDER BY s.subscription_id DESC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $subs = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($subs as &$sub) {
            $sub['subscription_id'] = (int)$sub['subscription_id'];
            $sub['gym_id'] = (int)$sub['gym_id'];
            $sub['branch_id'] = (int)$sub['branch_id'];
            $sub['user_id'] = (int)$sub['user_id'];
            $sub['plan_id'] = (int)$sub['plan_id'];
            $sub['plan_price'] = (float)$sub['plan_price'];
            $sub['duration_months'] = (int)$sub['duration_months'];
            $sub['status'] = (int)$sub['status'];
            $sub['wallet_credits'] = $this->getSubscriptionWalletCredits($sub['subscription_id']);
            $sub['invoices'] = $this->getSubscriptionInvoices($sub['user_id'], $sub['plan_id'], $sub['start_date']);
        }

        return $subs;
    }

    /**
     * Fetch single subscription details by ID.
     */
    public function getSubscriptionById(int $subId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT 
                s.*,
                u.name AS member_name,
                u.email AS member_email,
                u.phone AS member_phone,
                mp.plan_name,
                mp.plan_type,
                mp.price AS plan_price,
                mp.duration_months
            FROM subscriptions s
            JOIN users u ON u.user_id = s.user_id
            JOIN membership_plans mp ON mp.plan_id = s.plan_id
            WHERE s.subscription_id = :id LIMIT 1
        ");
        $stmt->execute(['id' => $subId]);
        $sub = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$sub) {
            return null;
        }

        $sub['subscription_id'] = (int)$sub['subscription_id'];
        $sub['gym_id'] = (int)$sub['gym_id'];
        $sub['branch_id'] = (int)$sub['branch_id'];
        $sub['user_id'] = (int)$sub['user_id'];
        $sub['plan_id'] = (int)$sub['plan_id'];
        $sub['plan_price'] = (float)$sub['plan_price'];
        $sub['duration_months'] = (int)$sub['duration_months'];
        $sub['status'] = (int)$sub['status'];
        $sub['wallet_credits'] = $this->getSubscriptionWalletCredits($subId);
        $sub['invoices'] = $this->getSubscriptionInvoices($sub['user_id'], $sub['plan_id'], $sub['start_date']);

        return $sub;
    }

    /**
     * Get active subscription for a member user ID.
     */
    public function getMemberActiveSubscription(int $userId): ?array
    {
        $subs = $this->getAllSubscriptions(['user_id' => $userId, 'status' => 1]);
        return !empty($subs) ? $subs[0] : null;
    }

    /**
     * Create a new subscription record.
     */
    public function createSubscription(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO subscriptions (
                gym_id, branch_id, user_id, plan_id, start_date, end_date, status, createdDate, createdTime
            ) VALUES (
                :gym_id, :branch_id, :user_id, :plan_id, :start_date, :end_date, :status, CURDATE(), CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id'     => $data['gym_id'],
            'branch_id'  => $data['branch_id'],
            'user_id'    => $data['user_id'],
            'plan_id'    => $data['plan_id'],
            'start_date' => $data['start_date'],
            'end_date'   => $data['end_date'],
            'status'     => isset($data['status']) ? (int)$data['status'] : 1
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Update subscription details.
     */
    public function updateSubscription(int $subId, array $data): bool
    {
        $fields = [];
        $params = ['sub_id' => $subId];

        if (isset($data['start_date'])) {
            $fields[] = "start_date = :start_date";
            $params['start_date'] = $data['start_date'];
        }
        if (isset($data['end_date'])) {
            $fields[] = "end_date = :end_date";
            $params['end_date'] = $data['end_date'];
        }
        if (isset($data['status'])) {
            $fields[] = "status = :status";
            $params['status'] = (int)$data['status'];
        }

        if (empty($fields)) {
            return true;
        }

        $fields[] = "updatedDate = CURDATE()";
        $fields[] = "updatedTime = CURTIME()";

        $sql = "UPDATE subscriptions SET " . implode(', ', $fields) . " WHERE subscription_id = :sub_id";
        $stmt = $this->db->prepare($sql);
        $success = $stmt->execute($params);

        // If end_date or status changed, update wallet credits expiration/status
        if ($success) {
            if (isset($data['end_date'])) {
                $stmtCred = $this->db->prepare("UPDATE client_wallet_credits SET expiration_date = :end_date WHERE subscription_id = :sub_id");
                $stmtCred->execute(['end_date' => $data['end_date'], 'sub_id' => $subId]);
            }
            if (isset($data['status'])) {
                $stmtCredStatus = $this->db->prepare("UPDATE client_wallet_credits SET status = :status WHERE subscription_id = :sub_id");
                $stmtCredStatus->execute(['status' => (int)$data['status'], 'sub_id' => $subId]);
            }
        }

        return $success;
    }

    /**
     * Cancel/Deactivate a subscription and its associated credits.
     */
    public function cancelSubscription(int $subId): bool
    {
        $stmt = $this->db->prepare("UPDATE subscriptions SET status = 0, updatedDate = CURDATE(), updatedTime = CURTIME() WHERE subscription_id = :id");
        $success = $stmt->execute(['id' => $subId]);

        if ($success) {
            $stmtCred = $this->db->prepare("UPDATE client_wallet_credits SET status = 0 WHERE subscription_id = :sub_id");
            $stmtCred->execute(['sub_id' => $subId]);
        }

        return $success;
    }

    /* ========================================================================= */
    /* ========================= WALLET CREDITS PROVISIONING =================== */
    /* ========================================================================= */

    /**
     * Get wallet credits associated with a subscription ID.
     */
    public function getSubscriptionWalletCredits(int $subId): array
    {
        $stmt = $this->db->prepare("SELECT * FROM client_wallet_credits WHERE subscription_id = :sub_id");
        $stmt->execute(['sub_id' => $subId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as &$row) {
            $row['credit_id'] = (int)$row['credit_id'];
            $row['subscription_id'] = (int)$row['subscription_id'];
            $row['user_id'] = (int)$row['user_id'];
            $row['is_unlimited'] = (int)$row['is_unlimited'];
            $row['original_quantity'] = (int)$row['original_quantity'];
            $row['remaining_quantity'] = (int)$row['remaining_quantity'];
            $row['status'] = (int)$row['status'];
        }

        return $rows;
    }

    /**
     * Fetch invoices matching the subscription user, plan, and purchase date.
     */
    public function getSubscriptionInvoices(int $userId, int $planId, string $startDate): array
    {
        $stmt = $this->db->prepare("
            SELECT i.invoice_id, i.invoice_number, i.final_amount, i.issued_at, i.status
            FROM invoices i
            JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
            WHERE i.user_id = :user_id
              AND ii.reference_id = :plan_id
              AND ii.item_type IN ('SUBSCRIPTION', 'PT_PACKAGE')
            ORDER BY ABS(DATEDIFF(i.issued_at, :start_date)) ASC, i.invoice_id DESC
        ");
        $stmt->execute([
            'user_id'    => $userId,
            'plan_id'    => $planId,
            'start_date' => $startDate
        ]);
        $invoices = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($invoices as &$inv) {
            $inv['invoice_id'] = (int)$inv['invoice_id'];
            $inv['final_amount'] = (float)$inv['final_amount'];
        }
        return $invoices;
    }

    /**
     * Provision wallet credits based on plan entitlements when a subscription is created.
     */
    public function provisionWalletCredits(int $subId, int $userId, int $planId, string $startDate, string $endDate): void
    {
        $entitlements = $this->getPlanEntitlements($planId);

        if (empty($entitlements)) {
            return;
        }

        $stmtIns = $this->db->prepare("
            INSERT INTO client_wallet_credits (
                subscription_id, user_id, entitlement_type, is_unlimited,
                original_quantity, remaining_quantity, expiration_date, status, created_at
            ) VALUES (
                :sub_id, :user_id, :entitlement_type, :is_unlimited,
                :original_quantity, :remaining_quantity, :expiration_date, 1, NOW()
            )
        ");

        foreach ($entitlements as $item) {
            $qty = (int)$item['quantity'];
            $isUnlimited = ($qty < 0 || $qty >= 9999) ? 1 : 0;

            // Calculate entitlement expiration date if valid_days is specified, or default to sub end date
            $expDate = $endDate;
            if (!empty($item['valid_days']) && (int)$item['valid_days'] > 0) {
                $calcExp = date('Y-m-d', strtotime($startDate . " + " . (int)$item['valid_days'] . " days"));
                if ($calcExp < $endDate) {
                    $expDate = $calcExp;
                }
            }

            $stmtIns->execute([
                'sub_id'             => $subId,
                'user_id'            => $userId,
                'entitlement_type'   => $item['entitlement_type'],
                'is_unlimited'       => $isUnlimited,
                'original_quantity'  => $qty,
                'remaining_quantity' => $qty,
                'expiration_date'    => $expDate
            ]);
        }
    }

    /**
     * Resolve gym_id and branch_id for a user ID.
     */
    public function getUserGymBranch(int $userId): ?array
    {
        $stmt = $this->db->prepare("SELECT gym_id, branch_id FROM users WHERE user_id = :id LIMIT 1");
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row && $row['gym_id'] && $row['branch_id']) {
            return [
                'gym_id'    => (int)$row['gym_id'],
                'branch_id' => (int)$row['branch_id']
            ];
        }
        return null;
    }

    /**
     * Check if user exists.
     */
    public function userExists(int $userId): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM users WHERE user_id = :id");
        $stmt->execute(['id' => $userId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    /**
     * Transaction Helpers
     */
    public function beginTransaction(): void
    {
        if (!$this->db->inTransaction()) {
            $this->db->beginTransaction();
        }
    }

    public function commit(): void
    {
        if ($this->db->inTransaction()) {
            $this->db->commit();
        }
    }

    public function rollBack(): void
    {
        if ($this->db->inTransaction()) {
            $this->db->rollBack();
        }
    }
}
