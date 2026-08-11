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
            $sub['invoice'] = !empty($sub['invoices']) ? $sub['invoices'][0] : null;
        }

        return $subs;
    }

    /**
     * Get aggregate statistics for subscriptions management.
     */
    public function getSubscriptionStats(array $filters = []): array
    {
        $whereSql = " WHERE 1=1";
        $params = [];

        if (!empty($filters['gym_id'])) {
            $whereSql .= " AND s.gym_id = :gym_id";
            $params['gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $whereSql .= " AND s.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        // 1. Overall counts & status breakdown
        $stmt = $this->db->prepare("
            SELECT 
                COUNT(*) AS total_subscriptions,
                SUM(CASE WHEN s.status = 1 AND s.end_date >= CURDATE() THEN 1 ELSE 0 END) AS active_subscriptions,
                SUM(CASE WHEN s.status = 1 AND s.end_date >= CURDATE() AND s.end_date <= DATE_ADD(CURDATE(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) AS expiring_soon_subscriptions,
                SUM(CASE WHEN s.status = 0 OR s.end_date < CURDATE() THEN 1 ELSE 0 END) AS expired_subscriptions,
                SUM(CASE WHEN s.status = 2 THEN 1 ELSE 0 END) AS frozen_subscriptions,
                SUM(CASE WHEN s.createdDate >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN 1 ELSE 0 END) AS new_subscriptions_this_month,
                COALESCE(SUM(mp.price), 0.0) AS total_subscription_revenue
            FROM subscriptions s
            JOIN membership_plans mp ON mp.plan_id = s.plan_id
            {$whereSql}
        ");
        $stmt->execute($params);
        $totals = $stmt->fetch(PDO::FETCH_ASSOC);

        // 2. Breakdown per plan
        $stmtPlan = $this->db->prepare("
            SELECT 
                mp.plan_id,
                mp.plan_name,
                mp.plan_type,
                mp.price AS plan_price,
                COUNT(s.subscription_id) AS total_count,
                SUM(CASE WHEN s.status = 1 AND s.end_date >= CURDATE() THEN 1 ELSE 0 END) AS active_count,
                COALESCE(SUM(mp.price), 0.0) AS total_revenue
            FROM membership_plans mp
            LEFT JOIN subscriptions s ON s.plan_id = mp.plan_id
            WHERE mp.status = 1
            " . (!empty($filters['gym_id']) ? " AND mp.gym_id = " . (int)$filters['gym_id'] : "") . "
            " . (!empty($filters['branch_id']) ? " AND mp.branch_id = " . (int)$filters['branch_id'] : "") . "
            GROUP BY mp.plan_id, mp.plan_name, mp.plan_type, mp.price
            ORDER BY total_count DESC, mp.plan_id ASC
        ");
        $stmtPlan->execute();
        $planBreakdown = $stmtPlan->fetchAll(PDO::FETCH_ASSOC);

        foreach ($planBreakdown as &$p) {
            $p['plan_id'] = (int)$p['plan_id'];
            $p['plan_price'] = (float)$p['plan_price'];
            $p['total_count'] = (int)$p['total_count'];
            $p['active_count'] = (int)$p['active_count'];
            $p['total_revenue'] = (float)$p['total_revenue'];
        }

        return [
            'total_subscriptions'         => (int)($totals['total_subscriptions'] ?? 0),
            'active_subscriptions'        => (int)($totals['active_subscriptions'] ?? 0),
            'expiring_soon_subscriptions' => (int)($totals['expiring_soon_subscriptions'] ?? 0),
            'expired_subscriptions'       => (int)($totals['expired_subscriptions'] ?? 0),
            'frozen_subscriptions'        => (int)($totals['frozen_subscriptions'] ?? 0),
            'new_subscriptions_this_month'=> (int)($totals['new_subscriptions_this_month'] ?? 0),
            'total_subscription_revenue'  => (float)($totals['total_subscription_revenue'] ?? 0.0),
            'total_revenue'               => (float)($totals['total_subscription_revenue'] ?? 0.0),
            'plan_breakdown'              => $planBreakdown
        ];
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
     * Get all active subscriptions for a member user ID with their plan types.
     */
    public function getMemberActiveSubscriptions(int $userId): array
    {
        return $this->getAllSubscriptions(['user_id' => $userId, 'status' => 1]);
    }

    /**
     * Get primary active subscription for a member user ID.
     */
    public function getMemberActiveSubscription(int $userId): ?array
    {
        $subs = $this->getMemberActiveSubscriptions($userId);
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
            SELECT 
                i.invoice_id, 
                i.invoice_number, 
                i.total_amount AS subtotal,
                i.tax_amount,
                i.tax_breakdown,
                i.final_amount, 
                i.issued_at, 
                i.status
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
            $invId = (int)$inv['invoice_id'];
            $inv['invoice_id'] = $invId;
            $inv['subtotal'] = (float)$inv['subtotal'];
            $inv['tax_amount'] = (float)$inv['tax_amount'];
            $inv['final_amount'] = (float)$inv['final_amount'];

            // Parse tax breakdown
            if (!empty($inv['tax_breakdown'])) {
                $decoded = json_decode($inv['tax_breakdown'], true);
                $inv['tax_breakdown'] = is_array($decoded) ? $decoded : $inv['tax_breakdown'];
            } else {
                $inv['tax_breakdown'] = [];
            }

            // Fetch payment transactions
            $stmtPay = $this->db->prepare("
                SELECT payment_id AS transaction_id, payment_id, payment_mode, payment_status, transaction_ref, amount, COALESCE(updated_at, createdDate) AS created_at 
                FROM payment_transactions 
                WHERE invoice_id = :id
            ");
            $stmtPay->execute(['id' => $invId]);
            $payments = $stmtPay->fetchAll(PDO::FETCH_ASSOC);
            foreach ($payments as &$p) {
                $p['transaction_id'] = (int)$p['transaction_id'];
                $p['payment_id'] = (int)$p['payment_id'];
                $p['amount'] = (float)$p['amount'];
            }
            $inv['payments'] = $payments;
            $inv['payment_mode'] = !empty($payments) ? $payments[0]['payment_mode'] : 'Cash';
            $inv['transaction_ref'] = !empty($payments) ? $payments[0]['transaction_ref'] : null;

            // Fetch items
            $stmtItems = $this->db->prepare("
                SELECT item_id, item_type, reference_id, item_name, quantity, unit_price, tax_percentage, tax_amount, total_price 
                FROM invoice_items 
                WHERE invoice_id = :id
            ");
            $stmtItems->execute(['id' => $invId]);
            $items = $stmtItems->fetchAll(PDO::FETCH_ASSOC);
            foreach ($items as &$it) {
                $it['item_id'] = (int)$it['item_id'];
                $it['reference_id'] = (int)$it['reference_id'];
                $it['quantity'] = (int)$it['quantity'];
                $it['unit_price'] = (float)$it['unit_price'];
                $it['tax_percentage'] = (float)$it['tax_percentage'];
                $it['tax_amount'] = (float)$it['tax_amount'];
                $it['total_price'] = (float)$it['total_price'];
            }
            $inv['items'] = $items;
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

    /**
     * Create invoice record.
     */
    public function createInvoice(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO invoices (
                user_id,
                invoice_number,
                total_amount,
                tax_amount,
                tax_breakdown,
                final_amount,
                status,
                issued_at,
                due_date
            ) VALUES (
                :user_id,
                :invoice_number,
                :total_amount,
                :tax_amount,
                :tax_breakdown,
                :final_amount,
                :status,
                NOW(),
                CURDATE()
            )
        ");

        $stmt->execute([
            'user_id'        => (int)($data['user_id'] ?? 0),
            'invoice_number' => $data['invoice_number'],
            'total_amount'   => (float)$data['total_amount'],
            'tax_amount'     => (float)($data['tax_amount'] ?? 0.0),
            'tax_breakdown'  => isset($data['tax_breakdown']) ? (is_array($data['tax_breakdown']) ? json_encode($data['tax_breakdown']) : $data['tax_breakdown']) : null,
            'final_amount'   => (float)$data['final_amount'],
            'status'         => $data['status'] ?? 'UNPAID'
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create invoice item record.
     */
    public function createInvoiceItem(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO invoice_items (
                invoice_id,
                item_type,
                reference_id,
                item_name,
                quantity,
                unit_price,
                tax_percentage,
                tax_amount,
                tax_breakdown,
                total_price
            ) VALUES (
                :invoice_id,
                :item_type,
                :reference_id,
                :item_name,
                :quantity,
                :unit_price,
                :tax_percentage,
                :tax_amount,
                :tax_breakdown,
                :total_price
            )
        ");

        $stmt->execute([
            'invoice_id'     => (int)$data['invoice_id'],
            'item_type'      => $data['item_type'],
            'reference_id'   => (int)$data['reference_id'],
            'item_name'      => trim($data['item_name']),
            'quantity'       => (int)($data['quantity'] ?? 1),
            'unit_price'     => (float)$data['unit_price'],
            'tax_percentage' => (float)($data['tax_percentage'] ?? 0.0),
            'tax_amount'     => (float)($data['tax_amount'] ?? 0.0),
            'tax_breakdown'  => isset($data['tax_breakdown']) ? (is_array($data['tax_breakdown']) ? json_encode($data['tax_breakdown']) : $data['tax_breakdown']) : null,
            'total_price'    => (float)$data['total_price']
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create payment transaction record.
     */
    public function createPaymentTransaction(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO payment_transactions (
                gym_id,
                branch_id,
                invoice_id,
                paid_by_user_id,
                amount,
                payment_mode,
                payment_status,
                transaction_ref,
                payment_date,
                status,
                createdDate,
                createdTime
            ) VALUES (
                :gym_id,
                :branch_id,
                :invoice_id,
                :paid_by_user_id,
                :amount,
                :payment_mode,
                :payment_status,
                :transaction_ref,
                CURDATE(),
                1,
                CURDATE(),
                CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id'          => (int)$data['gym_id'],
            'branch_id'       => (int)$data['branch_id'],
            'invoice_id'      => (int)$data['invoice_id'],
            'paid_by_user_id' => isset($data['paid_by_user_id']) && (int)$data['paid_by_user_id'] > 0 ? (int)$data['paid_by_user_id'] : null,
            'amount'          => (float)$data['amount'],
            'payment_mode'    => trim($data['payment_mode']),
            'payment_status'  => $data['payment_status'] ?? 'PENDING',
            'transaction_ref' => isset($data['transaction_ref']) ? trim($data['transaction_ref']) : null
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create financial ledger entry.
     */
    public function createFinancialLedgerEntry(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO financial_ledger (
                gym_id,
                branch_id,
                transaction_type,
                category,
                amount,
                reference_table,
                reference_id,
                payment_method,
                created_at
            ) VALUES (
                :gym_id,
                :branch_id,
                :transaction_type,
                :category,
                :amount,
                :reference_table,
                :reference_id,
                :payment_method,
                NOW()
            )
        ");

        $stmt->execute([
            'gym_id'           => (int)$data['gym_id'],
            'branch_id'        => (int)$data['branch_id'],
            'transaction_type' => strtoupper(trim($data['transaction_type'])),
            'category'         => strtoupper(trim($data['category'])),
            'amount'           => (float)$data['amount'],
            'reference_table'  => trim($data['reference_table']),
            'reference_id'     => (int)$data['reference_id'],
            'payment_method'   => strtoupper(trim($data['payment_method']))
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Get tax rates for gym.
     */
    public function getTaxRatesForGym(int $gymId, string $appliesTo = 'SUBSCRIPTIONS'): array
    {
        $stmt = $this->db->prepare("
            SELECT tax_name, percentage 
            FROM tax_rates 
            WHERE gym_id = :gym_id 
              AND applies_to IN (:applies_to, 'ALL') 
              AND status = 1
        ");
        $stmt->execute([
            'gym_id'     => $gymId,
            'applies_to' => $appliesTo
        ]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Complete admin subscription purchase workflow including plan validation,
     * reverse tax calculation, invoice creation, invoice items, payment transactions,
     * financial ledger entry, subscription record creation, and wallet credits provisioning.
     */
    public function purchaseSubscriptionWithInvoice(array $data): array
    {
        $userId = (int)($data['user_id'] ?? 0);
        $planId = (int)($data['plan_id'] ?? 0);

        if (!$userId || !$this->userExists($userId)) {
            throw new Exception("User with ID $userId does not exist", 404);
        }

        $plan = $this->getPlanById($planId);
        if (!$plan || (int)$plan['status'] !== 1) {
            throw new Exception("Invalid or inactive membership plan", 404);
        }

        // Gatekeeper checks:
        // 1. Prevent duplicate active Base Memberships
        // 2. PT_UPGRADE and ADD_ON require an active Base Membership
        $planType = strtoupper(trim($plan['plan_type'] ?? 'BASE_MEMBERSHIP'));
        if (in_array($planType, ['BASE_MEMBERSHIP', 'MEMBERSHIP'])) {
            $activeBase = $this->getUserActiveBaseMembership($userId);
            if ($activeBase) {
                throw new Exception("Action Blocked: Member already has an active Base Membership (Subscription #" . $activeBase['subscription_id'] . ", Plan #" . $activeBase['plan_id'] . ", valid until " . $activeBase['end_date'] . "). Cannot purchase another Base Membership while current one is active.", 400);
            }
        } elseif (in_array($planType, ['PT_UPGRADE', 'ADD_ON'])) {
            $activeBase = $this->getUserActiveBaseMembership($userId);
            if (!$activeBase) {
                throw new Exception("Action Blocked: Member does not have an active Base Membership required to purchase a " . str_replace('_', ' ', $planType) . " plan", 403);
            }
        }

        $gymBranch = $this->getUserGymBranch($userId);
        $gymId = (int)($data['gym_id'] ?? ($gymBranch ? $gymBranch['gym_id'] : ($plan['gym_id'] ?: 1)));
        $branchId = (int)($data['branch_id'] ?? ($gymBranch ? $gymBranch['branch_id'] : ($plan['branch_id'] ?: 1)));

        // Tax calculation (reverse tax math if price includes tax)
        $taxRates = $this->getTaxRatesForGym($gymId, 'SUBSCRIPTIONS');
        if (empty($taxRates)) {
            $taxRates = [
                ['tax_name' => 'CGST', 'percentage' => 9.00],
                ['tax_name' => 'SGST', 'percentage' => 9.00]
            ];
        }

        $totalTaxRate = 0.0;
        foreach ($taxRates as $tr) {
            $totalTaxRate += (float)$tr['percentage'];
        }

        $inclusivePrice = (float)$plan['price'];
        $basePrice = round($inclusivePrice / (1 + ($totalTaxRate / 100)), 2);
        $totalTaxAmount = round($inclusivePrice - $basePrice, 2);

        $taxBreakdown = [];
        $accumulatedTax = 0.0;
        $countRates = count($taxRates);
        for ($i = 0; $i < $countRates; $i++) {
            $tr = $taxRates[$i];
            $ratePct = (float)$tr['percentage'];
            $rateName = trim($tr['tax_name']);
            
            if ($i === $countRates - 1) {
                $rateAmount = round($totalTaxAmount - $accumulatedTax, 2);
            } else {
                $rateAmount = round($inclusivePrice * ($ratePct / (100 + $totalTaxRate)), 2);
                $accumulatedTax += $rateAmount;
            }
            
            $key = str_replace(['.', '-'], '_', strtoupper($rateName) . '_' . (int)$ratePct);
            $taxBreakdown[$key] = $rateAmount;
        }

        $startDate = !empty($data['start_date']) ? trim($data['start_date']) : date('Y-m-d');
        $durationMonths = (int)($plan['duration_months'] ?: 1);
        $endDate = !empty($data['end_date']) ? trim($data['end_date']) : date('Y-m-d', strtotime($startDate . " + {$durationMonths} months"));

        $this->beginTransaction();

        try {
            // 1. Invoice
            $invoiceNumber = 'INV-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(4)));
            $invoiceId = $this->createInvoice([
                'user_id'        => $userId,
                'invoice_number' => $invoiceNumber,
                'total_amount'   => $basePrice,
                'tax_amount'     => $totalTaxAmount,
                'tax_breakdown'  => $taxBreakdown,
                'final_amount'   => $inclusivePrice,
                'status'         => 'PAID'
            ]);

            // 2. Invoice Item
            $this->createInvoiceItem([
                'invoice_id'     => $invoiceId,
                'item_type'      => 'SUBSCRIPTION',
                'reference_id'   => $planId,
                'item_name'      => $plan['plan_name'],
                'quantity'       => 1,
                'unit_price'     => $basePrice,
                'tax_percentage' => $totalTaxRate,
                'tax_amount'     => $totalTaxAmount,
                'tax_breakdown'  => $taxBreakdown,
                'total_price'    => $inclusivePrice
            ]);

            // 3. Payment Transaction
            $rawPayMethod = strtoupper(trim($data['payment_method'] ?? 'CASH'));
            $payMode = 'Cash';
            if ($rawPayMethod === 'CARD') $payMode = 'Card';
            elseif ($rawPayMethod === 'UPI') $payMode = 'UPI';
            elseif ($rawPayMethod === 'BANK_TRANSFER' || $rawPayMethod === 'ONLINE') $payMode = 'Online';

            $txnRef = !empty($data['transaction_ref']) ? trim($data['transaction_ref']) : 'TXN-' . date('YmdHis') . '-' . rand(100, 999);

            $this->createPaymentTransaction([
                'gym_id'          => $gymId,
                'branch_id'       => $branchId,
                'invoice_id'      => $invoiceId,
                'paid_by_user_id' => $userId,
                'amount'          => $inclusivePrice,
                'payment_mode'    => $payMode,
                'payment_status'  => 'SUCCESS',
                'transaction_ref' => $txnRef
            ]);

            // 4. Financial Ledger
            $flMethod = 'CASH';
            if ($rawPayMethod === 'CARD') $flMethod = 'CARD';
            elseif ($rawPayMethod === 'UPI') $flMethod = 'UPI';
            elseif ($rawPayMethod === 'BANK_TRANSFER' || $rawPayMethod === 'ONLINE') $flMethod = 'BANK_TRANSFER';

            $this->createFinancialLedgerEntry([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => 'INFLOW',
                'category'         => 'REVENUE',
                'amount'           => $inclusivePrice,
                'reference_table'  => 'invoices',
                'reference_id'     => $invoiceId,
                'payment_method'   => $flMethod
            ]);

            // 5. Subscription
            $subId = $this->createSubscription([
                'gym_id'     => $gymId,
                'branch_id'  => $branchId,
                'user_id'    => $userId,
                'plan_id'    => $planId,
                'start_date' => $startDate,
                'end_date'   => $endDate,
                'status'     => 1
            ]);

            // 6. Wallet credits provisioning
            $this->provisionWalletCredits($subId, $userId, $planId, $startDate, $endDate);

            $this->commit();

            return [
                'subscription_id' => $subId,
                'invoice_id'      => $invoiceId,
                'invoice_number'  => $invoiceNumber,
                'user_id'         => $userId,
                'plan_id'         => $planId,
                'plan_name'       => $plan['plan_name'],
                'start_date'      => $startDate,
                'end_date'        => $endDate,
                'amount_paid'     => $inclusivePrice,
                'payment_method'  => $rawPayMethod,
                'transaction_ref' => $txnRef
            ];

        } catch (Exception $e) {
            $this->rollBack();
            throw $e;
        }
    }

    /**
     * Get user active base membership subscription if present.
     */
    public function getUserActiveBaseMembership(int $userId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT s.* 
            FROM subscriptions s
            JOIN membership_plans mp ON s.plan_id = mp.plan_id
            WHERE s.user_id = :user_id 
              AND s.status = 1 
              AND mp.plan_type IN ('BASE_MEMBERSHIP', 'MEMBERSHIP')
              AND s.end_date >= CURDATE()
            LIMIT 1
        ");
        $stmt->execute(['user_id' => $userId]);
        $sub = $stmt->fetch(PDO::FETCH_ASSOC);
        return $sub ?: null;
    }
}
