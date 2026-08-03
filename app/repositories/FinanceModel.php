<?php

require_once __DIR__ . '/../config/database.php';

class FinanceModel
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

    /**
     * Fetch complete invoice bill details.
     */
    public function getInvoiceDetails(int $invoiceId): ?array
    {
        // 1. Fetch parent invoice
        $stmt = $this->db->prepare("SELECT * FROM invoices WHERE invoice_id = :id LIMIT 1");
        $stmt->execute(['id' => $invoiceId]);
        $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$invoice) {
            return null;
        }

        // 2. Fetch invoice line items
        $stmtItems = $this->db->prepare("SELECT * FROM invoice_items WHERE invoice_id = :id");
        $stmtItems->execute(['id' => $invoiceId]);
        $items = $stmtItems->fetchAll(PDO::FETCH_ASSOC);

        // 3. Fetch payment transactions
        $stmtPayments = $this->db->prepare("SELECT * FROM payment_transactions WHERE invoice_id = :id");
        $stmtPayments->execute(['id' => $invoiceId]);
        $payments = $stmtPayments->fetchAll(PDO::FETCH_ASSOC);

        return [
            'invoice'  => $invoice,
            'items'    => $items,
            'payments' => $payments
        ];
    }

    /**
     * Find active promo code by code string.
     */
    public function getPromoCode(string $code): ?array
    {
        $stmt = $this->db->prepare("
            SELECT * FROM promo_codes 
            WHERE code = :code 
              AND status = 1 
              AND valid_from <= NOW() 
              AND valid_until >= NOW() 
            LIMIT 1
        ");
        $stmt->execute(['code' => trim($code)]);
        $promo = $stmt->fetch(PDO::FETCH_ASSOC);
        return $promo ?: null;
    }

    /**
     * Increment the usage counter of a promo code.
     */
    public function incrementPromoUses(int $promoId): bool
    {
        $stmt = $this->db->prepare("UPDATE promo_codes SET times_used = times_used + 1 WHERE promo_id = :id");
        return $stmt->execute(['id' => $promoId]);
    }

    /**
     * Execute full refund and cancellation logic.
     */
    public function refundInvoiceTransaction(int $invoiceId, string $reason): bool
    {
        // Fetch invoice details first to get reference tables/keys
        $details = $this->getInvoiceDetails($invoiceId);
        if (!$details) {
            throw new Exception("Invoice not found", 404);
        }

        $invoice = $details['invoice'];
        $items = $details['items'];
        $payments = $details['payments'];

        // Get gym_id and branch_id context from the payment logs
        $gymId = 1;
        $branchId = 1;
        $payMethod = 'BANK_TRANSFER';
        if (!empty($payments)) {
            $gymId = (int)$payments[0]['gym_id'];
            $branchId = (int)$payments[0]['branch_id'];
            $payMethod = strtoupper($payments[0]['payment_mode']);
        }

        // 1. Update invoice status to CANCELLED
        $stmtInv = $this->db->prepare("UPDATE invoices SET status = 'CANCELLED' WHERE invoice_id = :id");
        $stmtInv->execute(['id' => $invoiceId]);

        // 2. Update payment_transactions status to REFUNDED
        $stmtPt = $this->db->prepare("UPDATE payment_transactions SET payment_status = 'REFUNDED' WHERE invoice_id = :id");
        $stmtPt->execute(['id' => $invoiceId]);

        // 3. Write OUTFLOW row in financial_ledger
        $stmtFl = $this->db->prepare("
            INSERT INTO financial_ledger (
                gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, created_at
            ) VALUES (
                :gym_id, :branch_id, 'OUTFLOW', 'REFUND', :amount, 'invoices', :reference_id, :payment_method, NOW()
            )
        ");
        $stmtFl->execute([
            'gym_id'          => $gymId,
            'branch_id'       => $branchId,
            'amount'          => (float)$invoice['final_amount'],
            'reference_id'    => $invoiceId,
            'payment_method'  => $payMethod
        ]);

        // 4. Void unpaid trainer commissions
        $stmtComm = $this->db->prepare("UPDATE trainer_commissions SET status = 'VOIDED' WHERE invoice_id = :id AND status = 'UNPAID'");
        $stmtComm->execute(['id' => $invoiceId]);

        // 5. Deactivate associated subscriptions and revoke credits
        foreach ($items as $item) {
            if (in_array($item['item_type'], ['SUBSCRIPTION', 'PT_PACKAGE'])) {
                // Find sub ID linking this user and plan
                $stmtFindSub = $this->db->prepare("
                    SELECT subscription_id 
                    FROM subscriptions 
                    WHERE user_id = :user_id 
                      AND plan_id = :plan_id 
                      AND status = 1 
                    ORDER BY subscription_id DESC 
                    LIMIT 1
                ");
                $stmtFindSub->execute([
                    'user_id' => (int)$invoice['user_id'],
                    'plan_id' => (int)$item['reference_id']
                ]);
                $subId = $stmtFindSub->fetchColumn();

                if ($subId) {
                    // Deactivate subscription
                    $stmtDeactSub = $this->db->prepare("UPDATE subscriptions SET status = 0 WHERE subscription_id = :sub_id");
                    $stmtDeactSub->execute(['sub_id' => (int)$subId]);

                    // Revoke client wallet credits
                    $stmtDeactCredits = $this->db->prepare("UPDATE client_wallet_credits SET status = 0 WHERE subscription_id = :sub_id");
                    $stmtDeactCredits->execute(['sub_id' => (int)$subId]);
                }
            }
        }

        return true;
    }

    /**
     * Fetch all product buy records for a member user with invoices.
     */
    public function getMemberProductPurchases(int $userId): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                ii.item_id AS invoice_item_id,
                ii.invoice_id,
                ii.item_name,
                ii.quantity,
                ii.unit_price,
                ii.tax_percentage,
                ii.tax_amount,
                ii.total_price,
                i.invoice_number,
                i.total_amount AS invoice_subtotal,
                i.tax_amount AS invoice_tax,
                i.tax_breakdown AS invoice_tax_breakdown,
                i.final_amount AS invoice_total,
                i.status AS invoice_status,
                i.issued_at AS invoice_date
            FROM invoice_items ii
            JOIN invoices i ON i.invoice_id = ii.invoice_id
            WHERE i.user_id = :user_id 
              AND ii.item_type = 'PRODUCT'
            ORDER BY i.invoice_id DESC, ii.item_id DESC
        ");
        $stmt->execute(['user_id' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as &$row) {
            $row['invoice_item_id'] = (int)$row['invoice_item_id'];
            $row['invoice_id'] = (int)$row['invoice_id'];
            $row['quantity'] = (int)$row['quantity'];
            $row['unit_price'] = (float)$row['unit_price'];
            $row['tax_percentage'] = (float)$row['tax_percentage'];
            $row['tax_amount'] = (float)$row['tax_amount'];
            $row['total_price'] = (float)$row['total_price'];
            $row['invoice_subtotal'] = (float)$row['invoice_subtotal'];
            $row['invoice_tax'] = (float)$row['invoice_tax'];
            $row['invoice_total'] = (float)$row['invoice_total'];

            // Parse tax breakdown
            $taxBreakdown = [];
            if (!empty($row['invoice_tax_breakdown'])) {
                $decoded = json_decode($row['invoice_tax_breakdown'], true);
                $taxBreakdown = is_array($decoded) ? $decoded : $row['invoice_tax_breakdown'];
            }

            // Fetch payment transaction info
            $stmtPay = $this->db->prepare("
                SELECT payment_id AS transaction_id, payment_id, payment_mode, payment_status, transaction_ref, amount, COALESCE(updated_at, createdDate) AS created_at 
                FROM payment_transactions 
                WHERE invoice_id = :id
            ");
            $stmtPay->execute(['id' => $row['invoice_id']]);
            $payments = $stmtPay->fetchAll(PDO::FETCH_ASSOC);
            foreach ($payments as &$p) {
                $p['transaction_id'] = (int)$p['transaction_id'];
                $p['payment_id'] = (int)$p['payment_id'];
                $p['amount'] = (float)$p['amount'];
            }

            $paymentMode = !empty($payments) ? $payments[0]['payment_mode'] : 'Cash';
            $transactionRef = !empty($payments) ? $payments[0]['transaction_ref'] : null;

            $row['payment_mode'] = $paymentMode;
            $row['transaction_ref'] = $transactionRef;

            // Attach nested complete invoice object
            $row['invoice'] = [
                'invoice_id'      => $row['invoice_id'],
                'invoice_number'  => $row['invoice_number'],
                'subtotal'        => $row['invoice_subtotal'],
                'tax_amount'      => $row['invoice_tax'],
                'tax_breakdown'   => $taxBreakdown,
                'final_amount'    => $row['invoice_total'],
                'status'          => $row['invoice_status'],
                'issued_at'       => $row['invoice_date'],
                'payment_mode'    => $paymentMode,
                'transaction_ref' => $transactionRef,
                'payments'        => $payments
            ];

            unset($row['invoice_tax_breakdown']);
        }
        return $rows;
    }

    /**
     * Fetch daily paid revenues grouped by item type for a gym branch in a date range.
     */
    public function getRevenueBetweenDates(int $gymId, int $branchId, string $startDate, string $endDate): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                DATE(i.issued_at) as invoice_date, 
                ii.item_type,
                SUM(ii.total_price) as total_revenue
            FROM invoices i
            JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
            JOIN users u ON u.user_id = i.user_id
            WHERE i.status = 'PAID'
              AND i.issued_at >= :start_date
              AND i.issued_at <= :end_date
              AND u.gym_id = :gym_id 
              AND u.branch_id = :branch_id
            GROUP BY DATE(i.issued_at), ii.item_type
        ");
        $stmt->execute([
            'gym_id'     => $gymId,
            'branch_id'  => $branchId,
            'start_date' => $startDate,
            'end_date'   => $endDate
        ]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Fetch members and their latest active subscription details for a gym branch.
     */
    public function getMembersStatusData(int $gymId, int $branchId): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                u.user_id,
                u.status AS user_status,
                s.end_date,
                s.status AS sub_status
            FROM users u
            LEFT JOIN subscriptions s ON s.subscription_id = (
                SELECT subscription_id 
                FROM subscriptions 
                WHERE user_id = u.user_id AND status = 1 
                ORDER BY end_date DESC, subscription_id DESC 
                LIMIT 1
            )
            WHERE u.role = 'MEMBER'
              AND u.gym_id = :gym_id
              AND u.branch_id = :branch_id
        ");
        $stmt->execute([
            'gym_id'    => $gymId,
            'branch_id' => $branchId
        ]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
