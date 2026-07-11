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
}
