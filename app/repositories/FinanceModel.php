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
        // 1. Fetch parent invoice with member profile details
        $stmt = $this->db->prepare("
            SELECT i.*, 
                   COALESCE(u.name, CONCAT(COALESCE(u.first_name, ''), ' ', COALESCE(u.last_name, ''))) AS user_name,
                   u.email, 
                   u.phone,
                   COALESCE(mp.registration_number, CONCAT('FG-REG-', LPAD(u.user_id, 4, '0'))) AS reg_no
            FROM invoices i
            LEFT JOIN users u ON i.user_id = u.user_id
            LEFT JOIN member_profiles mp ON mp.user_id = u.user_id
            WHERE i.invoice_id = :id 
            LIMIT 1
        ");
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
     * Check if an invoice is eligible for 24-hour purchase reversal.
     */
    public function getInvoice24HourRevertEligibility(int $invoiceId): array
    {
        $stmt = $this->db->prepare("
            SELECT invoice_id, user_id, status, issued_at, final_amount,
                   TIMESTAMPDIFF(HOUR, issued_at, NOW()) AS hours_elapsed
            FROM invoices
            WHERE invoice_id = :id
        ");
        $stmt->execute(['id' => $invoiceId]);
        $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$invoice) {
            return ['eligible' => false, 'reason' => 'Invoice not found'];
        }
        if (!in_array(strtoupper($invoice['status']), ['PAID', 'COMPLETED'])) {
            return ['eligible' => false, 'reason' => 'Invoice is not in a paid/completed status (Current status: ' . $invoice['status'] . ')'];
        }
        if ((int)$invoice['hours_elapsed'] > 24) {
            return ['eligible' => false, 'reason' => 'Subscription purchase is older than 24 hours (' . $invoice['hours_elapsed'] . ' hours elapsed)'];
        }

        return ['eligible' => true, 'invoice' => $invoice];
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

        // 3. Write OUTFLOW row in financial_ledger safely
        $this->insertLedgerRecord([
            'gym_id'           => $gymId,
            'branch_id'        => $branchId,
            'transaction_type' => 'OUTFLOW',
            'category'         => 'REFUND',
            'amount'           => (float)$invoice['final_amount'],
            'reference_table'  => 'invoices',
            'reference_id'     => $invoiceId,
            'payment_method'   => $payMethod,
            'description'      => "24hr Subscription Reversal - Accidental Purchase (Invoice #{$invoiceId}): {$reason}"
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

    /**
     * Ensure operating_expenses and financial_ledger tables exist.
     */
    public function ensureTablesExist(): void
    {
        try {
            $this->db->exec("
                CREATE TABLE IF NOT EXISTS operating_expenses (
                    opex_id INT AUTO_INCREMENT PRIMARY KEY,
                    gym_id INT DEFAULT 1,
                    branch_id INT DEFAULT 1,
                    title VARCHAR(255) NOT NULL,
                    category_tag VARCHAR(100) DEFAULT 'OPERATING',
                    amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                    payment_method VARCHAR(50) DEFAULT 'CASH',
                    vendor_name VARCHAR(255) NULL,
                    receipt_ref VARCHAR(100) NULL,
                    receipt_url TEXT NULL,
                    expense_date DATE NOT NULL,
                    status VARCHAR(50) DEFAULT 'APPROVED',
                    cancellation_reason TEXT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            ");

            $this->db->exec("
                CREATE TABLE IF NOT EXISTS financial_ledger (
                    ledger_id INT AUTO_INCREMENT PRIMARY KEY,
                    gym_id INT DEFAULT 1,
                    branch_id INT DEFAULT 1,
                    transaction_type VARCHAR(20) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                    reference_table VARCHAR(100) NULL,
                    reference_id INT NULL,
                    payment_method VARCHAR(50) DEFAULT 'CASH',
                    description TEXT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            ");

            // Ensure columns exist and nullability on financial_ledger if table existed prior
            try { $this->db->exec("ALTER TABLE financial_ledger ADD description TEXT NULL"); } catch (\Throwable $t) {}
            try { $this->db->exec("ALTER TABLE financial_ledger MODIFY reference_table VARCHAR(100) NULL"); } catch (\Throwable $t) {}
            try { $this->db->exec("ALTER TABLE financial_ledger MODIFY reference_id INT NULL"); } catch (\Throwable $t) {}
            try { $this->db->exec("ALTER TABLE financial_ledger MODIFY category VARCHAR(50) NOT NULL"); } catch (\Throwable $t) {}
            try { $this->db->exec("ALTER TABLE financial_ledger MODIFY payment_method VARCHAR(50) DEFAULT 'CASH'"); } catch (\Throwable $t) {}

            $hasDesc = $this->hasLedgerDescriptionColumn();

            // Auto-sync unrecorded OpEx entries into financial_ledger
            try {
                $descSelect = $hasDesc ? "CONCAT('OpEx: ', oe.title)," : "";
                $descCol = $hasDesc ? "description," : "";
                $this->db->exec("
                    INSERT INTO financial_ledger (gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, {$descCol} created_at)
                    SELECT 
                        oe.gym_id, 
                        oe.branch_id, 
                        'OUTFLOW', 
                        'OPEX', 
                        oe.amount, 
                        'operating_expenses', 
                        oe.opex_id, 
                        oe.payment_method, 
                        {$descSelect}
                        CONCAT(oe.expense_date, ' 12:00:00')
                    FROM operating_expenses oe
                    WHERE oe.status != 'CANCELLED'
                      AND NOT EXISTS (
                          SELECT 1 FROM financial_ledger fl 
                          WHERE fl.reference_table = 'operating_expenses' 
                            AND fl.reference_id = oe.opex_id
                      )
                ");
            } catch (\Throwable $t) {}

            // Auto-sync unrecorded Payroll Disbursed entries into financial_ledger
            try {
                $descSelect = $hasDesc ? "CONCAT('Payroll Disbursed #', pr.payroll_id)," : "";
                $descCol = $hasDesc ? "description," : "";
                $this->db->exec("
                    INSERT INTO financial_ledger (gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, {$descCol} created_at)
                    SELECT 
                        pr.gym_id, 
                        pr.branch_id, 
                        'OUTFLOW', 
                        'PAYROLL', 
                        pr.net_payable, 
                        'payroll_runs', 
                        pr.payroll_id, 
                        'BANK_TRANSFER', 
                        {$descSelect}
                        COALESCE(pr.paid_at, pr.created_at)
                    FROM payroll_runs pr
                    WHERE pr.status IN ('PAID', 'DISBURSED')
                      AND NOT EXISTS (
                          SELECT 1 FROM financial_ledger fl 
                          WHERE fl.reference_table = 'payroll_runs' 
                            AND fl.reference_id = pr.payroll_id
                      )
                ");
            } catch (\Throwable $t) {}

            // Auto-sync unrecorded COGS (Purchase Orders) entries into financial_ledger
            try {
                $descSelect = $hasDesc ? "CONCAT('COGS/Inventory: ', COALESCE(po.supplier_name, 'Supplier Restock'))," : "";
                $descCol = $hasDesc ? "description," : "";
                $this->db->exec("
                    INSERT INTO financial_ledger (gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, {$descCol} created_at)
                    SELECT 
                        po.gym_id, 
                        po.branch_id, 
                        'OUTFLOW', 
                        'COGS', 
                        po.total_amount, 
                        'purchase_orders', 
                        po.po_id, 
                        'BANK_TRANSFER', 
                        {$descSelect}
                        po.created_at
                    FROM purchase_orders po
                    WHERE po.status IN ('COMPLETED', 'RECEIVED', 'PAID', 'APPROVED')
                      AND NOT EXISTS (
                          SELECT 1 FROM financial_ledger fl 
                          WHERE fl.reference_table = 'purchase_orders' 
                            AND fl.reference_id = po.po_id
                      )
                ");
            } catch (\Throwable $t) {}
        } catch (\Throwable $e) {
            // Ignore DDL errors
        }
    }

    /**
     * Check if financial_ledger table has 'description' column.
     */
    private function hasLedgerDescriptionColumn(): bool
    {
        try {
            $stmt = $this->db->query("SHOW COLUMNS FROM financial_ledger LIKE 'description'");
            return $stmt && $stmt->rowCount() > 0;
        } catch (\Throwable $t) {
            return false;
        }
    }

    /**
     * Insert a record into financial_ledger in a schema-safe manner.
     */
    public function insertLedgerRecord(array $data): bool
    {
        $hasDesc = $this->hasLedgerDescriptionColumn();

        $gymId           = (int)($data['gym_id'] ?? 1);
        $branchId        = (int)($data['branch_id'] ?? 1);
        $txnType         = strtoupper(trim($data['transaction_type'] ?? 'OUTFLOW'));
        $category        = strtoupper(trim($data['category'] ?? 'OPEX'));
        $amount          = (float)($data['amount'] ?? 0.0);
        $refTable        = !empty($data['reference_table']) ? trim($data['reference_table']) : 'manual_adjustment';
        $refId           = isset($data['reference_id']) && $data['reference_id'] !== null ? (int)$data['reference_id'] : 0;
        $payMethod       = !empty($data['payment_method']) ? strtoupper(trim($data['payment_method'])) : 'CASH';
        $description     = !empty($data['description']) ? trim($data['description']) : '';
        $createdAt       = !empty($data['created_at']) ? $data['created_at'] : date('Y-m-d H:i:s');

        if ($hasDesc) {
            $stmt = $this->db->prepare("
                INSERT INTO financial_ledger (
                    gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, description, created_at
                ) VALUES (
                    :gym_id, :branch_id, :transaction_type, :category, :amount, :reference_table, :reference_id, :payment_method, :description, :created_at
                )
            ");
            return $stmt->execute([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => $txnType,
                'category'         => $category,
                'amount'           => $amount,
                'reference_table'  => $refTable,
                'reference_id'     => $refId,
                'payment_method'   => $payMethod,
                'description'      => $description,
                'created_at'       => $createdAt
            ]);
        } else {
            $stmt = $this->db->prepare("
                INSERT INTO financial_ledger (
                    gym_id, branch_id, transaction_type, category, amount, reference_table, reference_id, payment_method, created_at
                ) VALUES (
                    :gym_id, :branch_id, :transaction_type, :category, :amount, :reference_table, :reference_id, :payment_method, :created_at
                )
            ");
            return $stmt->execute([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => $txnType,
                'category'         => $category,
                'amount'           => $amount,
                'reference_table'  => $refTable,
                'reference_id'     => $refId,
                'payment_method'   => $payMethod,
                'created_at'       => $createdAt
            ]);
        }
    }





    /**
     * Get Executive Profit & Loss (P&L) Summary.
     */
    public function getExecutiveSummary(array $filters): array
    {
        $this->ensureTablesExist();

        $startDate = !empty($filters['start_date']) ? $filters['start_date'] : date('Y-m-01');
        $endDate   = !empty($filters['end_date']) ? $filters['end_date'] : date('Y-m-t');
        $branchId  = !empty($filters['branch_id']) ? (int)$filters['branch_id'] : null;

        $startDateTime = $startDate . ' 00:00:00';
        $endDateTime   = $endDate . ' 23:59:59';

        // 1. Revenue Breakdown from paid invoices
        $membershipPtSales = 0.0;
        $storeProductSales = 0.0;
        try {
            $invWhere = " WHERE i.status IN ('PAID', 'SUCCESS', 'COMPLETED') AND i.issued_at >= :start_dt AND i.issued_at <= :end_dt";
            $invParams = ['start_dt' => $startDateTime, 'end_dt' => $endDateTime];
            if ($branchId) {
                $invWhere .= " AND (u.branch_id = :branch_id OR u.branch_id IS NULL OR u.branch_id = 0)";
                $invParams['branch_id'] = $branchId;
            }


            $stmtInv = $this->db->prepare("
                SELECT 
                    ii.item_type,
                    SUM(ii.total_price) AS total_amount
                FROM invoices i
                JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
                JOIN users u ON u.user_id = i.user_id
                {$invWhere}
                GROUP BY ii.item_type
            ");
            $stmtInv->execute($invParams);
            $revRows = $stmtInv->fetchAll(PDO::FETCH_ASSOC);

            foreach ($revRows as $r) {
                $type = strtoupper($r['item_type']);
                $val  = (float)$r['total_amount'];
                if ($type === 'SUBSCRIPTION' || $type === 'PT_PACKAGE') {
                    $membershipPtSales += $val;
                } elseif ($type === 'PRODUCT') {
                    $storeProductSales += $val;
                } else {
                    $membershipPtSales += $val;
                }
            }
        } catch (\Throwable $t) {
            $membershipPtSales = 0.0;
            $storeProductSales = 0.0;
        }

        // Adjustments Inflow from financial_ledger
        $adjustmentsInflow = 0.0;
        $flWhere = " WHERE created_at >= :start_dt AND created_at <= :end_dt";
        $flParams = ['start_dt' => $startDateTime, 'end_dt' => $endDateTime];
        if ($branchId) {
            $flWhere .= " AND branch_id = :branch_id";
            $flParams['branch_id'] = $branchId;
        }

        try {
            $stmtInflowAdj = $this->db->prepare("
                SELECT COALESCE(SUM(amount), 0.0) 
                FROM financial_ledger 
                {$flWhere} AND transaction_type = 'INFLOW' AND category = 'ADJUSTMENT'
            ");
            $stmtInflowAdj->execute($flParams);
            $adjustmentsInflow = (float)$stmtInflowAdj->fetchColumn();
        } catch (\Throwable $t) {
            $adjustmentsInflow = 0.0;
        }

        $grossRevenue = $membershipPtSales + $storeProductSales + $adjustmentsInflow;

        // 2. Expense Breakdown
        // COGS
        $cogs = 0.0;
        try {
            $stmtCogs = $this->db->prepare("
                SELECT COALESCE(SUM(amount), 0.0) 
                FROM financial_ledger 
                {$flWhere} AND category = 'COGS'
            ");
            $stmtCogs->execute($flParams);
            $cogs = (float)$stmtCogs->fetchColumn();
        } catch (\Throwable $t) {
            $cogs = 0.0;
        }

        // Staff & Trainer Payroll
        $payroll = 0.0;
        try {
            $payrollWhere = " WHERE created_at >= :start_dt AND created_at <= :end_dt";
            $payrollParams = ['start_dt' => $startDateTime, 'end_dt' => $endDateTime];
            if ($branchId) {
                $payrollWhere .= " AND branch_id = :branch_id";
                $payrollParams['branch_id'] = $branchId;
            }

            $stmtPay = $this->db->prepare("
                SELECT COALESCE(SUM(net_payable), 0.0) 
                FROM payroll_runs 
                {$payrollWhere} AND status IN ('PAID', 'DISBURSED')
            ");
            $stmtPay->execute($payrollParams);
            $payroll = (float)$stmtPay->fetchColumn();
        } catch (\Throwable $t) {
            $payroll = 0.0;
        }

        // Operating Expenses (OpEx)
        $opex = 0.0;
        try {
            $opexWhere = " WHERE status != 'CANCELLED' AND expense_date >= :start_d AND expense_date <= :end_d";
            $opexParams = ['start_d' => $startDate, 'end_d' => $endDate];
            if ($branchId) {
                $opexWhere .= " AND branch_id = :branch_id";
                $opexParams['branch_id'] = $branchId;
            }
            $stmtOpex = $this->db->prepare("SELECT COALESCE(SUM(amount), 0.0) FROM operating_expenses {$opexWhere}");
            $stmtOpex->execute($opexParams);
            $opex = (float)$stmtOpex->fetchColumn();
        } catch (\Throwable $t) {
            $opex = 0.0;
        }

        // Refunds Issued
        $refunds = 0.0;
        try {
            $stmtRefund = $this->db->prepare("
                SELECT COALESCE(SUM(amount), 0.0) 
                FROM financial_ledger 
                {$flWhere} AND category = 'REFUND'
            ");
            $stmtRefund->execute($flParams);
            $refunds = (float)$stmtRefund->fetchColumn();
        } catch (\Throwable $t) {
            $refunds = 0.0;
        }

        // Adjustments Outflow
        $adjustmentsOutflow = 0.0;
        try {
            $stmtOutflowAdj = $this->db->prepare("
                SELECT COALESCE(SUM(amount), 0.0) 
                FROM financial_ledger 
                {$flWhere} AND transaction_type = 'OUTFLOW' AND category = 'ADJUSTMENT'
            ");
            $stmtOutflowAdj->execute($flParams);
            $adjustmentsOutflow = (float)$stmtOutflowAdj->fetchColumn();
        } catch (\Throwable $t) {
            $adjustmentsOutflow = 0.0;
        }


        $totalExpenses = $cogs + $payroll + $opex + $refunds + $adjustmentsOutflow;

        // 3. Net Position
        $netOperatingProfit = $grossRevenue - $totalExpenses;
        $marginPct = $grossRevenue > 0 ? round(($netOperatingProfit / $grossRevenue) * 100, 2) : 0.0;

        return [
            "period" => [
                "start_date" => $startDate,
                "end_date"   => $endDate,
                "branch_id"  => $branchId
            ],
            "revenue_breakdown" => [
                "membership_and_pt_sales" => number_format($membershipPtSales, 2, '.', ''),
                "store_product_sales"     => number_format($storeProductSales, 2, '.', ''),
                "adjustments_inflow"      => number_format($adjustmentsInflow, 2, '.', ''),
                "gross_revenue"           => number_format($grossRevenue, 2, '.', '')
            ],
            "expense_breakdown" => [
                "cogs_inventory_procurement" => number_format($cogs, 2, '.', ''),
                "staff_and_trainer_payroll"  => number_format($payroll, 2, '.', ''),
                "operating_expenses_opex"    => number_format($opex, 2, '.', ''),
                "refunds_issued"             => number_format($refunds, 2, '.', ''),
                "adjustments_outflow"        => number_format($adjustmentsOutflow, 2, '.', ''),
                "total_expenses"             => number_format($totalExpenses, 2, '.', '')
            ],
            "net_position" => [
                "net_operating_profit"     => number_format($netOperatingProfit, 2, '.', ''),
                "profit_margin_percentage" => number_format($marginPct, 2, '.', '')
            ]
        ];
    }

    /**
     * Get paginated operational expenses.
     */
    public function getOpexLogs(array $filters): array
    {
        $this->ensureTablesExist();

        $where = ["1=1"];
        $params = [];

        if (!empty($filters['category_tag'])) {
            $where[] = "category_tag = :category_tag";
            $params['category_tag'] = trim($filters['category_tag']);
        }
        if (!empty($filters['vendor_name'])) {
            $where[] = "vendor_name LIKE :vendor_name";
            $params['vendor_name'] = '%' . trim($filters['vendor_name']) . '%';
        }
        if (!empty($filters['branch_id'])) {
            $where[] = "branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }
        if (!empty($filters['start_date'])) {
            $where[] = "expense_date >= :start_date";
            $params['start_date'] = $filters['start_date'];
        }
        if (!empty($filters['end_date'])) {
            $where[] = "expense_date <= :end_date";
            $params['end_date'] = $filters['end_date'];
        }
        if (!empty($filters['time_frame']) && empty($filters['start_date'])) {
            if ($filters['time_frame'] === 'current_month') {
                $where[] = "expense_date >= DATE_FORMAT(CURDATE(), '%Y-%m-01')";
            } elseif ($filters['time_frame'] === 'previous_month') {
                $where[] = "expense_date >= DATE_SUB(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 1 MONTH) AND expense_date < DATE_FORMAT(CURDATE(), '%Y-%m-01')";
            }
        }

        $whereClause = implode(' AND ', $where);

        // Count & Total amount
        $stmtCount = $this->db->prepare("SELECT COUNT(*) AS total_cnt, COALESCE(SUM(amount), 0.0) AS total_amt FROM operating_expenses WHERE {$whereClause}");
        $stmtCount->execute($params);
        $countRow = $stmtCount->fetch(PDO::FETCH_ASSOC);

        $totalRecords = (int)($countRow['total_cnt'] ?? 0);
        $totalAmount  = (float)($countRow['total_amt'] ?? 0.0);

        $page  = max(1, (int)($filters['page'] ?? 1));
        $limit = max(1, min(100, (int)($filters['limit'] ?? 20)));
        $offset = ($page - 1) * $limit;
        $totalPages = ceil($totalRecords / $limit) ?: 1;

        $stmtList = $this->db->prepare("
            SELECT * FROM operating_expenses 
            WHERE {$whereClause} 
            ORDER BY expense_date DESC, opex_id DESC 
            LIMIT {$limit} OFFSET {$offset}
        ");
        $stmtList->execute($params);
        $expenses = $stmtList->fetchAll(PDO::FETCH_ASSOC);

        foreach ($expenses as &$exp) {
            $exp['opex_id']   = (int)$exp['opex_id'];
            $exp['gym_id']    = (int)$exp['gym_id'];
            $exp['branch_id'] = (int)$exp['branch_id'];
            $exp['amount']    = number_format((float)$exp['amount'], 2, '.', '');
        }

        return [
            "expenses" => $expenses,
            "pagination" => [
                "current_page"  => $page,
                "limit"         => $limit,
                "total_records" => $totalRecords,
                "total_pages"   => $totalPages
            ],
            "summary_metrics" => [
                "filtered_total_opex_amount" => number_format($totalAmount, 2, '.', '')
            ]
        ];
    }

    /**
     * Log a new operational expense.
     */
    public function logOpex(array $data): int
    {
        $this->ensureTablesExist();

        $title         = !empty($data['title']) ? trim((string)$data['title']) : 'Operational Expense';
        $categoryTag   = !empty($data['category_tag']) ? strtoupper(trim((string)$data['category_tag'])) : 'OPERATING';
        $amount        = isset($data['amount']) ? (float)$data['amount'] : 0.0;
        $paymentMethod = !empty($data['payment_method']) ? strtoupper(trim((string)$data['payment_method'])) : 'UPI';
        $vendorName    = !empty($data['vendor_name']) ? trim((string)$data['vendor_name']) : null;
        $receiptRef    = !empty($data['receipt_ref']) ? trim((string)$data['receipt_ref']) : null;
        $receiptUrl    = !empty($data['receipt_url']) ? trim((string)$data['receipt_url']) : null;
        $expenseDate   = !empty($data['expense_date']) ? (string)$data['expense_date'] : date('Y-m-d');
        $gymId         = isset($data['gym_id']) ? (int)$data['gym_id'] : 1;
        $branchId      = isset($data['branch_id']) ? (int)$data['branch_id'] : 1;

        $stmt = $this->db->prepare("
            INSERT INTO operating_expenses (
                gym_id, branch_id, title, category_tag, amount, payment_method, 
                vendor_name, receipt_ref, receipt_url, expense_date, status
            ) VALUES (
                :gym_id, :branch_id, :title, :category_tag, :amount, :payment_method, 
                :vendor_name, :receipt_ref, :receipt_url, :expense_date, 'APPROVED'
            )
        ");

        $stmt->execute([
            'gym_id'         => $gymId,
            'branch_id'      => $branchId,
            'title'          => $title,
            'category_tag'   => $categoryTag,
            'amount'         => $amount,
            'payment_method' => $paymentMethod,
            'vendor_name'    => $vendorName,
            'receipt_ref'    => $receiptRef,
            'receipt_url'    => $receiptUrl,
            'expense_date'   => $expenseDate
        ]);

        $opexId = (int)$this->db->lastInsertId();

        // Also record in financial_ledger if ledger table is ready
        try {
            $ledgerCreatedAt = $expenseDate . ' ' . date('H:i:s');
            $this->insertLedgerRecord([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => 'OUTFLOW',
                'category'         => 'OPEX',
                'amount'           => $amount,
                'reference_table'  => 'operating_expenses',
                'reference_id'     => $opexId,
                'payment_method'   => $paymentMethod,
                'description'      => "OpEx: " . $title,
                'created_at'       => $ledgerCreatedAt
            ]);
        } catch (\Throwable $t) {
            // Ignore financial_ledger insert error if ledger table is missing
        }

        return $opexId;
    }


    /**
     * Cancel/Void an operational expense.
     */
    public function cancelOpex(int $opexId, string $reason): bool
    {
        $this->ensureTablesExist();

        $stmtCheck = $this->db->prepare("SELECT * FROM operating_expenses WHERE opex_id = :id LIMIT 1");
        $stmtCheck->execute(['id' => $opexId]);
        $exp = $stmtCheck->fetch(PDO::FETCH_ASSOC);

        if (!$exp) {
            throw new Exception("Operating expense not found", 404);
        }

        $stmt = $this->db->prepare("UPDATE operating_expenses SET status = 'CANCELLED', cancellation_reason = :reason WHERE opex_id = :id");
        $stmt->execute(['id' => $opexId, 'reason' => trim($reason)]);

        // Record offsetting INFLOW in financial_ledger
        $this->insertLedgerRecord([
            'gym_id'           => (int)$exp['gym_id'],
            'branch_id'        => (int)$exp['branch_id'],
            'transaction_type' => 'INFLOW',
            'category'         => 'ADJUSTMENT',
            'amount'           => (float)$exp['amount'],
            'reference_table'  => 'operating_expenses',
            'reference_id'     => $opexId,
            'payment_method'   => $exp['payment_method'],
            'description'      => "Voided OpEx #{$opexId}: " . trim($reason)
        ]);

        return true;
    }

    /**
     * Get paginated financial ledger logs.
     */
    public function getLedgerLogs(array $filters): array
    {
        $this->ensureTablesExist();

        $where = ["1=1"];
        $params = [];

        if (!empty($filters['transaction_type'])) {
            $where[] = "transaction_type = :transaction_type";
            $params['transaction_type'] = strtoupper(trim($filters['transaction_type']));
        }
        if (!empty($filters['category'])) {
            $where[] = "category = :category";
            $params['category'] = strtoupper(trim($filters['category']));
        }
        if (!empty($filters['payment_method'])) {
            $where[] = "payment_method = :payment_method";
            $params['payment_method'] = strtoupper(trim($filters['payment_method']));
        }
        if (!empty($filters['branch_id'])) {
            $where[] = "branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }
        if (!empty($filters['start_date'])) {
            $where[] = "created_at >= :start_date";
            $params['start_date'] = $filters['start_date'] . ' 00:00:00';
        }
        if (!empty($filters['end_date'])) {
            $where[] = "created_at <= :end_date";
            $params['end_date'] = $filters['end_date'] . ' 23:59:59';
        }

        $whereClause = implode(' AND ', $where);

        // Calculate totals
        $stmtTotals = $this->db->prepare("
            SELECT 
                COUNT(*) AS total_cnt,
                SUM(CASE WHEN transaction_type = 'INFLOW' THEN amount ELSE 0 END) AS total_inflow,
                SUM(CASE WHEN transaction_type = 'OUTFLOW' THEN amount ELSE 0 END) AS total_outflow
            FROM financial_ledger 
            WHERE {$whereClause}
        ");
        $stmtTotals->execute($params);
        $totalsRow = $stmtTotals->fetch(PDO::FETCH_ASSOC);

        $totalRecords = (int)($totalsRow['total_cnt'] ?? 0);
        $totalInflow  = (float)($totalsRow['total_inflow'] ?? 0.0);
        $totalOutflow = (float)($totalsRow['total_outflow'] ?? 0.0);
        $netCashflow  = $totalInflow - $totalOutflow;

        $page  = max(1, (int)($filters['page'] ?? 1));
        $limit = max(1, min(100, (int)($filters['limit'] ?? 50)));
        $offset = ($page - 1) * $limit;
        $totalPages = ceil($totalRecords / $limit) ?: 1;

        $stmtList = $this->db->prepare("
            SELECT * FROM financial_ledger 
            WHERE {$whereClause} 
            ORDER BY ledger_id DESC 
            LIMIT {$limit} OFFSET {$offset}
        ");
        $stmtList->execute($params);
        $entries = $stmtList->fetchAll(PDO::FETCH_ASSOC);

        foreach ($entries as &$entry) {
            $entry['ledger_id']    = (int)$entry['ledger_id'];
            $entry['gym_id']       = (int)$entry['gym_id'];
            $entry['branch_id']    = (int)$entry['branch_id'];
            $entry['reference_id'] = $entry['reference_id'] !== null ? (int)$entry['reference_id'] : null;
            $entry['amount']       = number_format((float)$entry['amount'], 2, '.', '');
            if (!isset($entry['description'])) {
                $entry['description'] = $entry['category'] . ' Transaction';
            }
        }

        return [
            "ledger_entries" => $entries,
            "pagination" => [
                "current_page"  => $page,
                "limit"         => $limit,
                "total_records" => $totalRecords,
                "total_pages"   => $totalPages
            ],
            "summary_metrics" => [
                "period_total_inflow"  => number_format($totalInflow, 2, '.', ''),
                "period_total_outflow" => number_format($totalOutflow, 2, '.', ''),
                "period_net_cashflow"  => number_format($netCashflow, 2, '.', '')
            ]
        ];
    }

    /**
     * Log manual financial adjustment.
     */
    public function logLedgerAdjustment(array $data): bool
    {
        $this->ensureTablesExist();

        $transactionType = !empty($data['transaction_type']) ? strtoupper(trim((string)$data['transaction_type'])) : 'OUTFLOW';
        $paymentMethod   = !empty($data['payment_method']) ? strtoupper(trim((string)$data['payment_method'])) : 'CASH';
        $description     = !empty($data['description']) ? trim((string)$data['description']) : 'Manual adjustment';
        $amount          = isset($data['amount']) ? (float)$data['amount'] : 0.0;
        $gymId           = isset($data['gym_id']) ? (int)$data['gym_id'] : 1;
        $branchId        = isset($data['branch_id']) ? (int)$data['branch_id'] : 1;

        return $this->insertLedgerRecord([
            'gym_id'           => $gymId,
            'branch_id'        => $branchId,
            'transaction_type' => $transactionType,
            'category'         => 'ADJUSTMENT',
            'amount'           => $amount,
            'reference_table'  => 'manual_adjustment',
            'reference_id'     => 0,
            'payment_method'   => $paymentMethod,
            'description'      => $description
        ]);
    }


}

