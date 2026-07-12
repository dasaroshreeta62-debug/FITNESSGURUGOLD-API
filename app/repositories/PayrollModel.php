<?php

require_once __DIR__ . '/../config/database.php';

class PayrollModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    public function beginTransaction(): bool { return $this->db->beginTransaction(); }
    public function commit(): bool           { return $this->db->commit(); }
    public function rollBack(): bool         { return $this->db->rollBack(); }
    public function inTransaction(): bool    { return $this->db->inTransaction(); }

    /**
     * Get all ACTIVE employees (TRAINER / STAFF / MANAGER) for a branch.
     * Optionally filters by branch_id if provided.
     */
    public function getActiveEmployeesForBranch(?int $branchId): array
    {
        $sql = "
            SELECT
                e.employee_id,
                e.user_id,
                e.gym_id,
                e.branch_id,
                e.full_name,
                e.salary_amount AS base_salary,
                u.role,
                tp.trainer_profile_id
            FROM employees e
            JOIN users u ON u.user_id = e.user_id
            LEFT JOIN trainer_profiles tp ON tp.employee_id = e.employee_id
            WHERE e.status = 'ACTIVE'
              AND u.role IN ('TRAINER', 'STAFF', 'MANAGER')
        ";
        $params = [];
        if ($branchId) {
            $sql .= " AND e.branch_id = :branch_id";
            $params['branch_id'] = $branchId;
        }
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Sum all UNPAID commissions for a specific trainer_profile_id.
     */
    public function getUnpaidCommissionsSum(int $trainerProfileId): float
    {
        $stmt = $this->db->prepare("
            SELECT COALESCE(SUM(commission_amount), 0)
            FROM trainer_commissions
            WHERE trainer_id = :trainer_id AND status = 'UNPAID'
        ");
        $stmt->execute(['trainer_id' => $trainerProfileId]);
        return (float)$stmt->fetchColumn();
    }

    /**
     * Check if payroll DRAFT rows already exist for a given pay_month / pay_year / branch_id.
     * Used to prevent duplicate draft generation.
     */
    public function payrollDraftExists(int $month, int $year, ?int $branchId): bool
    {
        $sql    = "SELECT COUNT(*) FROM payroll_runs WHERE pay_month = :month AND pay_year = :year";
        $params = ['month' => $month, 'year' => $year];
        if ($branchId) {
            $sql .= " AND branch_id = :branch_id";
            $params['branch_id'] = $branchId;
        }
        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn() > 0;
    }

    /**
     * Insert a single payroll draft row for one employee.
     */
    public function insertPayrollRun(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO payroll_runs (
                gym_id, branch_id, employee_id, pay_month, pay_year,
                base_salary, commission_amount, net_payable, status
            ) VALUES (
                :gym_id, :branch_id, :employee_id, :pay_month, :pay_year,
                :base_salary, :commission_amount, :net_payable, 'DRAFT'
            )
        ");
        $stmt->execute([
            'gym_id'            => (int)$data['gym_id'],
            'branch_id'         => (int)$data['branch_id'],
            'employee_id'       => (int)$data['employee_id'],
            'pay_month'         => (int)$data['pay_month'],
            'pay_year'          => (int)$data['pay_year'],
            'base_salary'       => (float)$data['base_salary'],
            'commission_amount' => (float)$data['commission_amount'],
            'net_payable'       => (float)$data['net_payable']
        ]);
        return (int)$this->db->lastInsertId();
    }

    /**
     * Fetch a single payroll run with employee details.
     */
    public function getPayrollRunById(int $payrollId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT
                pr.*,
                e.full_name  AS employee_name,
                e.user_id,
                tp.trainer_profile_id
            FROM payroll_runs pr
            JOIN employees e ON e.employee_id = pr.employee_id
            LEFT JOIN trainer_profiles tp ON tp.employee_id = pr.employee_id
            WHERE pr.payroll_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $payrollId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * Set a payroll run to PAID and record bonus/deductions/net amount.
     */
    public function updatePayrollRunPaid(int $payrollId, float $netPayable, float $bonus, float $deductions): bool
    {
        $stmt = $this->db->prepare("
            UPDATE payroll_runs
            SET status      = 'PAID',
                net_payable = :net_payable,
                bonus       = :bonus,
                deductions  = :deductions,
                paid_at     = NOW()
            WHERE payroll_id = :id
        ");
        return $stmt->execute([
            'id'          => $payrollId,
            'net_payable' => $netPayable,
            'bonus'       => $bonus,
            'deductions'  => $deductions
        ]);
    }

    /**
     * Fetch a single trainer commission by commission_id.
     */
    public function getCommissionById(int $commissionId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT
                tc.*,
                e.full_name      AS trainer_name,
                i.invoice_number
            FROM trainer_commissions tc
            LEFT JOIN trainer_profiles tp ON tp.trainer_profile_id = tc.trainer_id
            LEFT JOIN employees e ON e.employee_id = tp.employee_id
            LEFT JOIN invoices i ON i.invoice_id = tc.invoice_id
            WHERE tc.commission_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $commissionId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /**
     * Mark a commission as PAID. Optionally links a payroll_id (NULL for off-cycle).
     */
    public function markCommissionPaid(int $commissionId, ?int $payrollId = null): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_commissions
            SET status     = 'PAID',
                paid_at    = NOW(),
                payroll_id = :payroll_id
            WHERE commission_id = :id
        ");
        return $stmt->execute(['id' => $commissionId, 'payroll_id' => $payrollId]);
    }

    /**
     * Mark ALL UNPAID commissions for a trainer as PAID under a payroll run.
     * Returns the count of rows updated.
     */
    public function markTrainerCommissionsPaid(int $trainerProfileId, int $payrollId): int
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_commissions
            SET status     = 'PAID',
                paid_at    = NOW(),
                payroll_id = :payroll_id
            WHERE trainer_id = :trainer_id AND status = 'UNPAID'
        ");
        $stmt->execute(['payroll_id' => $payrollId, 'trainer_id' => $trainerProfileId]);
        return $stmt->rowCount();
    }

    /**
     * Insert a financial ledger entry (OUTFLOW / PAYROLL category).
     */
    public function insertLedgerEntry(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO financial_ledger (
                gym_id, branch_id, transaction_type, category,
                amount, reference_table, reference_id, payment_method, created_at
            ) VALUES (
                :gym_id, :branch_id, :transaction_type, :category,
                :amount, :reference_table, :reference_id, :payment_method, NOW()
            )
        ");
        $stmt->execute([
            'gym_id'           => (int)$data['gym_id'],
            'branch_id'        => (int)$data['branch_id'],
            'transaction_type' => strtoupper($data['transaction_type']),
            'category'         => strtoupper($data['category']),
            'amount'           => (float)$data['amount'],
            'reference_table'  => $data['reference_table'],
            'reference_id'     => (int)$data['reference_id'],
            'payment_method'   => strtoupper($data['payment_method'])
        ]);
        return (int)$this->db->lastInsertId();
    }

    /**
     * Get trainer commissions with optional filters and pagination.
     * Returns pagination meta, summary metrics, and commission rows.
     */
    public function getTrainerCommissions(array $filters): array
    {
        $page   = max(1, (int)($filters['page'] ?? 1));
        $limit  = min(100, max(1, (int)($filters['limit'] ?? 20)));
        $offset = ($page - 1) * $limit;

        $where  = [];
        $params = [];

        if (!empty($filters['status'])) {
            $where[]          = "tc.status = :status";
            $params['status'] = strtoupper($filters['status']);
        }

        if (!empty($filters['trainer_id'])) {
            $where[]              = "tc.trainer_id = :trainer_id";
            $params['trainer_id'] = (int)$filters['trainer_id'];
        }

        if (!empty($filters['branch_id'])) {
            $where[]             = "tc.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        // Shortcut time-frame filters
        $timeFrame = $filters['time_frame'] ?? '';
        if ($timeFrame === 'current_month') {
            $where[] = "MONTH(tc.created_at) = MONTH(NOW()) AND YEAR(tc.created_at) = YEAR(NOW())";
        } elseif ($timeFrame === 'previous_month') {
            $where[] = "MONTH(tc.created_at) = MONTH(NOW() - INTERVAL 1 MONTH)"
                     . " AND YEAR(tc.created_at) = YEAR(NOW() - INTERVAL 1 MONTH)";
        }

        // Explicit month / year filters
        if (!empty($filters['month'])) {
            $where[]         = "MONTH(tc.created_at) = :month";
            $params['month'] = (int)$filters['month'];
        }
        if (!empty($filters['year'])) {
            $where[]        = "YEAR(tc.created_at) = :year";
            $params['year'] = (int)$filters['year'];
        }

        $whereClause = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

        // Aggregate count + total amount
        $countSql  = "SELECT COUNT(*) AS cnt, COALESCE(SUM(tc.commission_amount), 0) AS total_amount
                      FROM trainer_commissions tc $whereClause";
        $countStmt = $this->db->prepare($countSql);
        $countStmt->execute($params);
        $meta         = $countStmt->fetch(PDO::FETCH_ASSOC);
        $totalRecords = (int)($meta['cnt'] ?? 0);
        $totalAmount  = (float)($meta['total_amount'] ?? 0.0);

        // Inline LIMIT/OFFSET as integers to avoid PDO named-param type binding issues
        $paginatedSql = "
            SELECT
                tc.commission_id,
                tc.gym_id,
                tc.branch_id,
                tc.trainer_id,
                e.full_name         AS trainer_name,
                tc.invoice_id,
                i.invoice_number,
                u.name              AS client_name,
                tc.commission_amount,
                tc.status,
                tc.payroll_id,
                tc.created_at       AS earned_at,
                tc.paid_at
            FROM trainer_commissions tc
            LEFT JOIN trainer_profiles tp ON tp.trainer_profile_id = tc.trainer_id
            LEFT JOIN employees e ON e.employee_id = tp.employee_id
            LEFT JOIN invoices i ON i.invoice_id = tc.invoice_id
            LEFT JOIN users u ON u.user_id = i.user_id
            $whereClause
            ORDER BY tc.created_at DESC
            LIMIT $limit OFFSET $offset
        ";
        $stmt = $this->db->prepare($paginatedSql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as &$row) {
            $row['commission_id']     = (int)$row['commission_id'];
            $row['gym_id']            = (int)$row['gym_id'];
            $row['branch_id']         = (int)$row['branch_id'];
            $row['trainer_id']        = (int)$row['trainer_id'];
            $row['invoice_id']        = (int)$row['invoice_id'];
            $row['commission_amount'] = number_format((float)$row['commission_amount'], 2, '.', '');
            $row['payroll_id']        = $row['payroll_id'] !== null ? (int)$row['payroll_id'] : null;
        }
        unset($row);

        return [
            'pagination' => [
                'current_page'  => $page,
                'limit'         => $limit,
                'total_records' => $totalRecords,
                'total_pages'   => (int)ceil($totalRecords / max($limit, 1))
            ],
            'summary_metrics' => [
                'filtered_total_commission_amount' => number_format($totalAmount, 2, '.', '')
            ],
            'commissions' => $rows
        ];
    }

    /**
     * List payroll runs with filters, summary metrics, and pagination.
     *
     * Supported filters:
     *   status, time_frame, pay_month, pay_year, employee_id, role, branch_id,
     *   includes_commission, page, limit
     */
    public function getPayrollRuns(array $filters): array
    {
        $page   = max(1, (int)($filters['page'] ?? 1));
        $limit  = min(100, max(1, (int)($filters['limit'] ?? 20)));
        $offset = ($page - 1) * $limit;

        $joins  = [];
        $where  = [];
        $params = [];

        // Always join employees and users for employee details
        $baseJoins = "
            JOIN employees e ON e.employee_id = pr.employee_id
            JOIN users u ON u.user_id = e.user_id
        ";

        // status filter
        if (!empty($filters['status'])) {
            $where[]          = "pr.status = :status";
            $params['status'] = strtoupper($filters['status']);
        }

        // branch_id filter
        if (!empty($filters['branch_id'])) {
            $where[]             = "pr.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        // employee_id filter
        if (!empty($filters['employee_id'])) {
            $where[]               = "pr.employee_id = :employee_id";
            $params['employee_id'] = (int)$filters['employee_id'];
        }

        // role filter (via users table)
        if (!empty($filters['role'])) {
            $where[]        = "u.role = :role";
            $params['role'] = strtoupper($filters['role']);
        }

        // includes_commission filter: true = commission_amount > 0, false = commission_amount = 0
        if (isset($filters['includes_commission']) && $filters['includes_commission'] !== null
            && $filters['includes_commission'] !== '') {
            $incComm = filter_var($filters['includes_commission'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            if ($incComm === true) {
                $where[] = "pr.commission_amount > 0";
            } elseif ($incComm === false) {
                $where[] = "pr.commission_amount = 0";
            }
        }

        // time_frame shortcut math (takes priority over explicit pay_month/pay_year)
        $timeFrame = $filters['time_frame'] ?? '';
        if ($timeFrame === 'current_month') {
            $where[] = "pr.pay_month = MONTH(CURRENT_DATE()) AND pr.pay_year = YEAR(CURRENT_DATE())";
        } elseif ($timeFrame === 'previous_month') {
            $where[] = "pr.pay_month = MONTH(CURRENT_DATE() - INTERVAL 1 MONTH)"
                     . " AND pr.pay_year = YEAR(CURRENT_DATE() - INTERVAL 1 MONTH)";
        } elseif ($timeFrame === 'last_3_months') {
            $where[] = "STR_TO_DATE(CONCAT(pr.pay_year, '-', pr.pay_month, '-01'), '%Y-%m-%d')"
                     . " >= CURRENT_DATE() - INTERVAL 3 MONTH";
        } else {
            // Explicit month/year filters (only applied when no time_frame shortcut)
            if (!empty($filters['pay_month'])) {
                $where[]             = "pr.pay_month = :pay_month";
                $params['pay_month'] = (int)$filters['pay_month'];
            }
            if (!empty($filters['pay_year'])) {
                $where[]            = "pr.pay_year = :pay_year";
                $params['pay_year'] = (int)$filters['pay_year'];
            }
            // Default: current month when nothing is specified
            if (empty($filters['pay_month']) && empty($filters['pay_year']) && empty($timeFrame)) {
                $where[] = "pr.pay_month = MONTH(CURRENT_DATE()) AND pr.pay_year = YEAR(CURRENT_DATE())";
            }
        }

        $whereClause = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

        // ── Aggregated summary metrics ────────────────────────────────────────
        $metaSql = "
            SELECT
                COUNT(*)                             AS cnt,
                COALESCE(SUM(pr.base_salary), 0)     AS total_base,
                COALESCE(SUM(pr.commission_amount), 0) AS total_comm,
                COALESCE(SUM(pr.bonus), 0)           AS total_bonus,
                COALESCE(SUM(pr.deductions), 0)      AS total_deductions,
                COALESCE(SUM(pr.net_payable), 0)     AS total_net
            FROM payroll_runs pr
            $baseJoins
            $whereClause
        ";
        $metaStmt = $this->db->prepare($metaSql);
        $metaStmt->execute($params);
        $meta         = $metaStmt->fetch(PDO::FETCH_ASSOC);
        $totalRecords = (int)($meta['cnt'] ?? 0);

        // ── Paginated payroll rows ────────────────────────────────────────────
        $paginatedSql = "
            SELECT
                pr.payroll_id,
                pr.gym_id,
                pr.branch_id,
                pr.employee_id,
                e.full_name       AS employee_name,
                u.role            AS employee_role,
                e.phone           AS employee_phone,
                pr.pay_month,
                pr.pay_year,
                pr.base_salary,
                pr.commission_amount,
                pr.bonus,
                pr.deductions,
                pr.net_payable,
                pr.status,
                pr.created_at,
                pr.paid_at
            FROM payroll_runs pr
            $baseJoins
            $whereClause
            ORDER BY pr.pay_year DESC, pr.pay_month DESC, pr.payroll_id DESC
            LIMIT $limit OFFSET $offset
        ";
        $stmt = $this->db->prepare($paginatedSql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // ── Build structured response rows ────────────────────────────────────
        $monthNames = [
            1  => 'January', 2  => 'February', 3  => 'March',    4  => 'April',
            5  => 'May',      6  => 'June',     7  => 'July',     8  => 'August',
            9  => 'September',10 => 'October', 11 => 'November', 12 => 'December'
        ];

        $payrolls = [];
        foreach ($rows as $row) {
            $month         = (int)$row['pay_month'];
            $year          = (int)$row['pay_year'];
            $commAmount    = (float)$row['commission_amount'];
            $bonusAmount   = (float)$row['bonus'];
            $deductAmount  = (float)$row['deductions'];

            $payrolls[] = [
                'payroll_id' => (int)$row['payroll_id'],
                'gym_id'     => (int)$row['gym_id'],
                'branch_id'  => (int)$row['branch_id'],
                'employee'   => [
                    'employee_id' => (int)$row['employee_id'],
                    'name'        => $row['employee_name'],
                    'role'        => $row['employee_role'],
                    'phone'       => $row['employee_phone']
                ],
                'pay_period' => [
                    'month'        => $month,
                    'year'         => $year,
                    'display_name' => ($monthNames[$month] ?? 'Unknown') . ' ' . $year
                ],
                'breakdown' => [
                    'base_salary'       => number_format((float)$row['base_salary'], 2, '.', ''),
                    'commission_amount' => number_format($commAmount, 2, '.', ''),
                    'bonus'             => number_format($bonusAmount, 2, '.', ''),
                    'deductions'        => number_format($deductAmount, 2, '.', '')
                ],
                'net_payable'         => number_format((float)$row['net_payable'], 2, '.', ''),
                'includes_commission' => $commAmount > 0,
                'status'              => $row['status'],
                'created_at'          => $row['created_at'],
                'paid_at'             => $row['paid_at']
            ];
        }

        return [
            'pagination' => [
                'current_page'  => $page,
                'limit'         => $limit,
                'total_records' => $totalRecords,
                'total_pages'   => (int)ceil($totalRecords / max($limit, 1))
            ],
            'summary_metrics' => [
                'filtered_total_base_salary'    => number_format((float)($meta['total_base']       ?? 0), 2, '.', ''),
                'filtered_total_commissions'    => number_format((float)($meta['total_comm']       ?? 0), 2, '.', ''),
                'filtered_total_bonuses'        => number_format((float)($meta['total_bonus']      ?? 0), 2, '.', ''),
                'filtered_total_deductions'     => number_format((float)($meta['total_deductions'] ?? 0), 2, '.', ''),
                'filtered_grand_net_payable'    => number_format((float)($meta['total_net']        ?? 0), 2, '.', '')
            ],
            'payrolls' => $payrolls
        ];
    }
}
