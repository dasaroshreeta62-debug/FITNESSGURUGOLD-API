<?php

require_once __DIR__ . '/../repositories/PayrollModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class PayrollWorkflow
{
    private PayrollModel $model;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->model = new PayrollModel();
    }

    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    private function verifyRole(string $accessToken, array $allowedRoles): object
    {
        try {
            $decoded = JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));
        } catch (\Throwable $e) {
            throw new Exception("Invalid or expired token", 401);
        }

        $role             = str_replace(['_', '-'], '', strtoupper($decoded->role ?? ''));
        $allowedNormalized = array_map(function ($r) {
            return str_replace(['_', '-'], '', strtoupper($r));
        }, $allowedRoles);

        if (!in_array($role, $allowedNormalized)) {
            throw new Exception("Access denied. Authorized role required.", 403);
        }
        return $decoded;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. GET /api/v1/admin/trainer-commissions
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * View and audit all PT commissions with rich filtering and pagination.
     */
    public function getTrainerCommissions(string $accessToken, array $filters): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $result = $this->model->getTrainerCommissions($filters);

            return [
                'status' => 'success',
                'data'   => $result
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. POST /api/v1/admin/trainer-commissions/{commission_id}/pay-early
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Manually disburse a single UNPAID commission off-cycle (no payroll run).
     * Logs the outflow in financial_ledger. payroll_id remains NULL.
     */
    public function payCommissionEarly(string $accessToken, int $commissionId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            // Fetch the commission
            $commission = $this->model->getCommissionById($commissionId);
            if (!$commission) {
                throw new Exception("Commission not found", 404);
            }

            // Guard: already paid?
            if ($commission['status'] === 'PAID') {
                throw new Exception("This commission has already been disbursed", 400);
            }

            if ($commission['status'] === 'VOIDED') {
                throw new Exception("This commission has been voided and cannot be paid", 400);
            }

            $paymentMethod = strtoupper(trim($data['payment_method'] ?? 'BANK_TRANSFER'));
            $remarks       = trim($data['remarks'] ?? '');

            $commissionAmount = (float)$commission['commission_amount'];
            $gymId            = (int)$commission['gym_id'];
            $branchId         = (int)$commission['branch_id'];
            $invoiceNumber    = $commission['invoice_number'] ?? 'N/A';

            $this->model->beginTransaction();

            // Mark commission PAID (payroll_id = NULL → off-cycle)
            $this->model->markCommissionPaid($commissionId, null);

            // Log immutable OUTFLOW entry in financial_ledger
            $description = "Off-cycle PT Commission Payout - Invoice #{$invoiceNumber}";
            $ledgerId = $this->model->insertLedgerEntry([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => 'OUTFLOW',
                'category'         => 'PAYROLL',
                'amount'           => $commissionAmount,
                'reference_table'  => 'trainer_commissions',
                'reference_id'     => $commissionId,
                'payment_method'   => $paymentMethod
            ]);

            $this->model->commit();

            $this->setResponseCode(200);
            return [
                'status'  => 'success',
                'message' => 'PT commission disbursed early and recorded in master ledger.',
                'data'    => [
                    'commission_id'       => $commissionId,
                    'trainer_id'          => (int)$commission['trainer_id'],
                    'amount_paid'         => number_format($commissionAmount, 2, '.', ''),
                    'payment_method'      => $paymentMethod,
                    'ledger_reference_id' => $ledgerId
                ]
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. POST /api/v1/jobs/payroll/generate-monthly-drafts
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generate DRAFT payroll run rows for all active employees in a branch.
     * Controlled by include_commissions flag: when true, sums UNPAID PT commissions
     * for trainer employees; when false, commission_amount = 0.00.
     * Guards against duplicate draft generation for the same month/year/branch.
     */
    public function generateMonthlyDrafts(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            // Resolve pay period — defaults to previous calendar month
            if (!empty($data['pay_month']) && !empty($data['pay_year'])) {
                $payMonth = (int)$data['pay_month'];
                $payYear  = (int)$data['pay_year'];
            } else {
                $payMonth = (int)date('n', strtotime('first day of last month'));
                $payYear  = (int)date('Y', strtotime('first day of last month'));
            }

            if ($payMonth < 1 || $payMonth > 12) {
                throw new Exception("pay_month must be between 1 and 12", 400);
            }
            if ($payYear < 2020 || $payYear > 2100) {
                throw new Exception("pay_year is out of valid range", 400);
            }

            $branchId           = isset($data['branch_id']) ? (int)$data['branch_id'] : null;
            $includeCommissions = !empty($data['include_commissions']) && $data['include_commissions'] !== false
                                  && $data['include_commissions'] !== 'false';

            // Duplicate-draft guard
            if ($this->model->payrollDraftExists($payMonth, $payYear, $branchId)) {
                throw new Exception(
                    "Payroll drafts for {$payMonth}/{$payYear} (branch_id={$branchId}) already exist. "
                    . "Delete or void them before re-generating.",
                    400
                );
            }

            $employees = $this->model->getActiveEmployeesForBranch($branchId);
            if (empty($employees)) {
                throw new Exception("No active employees found for the given branch", 404);
            }

            $this->model->beginTransaction();

            $totalEmployees    = 0;
            $totalBaseSalaries = 0.0;
            $totalCommissions  = 0.0;
            $totalDraftPayout  = 0.0;

            foreach ($employees as $emp) {
                $baseSalary       = (float)$emp['base_salary'];
                $commissionAmount = 0.0;

                // Only trainers have a trainer_profile_id; fetch their UNPAID sum if requested
                if ($includeCommissions && !empty($emp['trainer_profile_id'])) {
                    $commissionAmount = $this->model->getUnpaidCommissionsSum((int)$emp['trainer_profile_id']);
                }

                $netPayable = $baseSalary + $commissionAmount;

                $this->model->insertPayrollRun([
                    'gym_id'            => (int)$emp['gym_id'],
                    'branch_id'         => (int)$emp['branch_id'],
                    'employee_id'       => (int)$emp['employee_id'],
                    'pay_month'         => $payMonth,
                    'pay_year'          => $payYear,
                    'base_salary'       => $baseSalary,
                    'commission_amount' => $commissionAmount,
                    'net_payable'       => $netPayable
                ]);

                $totalEmployees++;
                $totalBaseSalaries += $baseSalary;
                $totalCommissions  += $commissionAmount;
                $totalDraftPayout  += $netPayable;
            }

            $this->model->commit();

            $this->setResponseCode(201);
            return [
                'status'  => 'success',
                'message' => 'Monthly payroll drafts generated successfully.',
                'data'    => [
                    'pay_period'                => str_pad($payMonth, 2, '0', STR_PAD_LEFT) . '/' . $payYear,
                    'include_commissions'       => $includeCommissions,
                    'total_employees_processed' => $totalEmployees,
                    'total_base_salaries'       => number_format($totalBaseSalaries, 2, '.', ''),
                    'total_unpaid_commissions'  => number_format($totalCommissions, 2, '.', ''),
                    'total_draft_payout'        => number_format($totalDraftPayout, 2, '.', '')
                ]
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. POST /api/v1/admin/payroll/{payroll_id}/disburse
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Approve and disburse a DRAFT payroll run with split ledger accounting.
     * Creates two separate financial_ledger entries:
     *   1. Fixed base salary payout (base_salary + bonus - deductions)
     *   2. PT commission payout (if include_pt_commissions = true and commission > 0)
     * Marks all UNPAID trainer commissions as PAID under this payroll_id.
     */
    public function disbursePayroll(string $accessToken, int $payrollId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $payrollRun = $this->model->getPayrollRunById($payrollId);
            if (!$payrollRun) {
                throw new Exception("Payroll run not found", 404);
            }

            if ($payrollRun['status'] !== 'DRAFT') {
                throw new Exception(
                    "Cannot disburse: payroll run status is '{$payrollRun['status']}'. Only DRAFT runs can be disbursed.",
                    400
                );
            }

            $bonus              = (float)($data['bonus'] ?? 0.0);
            $deductions         = (float)($data['deductions'] ?? 0.0);
            $paymentMethod      = strtoupper(trim($data['payment_method'] ?? 'BANK_TRANSFER'));
            $remarks            = trim($data['remarks'] ?? '');
            $includePtComm      = !empty($data['include_pt_commissions']) && $data['include_pt_commissions'] !== false
                                  && $data['include_pt_commissions'] !== 'false';

            $baseSalary           = (float)$payrollRun['base_salary'];
            $draftCommissionAmount = (float)$payrollRun['commission_amount'];
            $gymId                = (int)$payrollRun['gym_id'];
            $branchId             = (int)$payrollRun['branch_id'];
            $trainerProfileId     = $payrollRun['trainer_profile_id'] ? (int)$payrollRun['trainer_profile_id'] : null;

            // Pay period label for descriptions
            $payPeriodLabel = date('F Y', mktime(0, 0, 0, (int)$payrollRun['pay_month'], 1, (int)$payrollRun['pay_year']));

            $regularSalaryPayout = round($baseSalary + $bonus - $deductions, 2);

            $this->model->beginTransaction();

            $ledgerEntries       = [];
            $commLockedCount     = 0;
            $actualCommAmount    = 0.0;

            // ── Ledger Entry 1: Fixed salary payout ──────────────────────────
            if ($regularSalaryPayout > 0) {
                $ledgerId1 = $this->model->insertLedgerEntry([
                    'gym_id'           => $gymId,
                    'branch_id'        => $branchId,
                    'transaction_type' => 'OUTFLOW',
                    'category'         => 'PAYROLL',
                    'amount'           => $regularSalaryPayout,
                    'reference_table'  => 'payroll_runs',
                    'reference_id'     => $payrollId,
                    'payment_method'   => $paymentMethod
                ]);
                $ledgerEntries[] = [
                    'ledger_id'   => $ledgerId1,
                    'category'    => 'PAYROLL',
                    'description' => "Staff Base Salary & Bonus - {$payPeriodLabel}",
                    'amount'      => number_format($regularSalaryPayout, 2, '.', '')
                ];
            }

            // ── Ledger Entry 2: PT Commission payout (conditional) ───────────
            if ($includePtComm && $trainerProfileId) {
                // Re-query actual UNPAID sum at disbursement time to ensure accuracy
                $actualCommAmount = $this->model->getUnpaidCommissionsSum($trainerProfileId);

                if ($actualCommAmount > 0) {
                    // Lock all UNPAID commissions under this payroll run
                    $commLockedCount = $this->model->markTrainerCommissionsPaid($trainerProfileId, $payrollId);

                    $ledgerId2 = $this->model->insertLedgerEntry([
                        'gym_id'           => $gymId,
                        'branch_id'        => $branchId,
                        'transaction_type' => 'OUTFLOW',
                        'category'         => 'PAYROLL',
                        'amount'           => $actualCommAmount,
                        'reference_table'  => 'payroll_runs',
                        'reference_id'     => $payrollId,
                        'payment_method'   => $paymentMethod
                    ]);
                    $ledgerEntries[] = [
                        'ledger_id'   => $ledgerId2,
                        'category'    => 'PAYROLL',
                        'description' => "Trainer PT Package Commissions - {$payPeriodLabel}",
                        'amount'      => number_format($actualCommAmount, 2, '.', '')
                    ];
                }
            }

            $totalDisbursed = round($regularSalaryPayout + $actualCommAmount, 2);

            // Update the payroll run to PAID
            $this->model->updatePayrollRunPaid($payrollId, $totalDisbursed, $bonus, $deductions);

            $this->model->commit();

            return [
                'status'  => 'success',
                'message' => 'Salary disbursed with split accounting entries successfully.',
                'data'    => [
                    'payroll_id'              => $payrollId,
                    'employee_id'             => (int)$payrollRun['employee_id'],
                    'employee_name'           => $payrollRun['employee_name'],
                    'total_disbursed'         => number_format($totalDisbursed, 2, '.', ''),
                    'payment_method'          => $paymentMethod,
                    'ledger_entries_created'  => $ledgerEntries,
                    'commissions_locked_count'=> $commLockedCount
                ]
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. GET /api/v1/admin/payrolls
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * List payroll runs with full filtering, summary KPI metrics, and pagination.
     */
    public function listPayrolls(string $accessToken, array $filters): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $result = $this->model->getPayrollRuns($filters);

            return [
                'status' => 'success',
                'data'   => $result
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }
}
