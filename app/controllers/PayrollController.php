<?php

require_once __DIR__ . '/../services/PayrollWorkflow.php';

class PayrollController
{
    private PayrollWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new PayrollWorkflow();
    }

    private function getBearerToken(): string|false
    {
        $headers = getallheaders();
        if (empty($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode([
                'status'  => 'error',
                'message' => 'Authorization token missing'
            ]);
            return false;
        }
        return str_replace('Bearer ', '', $headers['Authorization']);
    }

    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents('php://input'), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            parse_str(file_get_contents('php://input'), $input);
        }
        return is_array($input) ? $input : [];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/v1/admin/trainer-commissions
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * View and audit all PT trainer commissions with filters and pagination.
     */
    public function getTrainerCommissions(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $filters = [
            'status'     => $_GET['status']     ?? null,
            'time_frame' => $_GET['time_frame']  ?? null,
            'month'      => $_GET['month']       ?? null,
            'year'       => $_GET['year']        ?? null,
            'trainer_id' => $_GET['trainer_id']  ?? null,
            'branch_id'  => $_GET['branch_id']   ?? null,
            'page'       => $_GET['page']        ?? 1,
            'limit'      => $_GET['limit']       ?? 20
        ];

        $response = $this->workflow->getTrainerCommissions($token, $filters);
        echo json_encode($response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /api/v1/admin/trainer-commissions/{commission_id}/pay-early
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Manually disburse an UNPAID commission off-cycle (no payroll run).
     */
    public function payCommissionEarly(int $commissionId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input    = $this->getRequestInput();
        $response = $this->workflow->payCommissionEarly($token, $commissionId, $input);
        echo json_encode($response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /api/v1/jobs/payroll/generate-monthly-drafts
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Cron / admin trigger: generate DRAFT payroll rows for all active employees.
     */
    public function generateMonthlyDrafts(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input    = $this->getRequestInput();
        $response = $this->workflow->generateMonthlyDrafts($token, $input);
        echo json_encode($response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /api/v1/admin/payroll/{payroll_id}/disburse
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Approve and disburse a DRAFT payroll run with split ledger accounting.
     */
    public function disbursePayroll(int $payrollId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input    = $this->getRequestInput();
        $response = $this->workflow->disbursePayroll($token, $payrollId, $input);
        echo json_encode($response);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/v1/admin/payrolls
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * List all payroll runs with filtering, KPI summary metrics, and pagination.
     */
    public function listPayrolls(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $filters = [
            'status'               => $_GET['status']               ?? null,
            'time_frame'           => $_GET['time_frame']           ?? null,
            'pay_month'            => $_GET['pay_month']            ?? null,
            'pay_year'             => $_GET['pay_year']             ?? null,
            'employee_id'          => $_GET['employee_id']          ?? null,
            'role'                 => $_GET['role']                 ?? null,
            'branch_id'            => $_GET['branch_id']            ?? null,
            'includes_commission'  => $_GET['includes_commission']  ?? null,
            'page'                 => $_GET['page']                 ?? 1,
            'limit'                => $_GET['limit']                ?? 20
        ];

        $response = $this->workflow->listPayrolls($token, $filters);
        echo json_encode($response);
    }
}
