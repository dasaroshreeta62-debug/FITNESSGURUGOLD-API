<?php

require_once __DIR__ . '/../services/FinanceWorkflow.php';

class FinanceController
{
    private FinanceWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new FinanceWorkflow();
    }

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

    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            parse_str(file_get_contents("php://input"), $input);
        }
        return is_array($input) ? $input : [];
    }

    /**
     * GET /api/v1/invoices/{invoice_id}
     */
    public function getInvoiceDetails(int $invoiceId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getInvoiceDetails($token, $invoiceId);
        echo json_encode($response);
    }

    /**
     * POST /api/v1/promos/validate
     */
    public function validatePromoCode(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->validatePromoCode($token, $input);
        echo json_encode($response);
    }

    /**
     * POST /api/v1/admin/finance/refund
     */
    public function refundInvoice(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->refundInvoice($token, $input);
        echo json_encode($response);
    }

    /**
     * GET /api/member/purchase-history
     */
    public function getMemberPurchaseHistory(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMemberPurchaseHistory($token);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/dashboard-kpis
     */
    public function getDashboardKpis(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDashboardKpis($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/dashboard/revenue-overview
     * GET /api/admin/revenue-overview
     */
    public function getRevenueOverview(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getRevenueOverview($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/dashboard/membership-status
     * GET /api/admin/membership-status
     */
    public function getMembershipStatus(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getMembershipStatus($token);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/finance/summary
     */
    public function getExecutiveSummary(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getExecutiveSummary($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/opex
     */
    public function getOpexLogs(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getOpexLogs($token, $_GET);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/opex/log
     */
    public function logOpex(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->logOpex($token, $input);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/opex/{id}/cancel
     */
    public function cancelOpex(int $opexId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->cancelOpex($token, $opexId, $input);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/finance/ledger
     */
    public function getLedgerLogs(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getLedgerLogs($token, $_GET);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/finance/ledger/adjust
     */
    public function logLedgerAdjustment(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->logLedgerAdjustment($token, $input);
        echo json_encode($response);
    }
}

