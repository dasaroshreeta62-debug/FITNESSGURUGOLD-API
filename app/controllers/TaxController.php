<?php

require_once __DIR__ . '/../services/TaxWorkflow.php';

class TaxController
{
    private TaxWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new TaxWorkflow();
    }

    /**
     * Get bearer token from Authorization header.
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
     * Get request body payload.
     */
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
     * GET /api/v1/admin/tax-rates
     */
    public function listTaxRates(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listTaxRates($token, $_GET);
        echo json_encode($response);
    }

    /**
     * POST /api/v1/admin/tax-rates
     */
    public function createTaxRate(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->createTaxRate($token, $input);
        echo json_encode($response);
    }

    /**
     * PUT /api/v1/admin/tax-rates/{id}
     */
    public function updateTaxRate(int $taxId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->updateTaxRate($token, $taxId, $input);
        echo json_encode($response);
    }

    /**
     * DELETE /api/v1/admin/tax-rates/{id}
     */
    public function deleteTaxRate(int $taxId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->deleteTaxRate($token, $taxId);
        echo json_encode($response);
    }
}
