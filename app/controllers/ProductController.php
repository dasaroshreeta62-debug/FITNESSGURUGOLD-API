<?php

require_once __DIR__ . '/../services/ProductWorkflow.php';

class ProductController
{
    private ProductWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new ProductWorkflow();
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
     * Get request body payload (JSON / Form Data / x-www-form-urlencoded).
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
     * GET /api/v1/admin/products
     */
    public function listAdminProducts(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listAdminProducts($token, $_GET);
        echo json_encode($response);
    }

    /**
     * POST /api/v1/admin/products
     */
    public function createProduct(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->createProduct($token, $input);
        echo json_encode($response);
    }

    /**
     * POST /api/v1/admin/inventory/restock
     */
    public function restockInventory(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->restockInventory($token, $input);
        echo json_encode($response);
    }

    /**
     * POST /api/v1/admin/store/sell
     */
    public function sellProduct(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->sellProduct($token, $input);
        echo json_encode($response);
    }

    /**
     * GET /api/v1/member/products
     */
    public function listMemberProducts(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->listMemberProducts($token, $_GET);
        echo json_encode($response);
    }
}
