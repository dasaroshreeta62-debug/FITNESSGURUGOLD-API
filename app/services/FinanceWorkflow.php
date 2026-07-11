<?php

require_once __DIR__ . '/../repositories/FinanceModel.php';
require_once __DIR__ . '/../repositories/model.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class FinanceWorkflow
{
    private FinanceModel $model;
    private Model $baseModel;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->model = new FinanceModel();
        $this->baseModel = new Model();
    }

    private function verifyRole(string $accessToken, array $allowedRoles): object
    {
        try {
            $decoded = JWT::decode($accessToken, new Key(self::JWT_SECRET, 'HS256'));
        } catch (\Throwable $e) {
            throw new Exception("Invalid or expired token", 401);
        }

        $role = str_replace(['_', '-'], '', strtoupper($decoded->role ?? ''));
        $allowedNormalized = array_map(function ($r) {
            return str_replace(['_', '-'], '', strtoupper($r));
        }, $allowedRoles);

        if (!in_array($role, $allowedNormalized)) {
            throw new Exception("Access denied. Authorized role required.", 403);
        }
        return $decoded;
    }

    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    /**
     * GET /api/v1/invoices/{invoice_id}
     */
    public function getInvoiceDetails(string $accessToken, int $invoiceId): array
    {
        try {
            // Retrieve caller context
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'MEMBER']);
            $callerUserId = (int)$decoded->sub;
            $callerRole = str_replace(['_', '-'], '', strtoupper($decoded->role ?? ''));

            $details = $this->model->getInvoiceDetails($invoiceId);
            if (!$details) {
                throw new Exception("Invoice not found", 404);
            }

            $invoice = $details['invoice'];

            // Gatekeeper ownership rule for members
            if ($callerRole === 'MEMBER') {
                if ((int)$invoice['user_id'] !== $callerUserId) {
                    throw new Exception("Access denied. You cannot read invoices belonging to other members.", 403);
                }
            }

            // Decode invoice and line items tax_breakdown JSON
            $invoice['tax_breakdown'] = json_decode($invoice['tax_breakdown'], true) ?: new stdClass();
            
            $formattedItems = [];
            foreach ($details['items'] as $item) {
                $item['tax_breakdown'] = json_decode($item['tax_breakdown'], true) ?: new stdClass();
                $formattedItems[] = $item;
            }

            return [
                "status" => "success",
                "data"   => [
                    "invoice"      => $invoice,
                    "line_items"   => $formattedItems,
                    "transactions" => $details['payments']
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * POST /api/v1/promos/validate
     */
    public function validatePromoCode(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'MEMBER']);

            if (empty($data['code']) || empty($data['item_type']) || !isset($data['cart_amount'])) {
                throw new Exception("code, item_type, and cart_amount are required", 400);
            }

            $code = trim($data['code']);
            $itemType = strtoupper(trim($data['item_type'])); // SUBSCRIPTION or PRODUCT or PT_PACKAGE
            $referenceId = isset($data['reference_id']) ? (int)$data['reference_id'] : null;
            $cartAmount = (float)$data['cart_amount'];

            $promo = $this->model->getPromoCode($code);
            if (!$promo) {
                throw new Exception("Invalid, expired, or deactivated promotional code", 404);
            }

            // Usage limits check
            if ($promo['max_uses'] !== null && (int)$promo['times_used'] >= (int)$promo['max_uses']) {
                throw new Exception("Promotional code usage limit has been reached", 400);
            }

            // Category match validation
            $appliesOn = strtoupper($promo['applicable_on']);
            $isValid = false;

            if ($appliesOn === 'ALL') {
                $isValid = true;
            } elseif ($appliesOn === 'SUBSCRIPTIONS' && $itemType === 'SUBSCRIPTION') {
                $isValid = true;
            } elseif ($appliesOn === 'PT_ONLY' && $itemType === 'PT_PACKAGE') {
                $isValid = true;
            } elseif ($appliesOn === 'PRODUCTS' && $itemType === 'PRODUCT') {
                $isValid = true;
            } elseif ($appliesOn === 'SPECIFIC_PLAN' && $itemType === 'SUBSCRIPTION' && $referenceId !== null && (int)$promo['applicable_item_id'] === $referenceId) {
                $isValid = true;
            } elseif ($appliesOn === 'SPECIFIC_PRODUCT' && $itemType === 'PRODUCT' && $referenceId !== null && (int)$promo['applicable_item_id'] === $referenceId) {
                $isValid = true;
            }

            if (!$isValid) {
                throw new Exception("Promotional code is not applicable for this item selection", 400);
            }

            // Math calculations
            $discountVal = (float)$promo['discount_value'];
            $discountAmount = 0.00;

            if ($promo['discount_type'] === 'PERCENTAGE') {
                $discountAmount = round($cartAmount * ($discountVal / 100.0), 2);
            } else {
                $discountAmount = round($discountVal, 2);
            }

            if ($discountAmount > $cartAmount) {
                $discountAmount = $cartAmount;
            }

            $finalPayable = round($cartAmount - $discountAmount, 2);

            return [
                "status" => "success",
                "data"   => [
                    "code"            => $promo['code'],
                    "discount_type"   => $promo['discount_type'],
                    "discount_value"  => $discountVal,
                    "discount_amount" => $discountAmount,
                    "final_payable"   => $finalPayable
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * POST /api/v1/admin/finance/refund
     */
    public function refundInvoice(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);

            if (empty($data['invoice_id'])) {
                throw new Exception("invoice_id is required", 400);
            }

            $invoiceId = (int)$data['invoice_id'];
            $reason = trim($data['reason'] ?? 'Accidental double billing / Admin override');

            $this->model->beginTransaction();

            $this->model->refundInvoiceTransaction($invoiceId, $reason);

            $this->model->commit();

            return [
                "status"  => "success",
                "message" => "Invoice cancelled, payment refunded, trainer commission voided, and services deactivated successfully."
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }
}
