<?php

require_once __DIR__ . '/../repositories/TaxModel.php';
require_once __DIR__ . '/../repositories/model.php'; // For getUserProfileById
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class TaxWorkflow
{
    private TaxModel $taxModel;
    private Model $baseModel;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->taxModel = new TaxModel();
        $this->baseModel = new Model();
    }

    /**
     * Decode JWT and verify user belongs to allowed roles.
     */
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

    /**
     * Set the HTTP response code.
     */
    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    /**
     * List all tax rates.
     */
    public function listTaxRates(string $accessToken, array $filters): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];

            // Super admin can filter by gym_id
            if (in_array(strtoupper($callerProfile['role']), ['SUPER_ADMIN', 'SUPER-ADMIN']) && isset($filters['gym_id'])) {
                $gymId = (int)$filters['gym_id'];
            }

            $rates = $this->taxModel->getTaxRates($gymId, $filters);

            // Format decimal percentage and cast fields
            $formattedRates = array_map(function ($r) {
                return [
                    "tax_id"     => (int)$r['tax_id'],
                    "gym_id"     => (int)$r['gym_id'],
                    "tax_name"   => $r['tax_name'],
                    "percentage" => number_format((float)$r['percentage'], 2, '.', ''),
                    "applies_to" => $r['applies_to'],
                    "status"     => (int)$r['status']
                ];
            }, $rates);

            return [
                "status" => "success",
                "data"   => [
                    "tax_rates" => $formattedRates
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
     * Create a new tax rate.
     */
    public function createTaxRate(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $gymId = isset($data['gym_id']) ? (int)$data['gym_id'] : (int)$callerProfile['gym_id'];

            // Validation
            if (empty($data['tax_name'])) {
                throw new Exception("Tax name is required (e.g. CGST, SGST, VAT)", 400);
            }
            if (!isset($data['percentage']) || (float)$data['percentage'] < 0.0 || (float)$data['percentage'] > 100.0) {
                throw new Exception("Percentage is required and must be between 0.00 and 100.00", 400);
            }
            if (empty($data['applies_to']) || !in_array(strtoupper($data['applies_to']), ['PRODUCTS', 'SUBSCRIPTIONS', 'ALL'])) {
                throw new Exception("applies_to is required and must be 'PRODUCTS', 'SUBSCRIPTIONS', or 'ALL'", 400);
            }

            $taxRateData = [
                'gym_id'     => $gymId,
                'tax_name'   => trim($data['tax_name']),
                'percentage' => (float)$data['percentage'],
                'applies_to' => strtoupper($data['applies_to']),
                'status'     => isset($data['status']) ? (int)$data['status'] : 1
            ];

            $taxId = $this->taxModel->createTaxRate($taxRateData);

            $this->setResponseCode(201);
            return [
                "status"  => "success",
                "message" => "Tax rate configured successfully.",
                "data"    => [
                    "tax_id"     => $taxId,
                    "gym_id"     => $gymId,
                    "tax_name"   => $taxRateData['tax_name'],
                    "percentage" => number_format($taxRateData['percentage'], 2, '.', ''),
                    "applies_to" => $taxRateData['applies_to'],
                    "status"     => $taxRateData['status']
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
     * Update an existing tax rate.
     */
    public function updateTaxRate(string $accessToken, int $taxId, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $existing = $this->taxModel->getTaxRateById($taxId);
            if (!$existing) {
                throw new Exception("Tax rate configuration not found", 404);
            }

            // Auth check: verify ownership
            if (!in_array(strtoupper($callerProfile['role']), ['SUPER_ADMIN', 'SUPER-ADMIN'])) {
                if ((int)$existing['gym_id'] !== (int)$callerProfile['gym_id']) {
                    throw new Exception("Access denied. You cannot modify configuration of other gyms.", 403);
                }
            }

            // Validation updates
            $updates = [];
            if (isset($data['tax_name'])) {
                $updates['tax_name'] = trim($data['tax_name']);
            }
            if (isset($data['percentage'])) {
                $pct = (float)$data['percentage'];
                if ($pct < 0.0 || $pct > 100.0) {
                    throw new Exception("Percentage must be between 0.00 and 100.00", 400);
                }
                $updates['percentage'] = $pct;
            }
            if (isset($data['applies_to'])) {
                $app = strtoupper(trim($data['applies_to']));
                if (!in_array($app, ['PRODUCTS', 'SUBSCRIPTIONS', 'ALL'])) {
                    throw new Exception("applies_to must be 'PRODUCTS', 'SUBSCRIPTIONS', or 'ALL'", 400);
                }
                $updates['applies_to'] = $app;
            }
            if (isset($data['status'])) {
                $updates['status'] = (int)$data['status'];
            }

            if (empty($updates)) {
                throw new Exception("No fields to update provided", 400);
            }

            $this->taxModel->updateTaxRate($taxId, $updates);

            return [
                "status"  => "success",
                "message" => "Tax rate configuration updated successfully.",
                "data"    => array_merge($existing, $updates, [
                    "tax_id" => $taxId,
                    "gym_id" => (int)$existing['gym_id']
                ])
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
     * Deactivate a tax rate.
     */
    public function deleteTaxRate(string $accessToken, int $taxId): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $existing = $this->taxModel->getTaxRateById($taxId);
            if (!$existing) {
                throw new Exception("Tax rate configuration not found", 404);
            }

            // Auth check: verify ownership
            if (!in_array(strtoupper($callerProfile['role']), ['SUPER_ADMIN', 'SUPER-ADMIN'])) {
                if ((int)$existing['gym_id'] !== (int)$callerProfile['gym_id']) {
                    throw new Exception("Access denied. You cannot delete configuration of other gyms.", 403);
                }
            }

            // Perform soft delete
            $this->taxModel->deleteTaxRate($taxId);

            return [
                "status"  => "success",
                "message" => "Tax rate configuration deactivated successfully."
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
}
