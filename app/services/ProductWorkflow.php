<?php

require_once __DIR__ . '/../repositories/ProductModel.php';
require_once __DIR__ . '/../repositories/model.php'; // For getUserProfileById
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class ProductWorkflow
{
    private ProductModel $productModel;
    private Model $baseModel;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->productModel = new ProductModel();
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
     * View stocks list for admin.
     */
    public function listAdminProducts(string $accessToken, array $filters): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;
            
            // Get user's gym and branch details
            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];
            $branchId = (int)$callerProfile['branch_id'];

            // Allow super-admin or admin to override via filters if passed
            if (in_array(strtoupper($callerProfile['role']), ['SUPER_ADMIN', 'SUPER-ADMIN'])) {
                if (isset($filters['gym_id'])) {
                    $gymId = (int)$filters['gym_id'];
                }
                if (isset($filters['branch_id'])) {
                    $branchId = (int)$filters['branch_id'];
                }
            }

            $count = $this->productModel->getProductsCount($gymId, $branchId, $filters, true);
            $products = $this->productModel->getProducts($gymId, $branchId, $filters, true);

            $formattedProducts = array_map(function ($p) {
                return [
                    "product_id"        => (int)$p['product_id'],
                    "product_name"      => $p['product_name'],
                    "category"          => $p['category'],
                    "sku"               => $p['sku'],
                    "cost_price"        => number_format((float)$p['cost_price'], 2, '.', ''),
                    "sale_price"        => number_format((float)$p['sale_price'], 2, '.', ''),
                    "stock_quantity"    => (int)$p['stock_quantity'],
                    "low_stock_alert"   => (int)$p['low_stock_alert'],
                    "is_low_stock"      => (int)$p['stock_quantity'] <= (int)$p['low_stock_alert'],
                    "product_photo_url" => $p['product_picture_url'] ?? '',
                    "status"            => (int)$p['status']
                ];
            }, $products);

            return [
                "status" => "success",
                "data" => [
                    "total_products" => $count,
                    "products"       => $formattedProducts
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
     * Add new product API.
     */
    public function createProduct(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            // Default to caller's gym and branch if not specified
            $gymId = isset($data['gym_id']) ? (int)$data['gym_id'] : (int)$callerProfile['gym_id'];
            $branchId = isset($data['branch_id']) ? (int)$data['branch_id'] : (int)$callerProfile['branch_id'];

            // Enforce required fields
            $required = ['product_name', 'sku', 'category', 'cost_price', 'sale_price'];
            foreach ($required as $field) {
                if (!isset($data[$field]) || trim((string)$data[$field]) === '') {
                    throw new Exception("Field '$field' is required", 400);
                }
            }

            $costPrice    = (float)$data['cost_price'];
            $salePrice    = (float)$data['sale_price'];
            $initialStock = isset($data['initial_stock']) ? (int)$data['initial_stock'] : 0;

            // Enforce sale_price > cost_price
            if ($salePrice <= $costPrice) {
                throw new Exception("Sale price must be strictly greater than cost price to prevent accidental negative profit margins.", 400);
            }

            $this->productModel->beginTransaction();

            $productData = array_merge($data, [
                'gym_id'    => $gymId,
                'branch_id' => $branchId
            ]);

            $productId = $this->productModel->createProduct($productData);

            if ($initialStock > 0) {
                $poAmount = $costPrice * $initialStock;
                
                // Create opening purchase order
                $poId = $this->productModel->createPurchaseOrder([
                    'gym_id'               => $gymId,
                    'branch_id'            => $branchId,
                    'supplier_name'        => isset($data['supplier_name']) ? trim($data['supplier_name']) : 'Opening Stock Catalog Creation',
                    'supplier_invoice_ref' => isset($data['supplier_invoice_ref']) ? trim($data['supplier_invoice_ref']) : 'OPENING-STOCK-INT-001',
                    'total_amount'         => $poAmount,
                    'status'               => 'RECEIVED'
                ]);

                // Create purchase order item
                $this->productModel->createPurchaseOrderItem([
                    'po_id'           => $poId,
                    'product_id'      => $productId,
                    'quantity_bought' => $initialStock,
                    'unit_cost'       => $costPrice,
                    'total_cost'      => $poAmount
                ]);

                // Record financial ledger outflow entry
                $this->productModel->createFinancialLedgerEntry([
                    'gym_id'           => $gymId,
                    'branch_id'        => $branchId,
                    'transaction_type' => 'OUTFLOW',
                    'category'         => 'COGS',
                    'amount'           => $poAmount,
                    'reference_table'  => 'purchase_orders',
                    'reference_id'     => $poId,
                    'payment_method'   => 'SYSTEM_AUTO'
                ]);
            }

            $this->productModel->commit();

            // Profit margin percentage = ((sale_price - cost_price) / sale_price) * 100
            $profitMargin = round((($salePrice - $costPrice) / $salePrice) * 100, 2);

            $this->setResponseCode(201);
            return [
                "status"  => "success",
                "message" => "New product created and opening stock ledger recorded successfully.",
                "data"    => [
                    "product_id"               => $productId,
                    "sku"                      => trim($data['sku']),
                    "stock_quantity"           => $initialStock,
                    "profit_margin_percentage" => $profitMargin
                ]
            ];

        } catch (\Throwable $e) {
            if (isset($this->productModel)) {
                try {
                    $this->productModel->rollBack();
                } catch (\Throwable $rollbackError) {
                    // Ignore rollback failures if transaction wasn't active
                }
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * Add restock details.
     */
    public function restockInventory(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];
            $branchId = (int)$callerProfile['branch_id'];

            // Validation
            if (empty($data['supplier_name'])) {
                throw new Exception("Supplier name is required", 400);
            }
            if (empty($data['items']) || !is_array($data['items'])) {
                throw new Exception("Restock items list is required", 400);
            }

            $this->productModel->beginTransaction();

            $totalAmount = 0.0;
            $itemsToProcess = [];

            // 1st pass: validate items and calculate total amount
            foreach ($data['items'] as $item) {
                if (empty($item['product_id'])) {
                    throw new Exception("Product ID is required for all restock items", 400);
                }
                if (!isset($item['quantity_bought']) || (int)$item['quantity_bought'] <= 0) {
                    throw new Exception("Quantity bought must be strictly positive", 400);
                }
                if (!isset($item['unit_cost']) || (float)$item['unit_cost'] < 0) {
                    throw new Exception("Unit cost must be non-negative", 400);
                }

                $productId = (int)$item['product_id'];
                $product = $this->productModel->getProductById($productId);
                if (!$product) {
                    throw new Exception("Product ID $productId not found in catalog", 404);
                }

                // If user specifies a new sale price, ensure it's > new cost price
                $newSalePrice = isset($item['update_sale_price']) ? (float)$item['update_sale_price'] : (float)$product['sale_price'];
                $newCostPrice = (float)$item['unit_cost'];
                if ($newSalePrice <= $newCostPrice) {
                    throw new Exception("Sale price must be strictly greater than cost price ($newCostPrice) for product ID $productId", 400);
                }

                $itemCost = $newCostPrice * (int)$item['quantity_bought'];
                $totalAmount += $itemCost;

                $itemsToProcess[] = [
                    'product'                => $product,
                    'quantity_bought'        => (int)$item['quantity_bought'],
                    'unit_cost'              => $newCostPrice,
                    'update_sale_price'      => $newSalePrice,
                    'update_low_stock_alert' => isset($item['update_low_stock_alert']) ? (int)$item['update_low_stock_alert'] : (int)$product['low_stock_alert']
                ];
            }

            // Create purchase order
            $poId = $this->productModel->createPurchaseOrder([
                'gym_id'               => $gymId,
                'branch_id'            => $branchId,
                'supplier_name'        => trim($data['supplier_name']),
                'supplier_invoice_ref' => $data['supplier_invoice_ref'] ?? null,
                'total_amount'         => $totalAmount,
                'status'               => 'RECEIVED'
            ]);

            $updatedProducts = [];

            // 2nd pass: apply database changes
            foreach ($itemsToProcess as $proc) {
                $product = $proc['product'];
                $productId = (int)$product['product_id'];
                $qty = $proc['quantity_bought'];
                $unitCost = $proc['unit_cost'];
                $salePrice = $proc['update_sale_price'];
                $lowAlert = $proc['update_low_stock_alert'];

                // Record purchase order item
                $this->productModel->createPurchaseOrderItem([
                    'po_id'           => $poId,
                    'product_id'      => $productId,
                    'quantity_bought' => $qty,
                    'unit_cost'       => $unitCost,
                    'total_cost'      => $unitCost * $qty
                ]);

                // Update product quantity and prices
                $newQty = (int)$product['stock_quantity'] + $qty;
                $this->productModel->updateProduct($productId, [
                    'stock_quantity'  => $newQty,
                    'cost_price'      => $unitCost,
                    'sale_price'      => $salePrice,
                    'low_stock_alert' => $lowAlert
                ]);

                $updatedProducts[] = [
                    "product_id"         => $productId,
                    "new_stock_quantity" => $newQty,
                    "new_cost_price"     => number_format($unitCost, 2, '.', ''),
                    "new_sale_price"     => number_format($salePrice, 2, '.', '')
                ];
            }

            // Record financial ledger COGS outflow entry
            $this->productModel->createFinancialLedgerEntry([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => 'OUTFLOW',
                'category'         => 'COGS',
                'amount'           => $totalAmount,
                'reference_table'  => 'purchase_orders',
                'reference_id'     => $poId,
                'payment_method'   => 'SYSTEM_AUTO'
            ]);

            $this->productModel->commit();

            $this->setResponseCode(201);
            return [
                "status"  => "success",
                "message" => "Restock completed and catalog pricing updated successfully.",
                "data"    => [
                    "po_id"            => $poId,
                    "total_amount"     => number_format($totalAmount, 2, '.', ''),
                    "updated_products" => $updatedProducts
                ]
            ];

        } catch (\Throwable $e) {
            if (isset($this->productModel)) {
                try {
                    $this->productModel->rollBack();
                } catch (\Throwable $rollbackError) {
                }
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * Record a product sale to a member (POS Desk transaction).
     */
    public function sellProduct(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];
            $branchId = (int)$callerProfile['branch_id'];

            // Validation
            if (empty($data['items']) || !is_array($data['items'])) {
                throw new Exception("Sale items list is required", 400);
            }
            $paymentMethod = $data['payment_method'] ?? 'UPI';

            // Resolve target member/user
            $targetUserId = isset($data['user_id']) ? (int)$data['user_id'] : 0;

            $this->productModel->beginTransaction();

            $itemsToProcess = [];
            $totalInvoiceInclusiveAmount = 0.0;
            $totalInvoiceTaxAmount = 0.0;

            // 1st pass: Validate stock & compute pricing/tax breakdown
            foreach ($data['items'] as $item) {
                if (empty($item['product_id'])) {
                    throw new Exception("Product ID is required for all sale items", 400);
                }
                $productId = (int)$item['product_id'];
                $quantity = isset($item['quantity']) ? (int)$item['quantity'] : 1;
                if ($quantity <= 0) {
                    throw new Exception("Sale quantity must be positive", 400);
                }

                $product = $this->productModel->getProductById($productId);
                if (!$product) {
                    throw new Exception("Product ID $productId not found in inventory catalog", 404);
                }

                // Verify stock availability
                $currentStock = (int)$product['stock_quantity'];
                if ($currentStock < $quantity) {
                    throw new Exception("Insufficient stock for product '{$product['product_name']}'. Requested: $quantity, Available: $currentStock", 400);
                }

                // Reverse-tax calculations (Assuming 18% GST inclusive pricing)
                // Inclusive unit price = sale_price
                $inclusiveUnitPrice = (float)$product['sale_price'];
                $totalInclusive = $inclusiveUnitPrice * $quantity;

                // Exclusive unit price = inclusive_price / 1.18
                $exclusiveUnitPrice = round($inclusiveUnitPrice / 1.18, 4);
                $totalExclusive = round($totalInclusive / 1.18, 2);

                // Tax amount
                $taxAmount = round($totalInclusive - $totalExclusive, 2);
                $cgstAmount = round($taxAmount / 2.0, 2);
                $sgstAmount = round($taxAmount - $cgstAmount, 2); // Exact balancing split

                $taxBreakdown = [
                    'cgst_rate'   => 9.00,
                    'cgst_amount' => $cgstAmount,
                    'sgst_rate'   => 9.00,
                    'sgst_amount' => $sgstAmount
                ];

                $totalInvoiceInclusiveAmount += $totalInclusive;
                $totalInvoiceTaxAmount       += $taxAmount;

                $itemsToProcess[] = [
                    'product'         => $product,
                    'quantity'        => $quantity,
                    'unit_price'      => $exclusiveUnitPrice,
                    'tax_amount'      => $taxAmount,
                    'tax_breakdown'   => $taxBreakdown,
                    'total_price'     => $totalInclusive // Storing total price inclusive or exclusive? Let's use inclusive for billing
                ];
            }

            // Generate invoice number
            $invoiceNumber = 'INV-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(4)));

            // Create Invoice
            $invoiceId = $this->productModel->createInvoice([
                'user_id'        => $targetUserId,
                'invoice_number' => $invoiceNumber,
                'total_amount'   => $totalInvoiceInclusiveAmount - $totalInvoiceTaxAmount, // Exclusive subtotal
                'tax_amount'     => $totalInvoiceTaxAmount,
                'tax_breakdown'  => [
                    'cgst_amount' => round($totalInvoiceTaxAmount / 2.0, 2),
                    'sgst_amount' => round($totalInvoiceTaxAmount / 2.0, 2)
                ],
                'final_amount'   => $totalInvoiceInclusiveAmount, // Inclusive total
                'status'         => 'PAID'
            ]);

            $lowStockWarnings = [];

            // 2nd pass: Update stock & write items
            foreach ($itemsToProcess as $proc) {
                $product = $proc['product'];
                $productId = (int)$product['product_id'];
                $qty = $proc['quantity'];

                // Insert invoice item
                $this->productModel->createInvoiceItem([
                    'invoice_id'     => $invoiceId,
                    'reference_id'   => $productId,
                    'item_name'      => $product['product_name'],
                    'quantity'       => $qty,
                    'unit_price'     => $proc['unit_price'],
                    'tax_percentage' => 18.00,
                    'tax_amount'     => $proc['tax_amount'],
                    'tax_breakdown'  => $proc['tax_breakdown'],
                    'total_price'    => $proc['total_price']
                ]);

                // Decrement stock
                $newStock = (int)$product['stock_quantity'] - $qty;
                $this->productModel->updateProduct($productId, [
                    'stock_quantity' => $newStock
                ]);

                // Check low stock warning trigger
                if ($newStock <= (int)$product['low_stock_alert']) {
                    $lowStockWarnings[] = [
                        "product_id"      => $productId,
                        "product_name"    => $product['product_name'],
                        "remaining_stock" => $newStock,
                        "alert_threshold" => (int)$product['low_stock_alert'],
                        "message"         => "Stock is below alert threshold! Please initiate a restock."
                    ];
                }
            }

            // Map payment mode and payment method for transaction / ledger tables
            // payment_transactions.payment_mode: enum('Cash','Card','UPI','Online')
            // financial_ledger.payment_method: enum('CASH','CARD','BANK_TRANSFER','UPI','SYSTEM_AUTO')
            $ptMode = 'UPI';
            $flMethod = 'UPI';

            $normPayMethod = strtoupper(trim($paymentMethod));
            if ($normPayMethod === 'CASH') {
                $ptMode = 'Cash';
                $flMethod = 'CASH';
            } elseif ($normPayMethod === 'CARD') {
                $ptMode = 'Card';
                $flMethod = 'CARD';
            } elseif ($normPayMethod === 'UPI') {
                $ptMode = 'UPI';
                $flMethod = 'UPI';
            } else {
                $ptMode = 'Online';
                $flMethod = 'BANK_TRANSFER';
            }

            // Create Payment Transaction
            $this->productModel->createPaymentTransaction([
                'gym_id'          => $gymId,
                'branch_id'       => $branchId,
                'invoice_id'      => $invoiceId,
                'paid_by_user_id' => $targetUserId,
                'amount'          => $totalInvoiceInclusiveAmount,
                'payment_mode'    => $ptMode,
                'payment_status'  => 'SUCCESS',
                'transaction_ref' => 'TXN-' . date('YmdHis') . '-' . rand(100, 999)
            ]);

            // Create Financial Ledger Entry (INFLOW)
            $this->productModel->createFinancialLedgerEntry([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => 'INFLOW',
                'category'         => 'REVENUE',
                'amount'           => $totalInvoiceInclusiveAmount,
                'reference_table'  => 'invoices',
                'reference_id'     => $invoiceId,
                'payment_method'   => $flMethod
            ]);

            $this->productModel->commit();

            $this->setResponseCode(201);
            return [
                "status"  => "success",
                "message" => "POS transaction completed successfully.",
                "data"    => [
                    "invoice_id"         => $invoiceId,
                    "final_amount"       => number_format($totalInvoiceInclusiveAmount, 2, '.', ''),
                    "payment_status"     => "SUCCESS",
                    "low_stock_warnings" => $lowStockWarnings
                ]
            ];

        } catch (\Throwable $e) {
            if (isset($this->productModel)) {
                try {
                    $this->productModel->rollBack();
                } catch (\Throwable $rollbackError) {
                }
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * View member available products.
     */
    public function listMemberProducts(string $accessToken, array $filters): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER', 'ADMIN', 'SUPER-ADMIN', 'TRAINER', 'GYM_ADMIN']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("User profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];
            $branchId = (int)$callerProfile['branch_id'];

            // Fetch active, in-stock products
            $products = $this->productModel->getProducts($gymId, $branchId, $filters, false);

            $formattedProducts = array_map(function ($p) {
                return [
                    "product_id"        => (int)$p['product_id'],
                    "product_name"      => $p['product_name'],
                    "category"          => $p['category'],
                    "price"             => number_format((float)$p['sale_price'], 2, '.', ''),
                    "product_photo_url" => $p['product_picture_url'] ?? '',
                    "stock_quantity"    => (int)$p['stock_quantity'],
                    "in_stock"          => (int)$p['stock_quantity'] > 0
                ];
            }, $products);

            return [
                "status" => "success",
                "data" => [
                    "products" => $formattedProducts
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
}
