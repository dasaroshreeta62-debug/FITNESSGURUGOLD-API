<?php

require_once __DIR__ . '/../config/database.php';

class ProductModel
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

    /**
     * Get products matching filters.
     */
    public function getProducts(int $gymId, int $branchId, array $filters = [], bool $isAdmin = false): array
    {
        $sql = "SELECT * FROM gym_products WHERE gym_id = :gym_id AND branch_id = :branch_id";
        $params = [
            'gym_id' => $gymId,
            'branch_id' => $branchId
        ];

        if (!$isAdmin) {
            $sql .= " AND status = 1 AND stock_quantity > 0";
        }

        if (isset($filters['category']) && $filters['category'] !== '') {
            $sql .= " AND category = :category";
            $params['category'] = strtoupper(trim($filters['category']));
        }

        if ($isAdmin && isset($filters['low_stock']) && ($filters['low_stock'] === true || $filters['low_stock'] === 'true')) {
            $sql .= " AND stock_quantity <= low_stock_alert";
        }

        $sql .= " ORDER BY product_id DESC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Get count of products matching filters (useful for admin total summary).
     */
    public function getProductsCount(int $gymId, int $branchId, array $filters = [], bool $isAdmin = false): int
    {
        $sql = "SELECT COUNT(*) FROM gym_products WHERE gym_id = :gym_id AND branch_id = :branch_id";
        $params = [
            'gym_id' => $gymId,
            'branch_id' => $branchId
        ];

        if (!$isAdmin) {
            $sql .= " AND status = 1 AND stock_quantity > 0";
        }

        if (isset($filters['category']) && $filters['category'] !== '') {
            $sql .= " AND category = :category";
            $params['category'] = strtoupper(trim($filters['category']));
        }

        if ($isAdmin && isset($filters['low_stock']) && ($filters['low_stock'] === true || $filters['low_stock'] === 'true')) {
            $sql .= " AND stock_quantity <= low_stock_alert";
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }

    /**
     * Get single product details by product_id.
     */
    public function getProductById(int $productId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM gym_products WHERE product_id = :id LIMIT 1");
        $stmt->execute(['id' => $productId]);
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        return $product ?: null;
    }

    /**
     * Create a new product catalog item.
     */
    public function createProduct(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO gym_products (
                gym_id,
                branch_id,
                product_name,
                sku,
                category,
                cost_price,
                sale_price,
                stock_quantity,
                low_stock_alert,
                product_picture_url,
                status,
                createdDate,
                createdTime
            ) VALUES (
                :gym_id,
                :branch_id,
                :product_name,
                :sku,
                :category,
                :cost_price,
                :sale_price,
                :stock_quantity,
                :low_stock_alert,
                :product_picture_url,
                :status,
                CURDATE(),
                CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id'              => (int)$data['gym_id'],
            'branch_id'           => (int)$data['branch_id'],
            'product_name'        => trim($data['product_name']),
            'sku'                 => isset($data['sku']) ? trim($data['sku']) : null,
            'category'            => strtoupper(trim($data['category'])),
            'cost_price'          => (float)$data['cost_price'],
            'sale_price'          => (float)$data['sale_price'],
            'stock_quantity'      => (int)($data['initial_stock'] ?? $data['stock_quantity'] ?? 0),
            'low_stock_alert'     => (int)($data['low_stock_alert'] ?? 5),
            'product_picture_url' => isset($data['product_picture_url']) ? trim($data['product_picture_url']) : (isset($data['product_photo_url']) ? trim($data['product_photo_url']) : null),
            'status'              => isset($data['status']) ? (int)$data['status'] : 1
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Update product details (e.g. stock, cost_price, sale_price).
     */
    public function updateProduct(int $productId, array $data): bool
    {
        $fields = [];
        $params = [':product_id' => $productId];

        foreach ($data as $key => $value) {
            $fields[] = "$key = :$key";
            if ($value === null) {
                $params[":$key"] = null;
            } elseif (is_int($value)) {
                $params[":$key"] = (int)$value;
            } elseif (is_float($value)) {
                $params[":$key"] = (float)$value;
            } else {
                $params[":$key"] = (string)$value;
            }
        }

        $sql = "UPDATE gym_products 
                SET " . implode(', ', $fields) . ", 
                    updatedDate = CURDATE(), 
                    updatedTime = CURTIME() 
                WHERE product_id = :product_id";

        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    /**
     * Create a purchase order.
     */
    public function createPurchaseOrder(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO purchase_orders (
                gym_id,
                branch_id,
                supplier_name,
                supplier_invoice_ref,
                total_amount,
                status,
                created_at,
                updated_at
            ) VALUES (
                :gym_id,
                :branch_id,
                :supplier_name,
                :supplier_invoice_ref,
                :total_amount,
                :status,
                NOW(),
                NOW()
            )
        ");

        $stmt->execute([
            'gym_id'               => (int)$data['gym_id'],
            'branch_id'            => (int)$data['branch_id'],
            'supplier_name'        => trim($data['supplier_name']),
            'supplier_invoice_ref' => isset($data['supplier_invoice_ref']) ? trim($data['supplier_invoice_ref']) : null,
            'total_amount'         => (float)$data['total_amount'],
            'status'               => $data['status'] ?? 'PENDING'
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create a purchase order item.
     */
    public function createPurchaseOrderItem(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO purchase_order_items (
                po_id,
                product_id,
                quantity_bought,
                unit_cost,
                total_cost
            ) VALUES (
                :po_id,
                :product_id,
                :quantity_bought,
                :unit_cost,
                :total_cost
            )
        ");

        $stmt->execute([
            'po_id'           => (int)$data['po_id'],
            'product_id'      => (int)$data['product_id'],
            'quantity_bought' => (int)$data['quantity_bought'],
            'unit_cost'       => (float)$data['unit_cost'],
            'total_cost'      => (float)$data['total_cost']
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create an invoice.
     */
    public function createInvoice(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO invoices (
                user_id,
                invoice_number,
                total_amount,
                tax_amount,
                tax_breakdown,
                final_amount,
                status,
                issued_at,
                due_date
            ) VALUES (
                :user_id,
                :invoice_number,
                :total_amount,
                :tax_amount,
                :tax_breakdown,
                :final_amount,
                :status,
                NOW(),
                CURDATE()
            )
        ");

        $stmt->execute([
            'user_id'        => (int)($data['user_id'] ?? 0),
            'invoice_number' => $data['invoice_number'],
            'total_amount'   => (float)$data['total_amount'],
            'tax_amount'     => (float)($data['tax_amount'] ?? 0.0),
            'tax_breakdown'  => isset($data['tax_breakdown']) ? (is_array($data['tax_breakdown']) ? json_encode($data['tax_breakdown']) : $data['tax_breakdown']) : null,
            'final_amount'   => (float)$data['final_amount'],
            'status'         => $data['status'] ?? 'UNPAID'
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create an invoice item.
     */
    public function createInvoiceItem(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO invoice_items (
                invoice_id,
                item_type,
                reference_id,
                item_name,
                quantity,
                unit_price,
                tax_percentage,
                tax_amount,
                tax_breakdown,
                total_price
            ) VALUES (
                :invoice_id,
                'PRODUCT',
                :reference_id,
                :item_name,
                :quantity,
                :unit_price,
                :tax_percentage,
                :tax_amount,
                :tax_breakdown,
                :total_price
            )
        ");

        $stmt->execute([
            'invoice_id'     => (int)$data['invoice_id'],
            'reference_id'   => (int)$data['reference_id'], // product_id
            'item_name'      => trim($data['item_name']),
            'quantity'       => (int)($data['quantity'] ?? 1),
            'unit_price'     => (float)$data['unit_price'],
            'tax_percentage' => (float)($data['tax_percentage'] ?? 0.0),
            'tax_amount'     => (float)($data['tax_amount'] ?? 0.0),
            'tax_breakdown'  => isset($data['tax_breakdown']) ? (is_array($data['tax_breakdown']) ? json_encode($data['tax_breakdown']) : $data['tax_breakdown']) : null,
            'total_price'    => (float)$data['total_price']
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create a payment transaction.
     */
    public function createPaymentTransaction(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO payment_transactions (
                gym_id,
                branch_id,
                invoice_id,
                paid_by_user_id,
                amount,
                payment_mode,
                payment_status,
                transaction_ref,
                payment_date,
                status,
                createdDate,
                createdTime
            ) VALUES (
                :gym_id,
                :branch_id,
                :invoice_id,
                :paid_by_user_id,
                :amount,
                :payment_mode,
                :payment_status,
                :transaction_ref,
                CURDATE(),
                1,
                CURDATE(),
                CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id'          => (int)$data['gym_id'],
            'branch_id'       => (int)$data['branch_id'],
            'invoice_id'      => (int)$data['invoice_id'],
            'paid_by_user_id' => isset($data['paid_by_user_id']) && (int)$data['paid_by_user_id'] > 0 ? (int)$data['paid_by_user_id'] : null,
            'amount'          => (float)$data['amount'],
            'payment_mode'    => trim($data['payment_mode']),
            'payment_status'  => $data['payment_status'] ?? 'PENDING',
            'transaction_ref' => isset($data['transaction_ref']) ? trim($data['transaction_ref']) : null
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Create a financial ledger entry.
     */
    public function createFinancialLedgerEntry(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO financial_ledger (
                gym_id,
                branch_id,
                transaction_type,
                category,
                amount,
                reference_table,
                reference_id,
                payment_method,
                created_at
            ) VALUES (
                :gym_id,
                :branch_id,
                :transaction_type,
                :category,
                :amount,
                :reference_table,
                :reference_id,
                :payment_method,
                NOW()
            )
        ");

        $stmt->execute([
            'gym_id'           => (int)$data['gym_id'],
            'branch_id'        => (int)$data['branch_id'],
            'transaction_type' => strtoupper(trim($data['transaction_type'])), // INFLOW / OUTFLOW
            'category'         => strtoupper(trim($data['category'])), // REVENUE / COGS
            'amount'           => (float)$data['amount'],
            'reference_table'  => trim($data['reference_table']),
            'reference_id'     => (int)$data['reference_id'],
            'payment_method'   => strtoupper(trim($data['payment_method'])) // CASH, CARD, BANK_TRANSFER, UPI, SYSTEM_AUTO
        ]);

        return (int)$this->db->lastInsertId();
    }
}
