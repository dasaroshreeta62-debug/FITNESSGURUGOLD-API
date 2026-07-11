<?php

require_once __DIR__ . '/../config/database.php';

class TaxModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    /**
     * Get tax rates for a gym.
     */
    public function getTaxRates(int $gymId, array $filters = []): array
    {
        $sql = "SELECT * FROM tax_rates WHERE gym_id = :gym_id";
        $params = ['gym_id' => $gymId];

        if (isset($filters['applies_to']) && $filters['applies_to'] !== '') {
            $sql .= " AND applies_to = :applies_to";
            $params['applies_to'] = strtoupper(trim($filters['applies_to']));
        }

        if (isset($filters['status']) && $filters['status'] !== '') {
            $sql .= " AND status = :status";
            $params['status'] = (int)$filters['status'];
        }

        $sql .= " ORDER BY tax_id DESC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Fetch a single tax rate by ID.
     */
    public function getTaxRateById(int $taxId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM tax_rates WHERE tax_id = :id LIMIT 1");
        $stmt->execute(['id' => $taxId]);
        $rate = $stmt->fetch(PDO::FETCH_ASSOC);
        return $rate ?: null;
    }

    /**
     * Create a new tax rate config.
     */
    public function createTaxRate(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO tax_rates (
                gym_id,
                tax_name,
                percentage,
                applies_to,
                status
            ) VALUES (
                :gym_id,
                :tax_name,
                :percentage,
                :applies_to,
                :status
            )
        ");

        $stmt->execute([
            'gym_id'     => (int)$data['gym_id'],
            'tax_name'   => trim($data['tax_name']),
            'percentage' => (float)$data['percentage'],
            'applies_to' => strtoupper(trim($data['applies_to'])),
            'status'     => isset($data['status']) ? (int)$data['status'] : 1
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Update an existing tax rate config.
     */
    public function updateTaxRate(int $taxId, array $data): bool
    {
        $fields = [];
        $params = [':tax_id' => $taxId];

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

        $sql = "UPDATE tax_rates SET " . implode(', ', $fields) . " WHERE tax_id = :tax_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    /**
     * Soft delete/deactivate a tax rate config.
     */
    public function deleteTaxRate(int $taxId): bool
    {
        $stmt = $this->db->prepare("UPDATE tax_rates SET status = 0 WHERE tax_id = :id");
        return $stmt->execute(['id' => $taxId]);
    }
}
