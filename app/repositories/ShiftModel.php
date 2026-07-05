<?php

require_once __DIR__ . '/../config/database.php';

class ShiftModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
    }

    /* ========================================================================= */
    /* ========================= GYM SHIFTS ==================================== */
    /* ========================================================================= */

    /**
     * Get all gym shifts matching optional filters, with attached PT slots.
     */
    public function getAllShifts(array $filters = []): array
    {
        $sql = "SELECT * FROM gym_shifts WHERE 1=1";
        $params = [];

        if (isset($filters['status']) && $filters['status'] !== '') {
            $sql .= " AND status = :status";
            $params['status'] = (int)$filters['status'];
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND gym_id = :gym_id";
            $params['gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        if (!empty($filters['shift_type'])) {
            $sql .= " AND shift_type = :shift_type";
            $params['shift_type'] = $filters['shift_type'];
        }

        $sql .= " ORDER BY shift_id ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $shifts = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($shifts as &$shift) {
            $shift['shift_id'] = (int)$shift['shift_id'];
            $shift['gym_id'] = (int)$shift['gym_id'];
            $shift['branch_id'] = (int)$shift['branch_id'];
            $shift['grace_minutes'] = (int)$shift['grace_minutes'];
            $shift['auto_checkout'] = (int)$shift['auto_checkout'];
            $shift['status'] = (int)$shift['status'];
            $shift['slots'] = $this->getSlotsByShiftId($shift['shift_id']);
        }

        return $shifts;
    }

    /**
     * Get single gym shift by shift_id, with attached PT slots.
     */
    public function getShiftById(int $shiftId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM gym_shifts WHERE shift_id = :id LIMIT 1");
        $stmt->execute(['id' => $shiftId]);
        $shift = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$shift) {
            return null;
        }

        $shift['shift_id'] = (int)$shift['shift_id'];
        $shift['gym_id'] = (int)$shift['gym_id'];
        $shift['branch_id'] = (int)$shift['branch_id'];
        $shift['grace_minutes'] = (int)$shift['grace_minutes'];
        $shift['auto_checkout'] = (int)$shift['auto_checkout'];
        $shift['status'] = (int)$shift['status'];
        $shift['slots'] = $this->getSlotsByShiftId($shiftId);

        return $shift;
    }

    /**
     * Check if a shift exists by ID.
     */
    public function shiftExists(int $shiftId): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM gym_shifts WHERE shift_id = :id");
        $stmt->execute(['id' => $shiftId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    /**
     * Create a new gym shift.
     */
    public function createShift(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO gym_shifts (
                gym_id, branch_id, shift_name, shift_type, start_time, end_time,
                grace_minutes, auto_checkout, status, createdDate, createdTime
            ) VALUES (
                :gym_id, :branch_id, :shift_name, :shift_type, :start_time, :end_time,
                :grace_minutes, :auto_checkout, :status, CURDATE(), CURTIME()
            )
        ");

        $stmt->execute([
            'gym_id'        => $data['gym_id'],
            'branch_id'     => $data['branch_id'],
            'shift_name'    => trim($data['shift_name']),
            'shift_type'    => $data['shift_type'] ?? 'FullDay',
            'start_time'    => $data['start_time'],
            'end_time'      => $data['end_time'],
            'grace_minutes' => isset($data['grace_minutes']) ? (int)$data['grace_minutes'] : 10,
            'auto_checkout' => isset($data['auto_checkout']) ? (int)$data['auto_checkout'] : 1,
            'status'        => isset($data['status']) ? (int)$data['status'] : 1
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Update an existing gym shift.
     */
    public function updateShift(int $shiftId, array $data): bool
    {
        $fields = [];
        $params = ['shift_id' => $shiftId];

        if (isset($data['shift_name'])) {
            $fields[] = "shift_name = :shift_name";
            $params['shift_name'] = trim($data['shift_name']);
        }
        if (isset($data['shift_type'])) {
            $fields[] = "shift_type = :shift_type";
            $params['shift_type'] = $data['shift_type'];
        }
        if (isset($data['start_time'])) {
            $fields[] = "start_time = :start_time";
            $params['start_time'] = $data['start_time'];
        }
        if (isset($data['end_time'])) {
            $fields[] = "end_time = :end_time";
            $params['end_time'] = $data['end_time'];
        }
        if (isset($data['grace_minutes'])) {
            $fields[] = "grace_minutes = :grace_minutes";
            $params['grace_minutes'] = (int)$data['grace_minutes'];
        }
        if (isset($data['auto_checkout'])) {
            $fields[] = "auto_checkout = :auto_checkout";
            $params['auto_checkout'] = (int)$data['auto_checkout'];
        }
        if (isset($data['status'])) {
            $fields[] = "status = :status";
            $params['status'] = (int)$data['status'];
        }

        if (empty($fields)) {
            return true;
        }

        $fields[] = "updatedDate = CURDATE()";
        $fields[] = "updatedTime = CURTIME()";

        $sql = "UPDATE gym_shifts SET " . implode(', ', $fields) . " WHERE shift_id = :shift_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    /**
     * Soft delete/deactivate a shift.
     */
    public function deleteShift(int $shiftId): bool
    {
        $stmt = $this->db->prepare("UPDATE gym_shifts SET status = 0, updatedDate = CURDATE(), updatedTime = CURTIME() WHERE shift_id = :id");
        return $stmt->execute(['id' => $shiftId]);
    }

    /* ========================================================================= */
    /* ========================= GYM PT SLOTS ================================== */
    /* ========================================================================= */

    /**
     * Get PT slots for a specific shift_id.
     */
    public function getSlotsByShiftId(int $shiftId): array
    {
        $stmt = $this->db->prepare("SELECT * FROM gym_pt_slots WHERE shift_id = :shift_id ORDER BY start_time ASC");
        $stmt->execute(['shift_id' => $shiftId]);
        $slots = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($slots as &$slot) {
            $slot['slot_id'] = (int)$slot['slot_id'];
            $slot['shift_id'] = (int)$slot['shift_id'];
        }

        return $slots;
    }

    /**
     * Get all PT slots across all shifts with parent shift details.
     */
    public function getAllSlots(array $filters = []): array
    {
        $sql = "
            SELECT 
                s.*,
                gs.shift_name,
                gs.shift_type,
                gs.gym_id,
                gs.branch_id
            FROM gym_pt_slots s
            JOIN gym_shifts gs ON gs.shift_id = s.shift_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['shift_id'])) {
            $sql .= " AND s.shift_id = :shift_id";
            $params['shift_id'] = (int)$filters['shift_id'];
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND gs.gym_id = :gym_id";
            $params['gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND gs.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        $sql .= " ORDER BY s.shift_id ASC, s.start_time ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $slots = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($slots as &$slot) {
            $slot['slot_id'] = (int)$slot['slot_id'];
            $slot['shift_id'] = (int)$slot['shift_id'];
            $slot['gym_id'] = (int)$slot['gym_id'];
            $slot['branch_id'] = (int)$slot['branch_id'];
        }

        return $slots;
    }

    /**
     * Get single PT slot details by slot_id.
     */
    public function getSlotById(int $slotId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT 
                s.*,
                gs.shift_name,
                gs.shift_type,
                gs.gym_id,
                gs.branch_id
            FROM gym_pt_slots s
            JOIN gym_shifts gs ON gs.shift_id = s.shift_id
            WHERE s.slot_id = :id LIMIT 1
        ");
        $stmt->execute(['id' => $slotId]);
        $slot = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$slot) {
            return null;
        }

        $slot['slot_id'] = (int)$slot['slot_id'];
        $slot['shift_id'] = (int)$slot['shift_id'];
        $slot['gym_id'] = (int)$slot['gym_id'];
        $slot['branch_id'] = (int)$slot['branch_id'];

        return $slot;
    }

    /**
     * Create a new PT slot.
     */
    public function createSlot(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO gym_pt_slots (shift_id, slot_name, start_time, end_time)
            VALUES (:shift_id, :slot_name, :start_time, :end_time)
        ");

        $stmt->execute([
            'shift_id'   => (int)$data['shift_id'],
            'slot_name'  => trim($data['slot_name']),
            'start_time' => $data['start_time'],
            'end_time'   => $data['end_time']
        ]);

        return (int)$this->db->lastInsertId();
    }

    /**
     * Update an existing PT slot.
     */
    public function updateSlot(int $slotId, array $data): bool
    {
        $fields = [];
        $params = ['slot_id' => $slotId];

        if (isset($data['shift_id'])) {
            $fields[] = "shift_id = :shift_id";
            $params['shift_id'] = (int)$data['shift_id'];
        }
        if (isset($data['slot_name'])) {
            $fields[] = "slot_name = :slot_name";
            $params['slot_name'] = trim($data['slot_name']);
        }
        if (isset($data['start_time'])) {
            $fields[] = "start_time = :start_time";
            $params['start_time'] = $data['start_time'];
        }
        if (isset($data['end_time'])) {
            $fields[] = "end_time = :end_time";
            $params['end_time'] = $data['end_time'];
        }

        if (empty($fields)) {
            return true;
        }

        $sql = "UPDATE gym_pt_slots SET " . implode(', ', $fields) . " WHERE slot_id = :slot_id";
        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params);
    }

    /**
     * Delete a PT slot by slot_id.
     */
    public function deleteSlot(int $slotId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM gym_pt_slots WHERE slot_id = :id");
        return $stmt->execute(['id' => $slotId]);
    }

    /**
     * Resolve user gym_id and branch_id.
     */
    public function getUserGymBranch(int $userId): ?array
    {
        $stmt = $this->db->prepare("SELECT gym_id, branch_id FROM users WHERE user_id = :id LIMIT 1");
        $stmt->execute(['id' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row && $row['gym_id'] && $row['branch_id']) {
            return [
                'gym_id'    => (int)$row['gym_id'],
                'branch_id' => (int)$row['branch_id']
            ];
        }
        return null;
    }

    /**
     * Transaction Helpers
     */
    public function beginTransaction(): void
    {
        if (!$this->db->inTransaction()) {
            $this->db->beginTransaction();
        }
    }

    public function commit(): void
    {
        if ($this->db->inTransaction()) {
            $this->db->commit();
        }
    }

    public function rollBack(): void
    {
        if ($this->db->inTransaction()) {
            $this->db->rollBack();
        }
    }
}
