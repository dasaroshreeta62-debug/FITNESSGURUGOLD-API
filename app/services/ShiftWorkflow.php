<?php

require_once __DIR__ . '/../repositories/ShiftModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class ShiftWorkflow
{
    private ShiftModel $model;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';
    private const ALLOWED_SHIFT_TYPES = ['Morning', 'Afternoon', 'Evening', 'Night', 'FullDay'];

    public function __construct()
    {
        $this->model = new ShiftModel();
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
     * SAPI-aware response header helper.
     */
    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    /* ========================================================================= */
    /* ========================= GYM SHIFTS WORKFLOWS ========================== */
    /* ========================================================================= */

    /**
     * List all gym shifts with slots. Admin, Trainer.
     */
    public function listShifts(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER']);

            $shifts = $this->model->getAllShifts($filters);
            return ["status" => "success", "data" => $shifts];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get single gym shift details with slots. Admin, Trainer.
     */
    public function getShiftDetails(string $accessToken, int $shiftId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER']);

            $shift = $this->model->getShiftById($shiftId);
            if (!$shift) {
                throw new Exception("Gym shift not found", 404);
            }

            return ["status" => "success", "data" => $shift];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Create a new gym shift with optional inline PT slots. Admin only.
     */
    public function createShift(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);
            $adminUserId = (int)$decoded->sub;

            // Required fields validation
            $required = ['shift_name', 'start_time', 'end_time'];
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    throw new Exception("Field '$field' is required", 400);
                }
            }

            $shiftType = !empty($data['shift_type']) ? ucfirst(strtolower(trim($data['shift_type']))) : 'FullDay';
            if (!in_array($shiftType, self::ALLOWED_SHIFT_TYPES)) {
                throw new Exception("Invalid shift_type. Allowed types: " . implode(', ', self::ALLOWED_SHIFT_TYPES), 400);
            }

            // Resolve gym_id & branch_id
            $gymId = isset($data['gym_id']) ? (int)$data['gym_id'] : null;
            $branchId = isset($data['branch_id']) ? (int)$data['branch_id'] : null;

            if (!$gymId || !$branchId) {
                $gymBranch = $this->model->getUserGymBranch($adminUserId);
                if ($gymBranch) {
                    $gymId = $gymId ?: $gymBranch['gym_id'];
                    $branchId = $branchId ?: $gymBranch['branch_id'];
                } else {
                    $gymId = $gymId ?: 1;
                    $branchId = $branchId ?: 1;
                }
            }

            $this->model->beginTransaction();

            $shiftData = [
                'gym_id'        => $gymId,
                'branch_id'     => $branchId,
                'shift_name'    => $data['shift_name'],
                'shift_type'    => $shiftType,
                'start_time'    => trim($data['start_time']),
                'end_time'      => trim($data['end_time']),
                'grace_minutes' => isset($data['grace_minutes']) ? (int)$data['grace_minutes'] : 10,
                'auto_checkout' => isset($data['auto_checkout']) ? (int)$data['auto_checkout'] : 1,
                'status'        => isset($data['status']) ? (int)$data['status'] : 1
            ];

            $shiftId = $this->model->createShift($shiftData);

            // Create inline PT slots if provided
            if (isset($data['slots']) && is_array($data['slots'])) {
                foreach ($data['slots'] as $slotItem) {
                    if (!empty($slotItem['slot_name']) && !empty($slotItem['start_time']) && !empty($slotItem['end_time'])) {
                        $this->model->createSlot([
                            'shift_id'   => $shiftId,
                            'slot_name'  => $slotItem['slot_name'],
                            'start_time' => $slotItem['start_time'],
                            'end_time'   => $slotItem['end_time']
                        ]);
                    }
                }
            }

            $this->model->commit();

            return [
                "status"   => "success",
                "message"  => "Gym shift created successfully",
                "shift_id" => $shiftId
            ];

        } catch (\Throwable $e) {
            $this->model->rollBack();
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Update an existing gym shift. Admin only.
     */
    public function updateShift(string $accessToken, int $shiftId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (!$this->model->shiftExists($shiftId)) {
                throw new Exception("Gym shift not found", 404);
            }

            if (!empty($data['shift_type'])) {
                $shiftType = ucfirst(strtolower(trim($data['shift_type'])));
                if (!in_array($shiftType, self::ALLOWED_SHIFT_TYPES)) {
                    throw new Exception("Invalid shift_type. Allowed types: " . implode(', ', self::ALLOWED_SHIFT_TYPES), 400);
                }
                $data['shift_type'] = $shiftType;
            }

            $this->model->updateShift($shiftId, $data);

            return [
                "status"   => "success",
                "message"  => "Gym shift updated successfully",
                "shift_id" => $shiftId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Deactivate a gym shift. Admin only.
     */
    public function deleteShift(string $accessToken, int $shiftId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (!$this->model->shiftExists($shiftId)) {
                throw new Exception("Gym shift not found", 404);
            }

            $this->model->deleteShift($shiftId);

            return [
                "status"   => "success",
                "message"  => "Gym shift deactivated successfully",
                "shift_id" => $shiftId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /* ========================================================================= */
    /* ========================= GYM PT SLOTS WORKFLOWS ======================== */
    /* ========================================================================= */

    /**
     * List all PT slots. Admin, Trainer.
     */
    public function listSlots(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER']);

            $slots = $this->model->getAllSlots($filters);
            return ["status" => "success", "data" => $slots];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get single PT slot details. Admin, Trainer.
     */
    public function getSlotDetails(string $accessToken, int $slotId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'TRAINER']);

            $slot = $this->model->getSlotById($slotId);
            if (!$slot) {
                throw new Exception("PT slot not found", 404);
            }

            return ["status" => "success", "data" => $slot];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Create a new PT slot under a shift. Admin only.
     */
    public function createSlot(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $required = ['shift_id', 'slot_name', 'start_time', 'end_time'];
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    throw new Exception("Field '$field' is required", 400);
                }
            }

            $shiftId = (int)$data['shift_id'];
            if (!$this->model->shiftExists($shiftId)) {
                throw new Exception("Gym shift with ID $shiftId does not exist", 404);
            }

            $slotId = $this->model->createSlot([
                'shift_id'   => $shiftId,
                'slot_name'  => $data['slot_name'],
                'start_time' => trim($data['start_time']),
                'end_time'   => trim($data['end_time'])
            ]);

            return [
                "status"  => "success",
                "message" => "PT slot created successfully",
                "slot_id" => $slotId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Update an existing PT slot. Admin only.
     */
    public function updateSlot(string $accessToken, int $slotId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getSlotById($slotId);
            if (!$existing) {
                throw new Exception("PT slot not found", 404);
            }

            if (!empty($data['shift_id'])) {
                $shiftId = (int)$data['shift_id'];
                if (!$this->model->shiftExists($shiftId)) {
                    throw new Exception("Gym shift with ID $shiftId does not exist", 404);
                }
            }

            $this->model->updateSlot($slotId, $data);

            return [
                "status"  => "success",
                "message" => "PT slot updated successfully",
                "slot_id" => $slotId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Delete a PT slot. Admin only.
     */
    public function deleteSlot(string $accessToken, int $slotId): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $existing = $this->model->getSlotById($slotId);
            if (!$existing) {
                throw new Exception("PT slot not found", 404);
            }

            $this->model->deleteSlot($slotId);

            return [
                "status"  => "success",
                "message" => "PT slot deleted successfully",
                "slot_id" => $slotId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}
