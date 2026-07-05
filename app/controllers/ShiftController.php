
<?php

require_once __DIR__ . '/../services/ShiftWorkflow.php';

class ShiftController
{
    private ShiftWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new ShiftWorkflow();
    }

    /**
     * Retrieve the Bearer Token from HTTP request headers.
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
     * Get JSON or url-encoded request body inputs.
     */
    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            return [];
        }
        return $input;
    }

    /* ========================================================================= */
    /* ========================= GYM SHIFTS ==================================== */
    /* ========================================================================= */

    /**
     * GET /api/admin/shifts
     */
    public function listShifts(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->listShifts($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/shifts/(\d+)
     */
    public function getShiftDetails(int $shiftId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getShiftDetails($token, $shiftId);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/shifts
     */
    public function createShift(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->createShift($token, $input);
        echo json_encode($response);
    }

    /**
     * PUT /api/admin/shifts/(\d+)
     */
    public function updateShift(int $shiftId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->updateShift($token, $shiftId, $input);
        echo json_encode($response);
    }

    /**
     * DELETE /api/admin/shifts/(\d+)
     */
    public function deleteShift(int $shiftId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->deleteShift($token, $shiftId);
        echo json_encode($response);
    }

    /* ========================================================================= */
    /* ========================= GYM PT SLOTS ================================== */
    /* ========================================================================= */

    /**
     * GET /api/admin/pt-slots
     */
    public function listSlots(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->listSlots($token, $_GET);
        echo json_encode($response);
    }

    /**
     * GET /api/admin/pt-slots/(\d+)
     */
    public function getSlotDetails(int $slotId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->getSlotDetails($token, $slotId);
        echo json_encode($response);
    }

    /**
     * POST /api/admin/pt-slots
     */
    public function createSlot(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->createSlot($token, $input);
        echo json_encode($response);
    }

    /**
     * PUT /api/admin/pt-slots/(\d+)
     */
    public function updateSlot(int $slotId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $input = $this->getRequestInput();
        $response = $this->workflow->updateSlot($token, $slotId, $input);
        echo json_encode($response);
    }

    /**
     * DELETE /api/admin/pt-slots/(\d+)
     */
    public function deleteSlot(int $slotId): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $response = $this->workflow->deleteSlot($token, $slotId);
        echo json_encode($response);
    }
}
