<?php

require_once __DIR__ . '/../services/PersonalTrainingWorkflow.php';

class PersonalTrainingController
{
    private PersonalTrainingWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new PersonalTrainingWorkflow();
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
            parse_str(file_get_contents("php://input"), $input);
        }
        return is_array($input) ? $input : [];
    }

    /**
     * API 1: Manual Admin PT Purchase & Credit Provisioning
     */
    public function manualPurchase(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->manualPurchase($token, $input);
        echo json_encode($response);
    }

    /**
     * API 2: Balanced Trainer Assignment (Capacity Guardrail)
     */
    public function assignTrainer(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->assignTrainer($token, $input);
        echo json_encode($response);
    }

    /**
     * API 3: Set Baseline Weekly Repeating Layout
     */
    public function setWeeklyTemplate(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->setWeeklyTemplate($token, $input);
        echo json_encode($response);
    }

    /**
     * API 4: View Daily Assigned Booking Roster
     */
    public function getTrainerRoster(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $date = $_GET['date'] ?? null;
        $response = $this->workflow->getTrainerRoster($token, $date);
        echo json_encode($response);
    }

    /**
     * API 5: Fetch Available 1.5-Hour Blocks for Calendar View
     */
    public function getMemberAvailableSlots(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $date = $_GET['date'] ?? null;
        $response = $this->workflow->getMemberAvailableSlots($token, $date);
        echo json_encode($response);
    }

    /**
     * API 6: Claim and Book a Predefined PT Slot
     */
    public function bookSlot(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->bookSlot($token, $input);
        echo json_encode($response);
    }

    /**
     * API 7: Initiate Completion & Generate PIN Token
     */
    public function initiateSessionComplete(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->initiateSessionCompletion($token, $input);
        echo json_encode($response);
    }

    /**
     * API 8: Verify PIN and Finalize Ledger Transaction
     */
    public function verifySessionComplete(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->verifySessionCompletion($token, $input);
        echo json_encode($response);
    }

    /**
     * Helper API: Generate Schedule slots from Availability templates
     */
    public function generateSchedule(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->generateSchedule($token, $input);
        echo json_encode($response);
    }
}
