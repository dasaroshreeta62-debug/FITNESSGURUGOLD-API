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

    /**
     * Action M3: Report Individual Trainer Absence (Member)
     */
    public function reportTrainerAbsence(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->reportTrainerAbsence($token, $input);
        echo json_encode($response);
    }

    /**
     * Action M4: Contest No-Show Claim (Member)
     */
    public function disputeNoShow(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->disputeNoShow($token, $input);
        echo json_encode($response);
    }

    /**
     * Action T2: Mutual Absence Release (Trainer)
     */
    public function releaseSession(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->releaseSession($token, $input);
        echo json_encode($response);
    }

    /**
     * Action T3: Flag Client Individual Absence (Trainer)
     */
    public function flagNoShow(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->flagNoShow($token, $input);
        echo json_encode($response);
    }

    /**
     * Action A1: Resolve Dispute in Favor of Trainer (Admin)
     */
    public function resolveDisputeTrainer(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->resolveDisputeTrainer($token, $input);
        echo json_encode($response);
    }

    /**
     * Action A2: Resolve Dispute in Favor of Member (Admin)
     */
    public function resolveDisputeMember(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->resolveDisputeMember($token, $input);
        echo json_encode($response);
    }

    /**
     * Nightly System Evaluation Endpoint (Admin)
     */
    public function nightlyEvaluation(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $input = $this->getRequestInput();
        $response = $this->workflow->nightlyEvaluation($token, $input);
        echo json_encode($response);
    }

    /**
     * API: Get Trainer's Own Weekly Template Availability
     */
    public function getWeeklyTemplate(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getWeeklyTemplate($token);
        echo json_encode($response);
    }

    /**
     * API: Get Trainers and their active client assignment capacities (for Admin dropdown)
     */
    public function getTrainersCapacity(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getTrainersCapacity($token);
        echo json_encode($response);
    }

    /**
     * API: Get PT Dashboard Stats (Admin)
     */
    public function getDashboardStats(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDashboardStats($token);
        echo json_encode($response);
    }

    /**
     * API: Get PT Subscriptions only (Admin dashboard)
     */
    public function getPtSubscriptions(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        $filters = [
            'status'    => isset($_GET['status']) && $_GET['status'] !== '' ? $_GET['status'] : null,
            'gym_id'    => $_GET['gym_id'] ?? null,
            'branch_id' => $_GET['branch_id'] ?? null,
            'user_id'   => $_GET['user_id'] ?? null,
            'plan_id'   => $_GET['plan_id'] ?? null
        ];

        $response = $this->workflow->getPtSubscriptions($token, $filters);
        echo json_encode($response);
    }

    /**
     * API: Get Filtered PT Sessions (Admin)
     */
    public function getSessions(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        
        $filters = [
            'status'     => $_GET['status'] ?? null,
            'trainer_id' => $_GET['trainer_id'] ?? null,
            'member_id'  => $_GET['member_id'] ?? null,
            'start_date' => $_GET['start_date'] ?? null,
            'end_date'   => $_GET['end_date'] ?? null
        ];

        $response = $this->workflow->getSessions($token, $filters);
        echo json_encode($response);
    }

    /**
     * API: Get Disputed PT Sessions (Admin)
     */
    public function getDisputes(): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;
        $response = $this->workflow->getDisputes($token);
        echo json_encode($response);
    }
}

