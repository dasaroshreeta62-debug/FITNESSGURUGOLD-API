<?php

require_once __DIR__ . '/../repositories/PersonalTrainingModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class PersonalTrainingWorkflow
{
    private PersonalTrainingModel $model;

    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';
    private const MAX_CLIENTS_PER_TRAINER = 15;

    public function __construct()
    {
        $this->model = new PersonalTrainingModel();
    }

    /**
     * Set HTTP response code if not running in CLI mode.
     */
    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
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
     * API 1: Manual Admin PT Purchase & Credit Provisioning
     */
    public function manualPurchase(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            // Validate inputs
            if (empty($data['user_id']) || empty($data['plan_id'])) {
                throw new Exception("user_id and plan_id are required", 400);
            }

            $userId = (int)$data['user_id'];
            $planId = (int)$data['plan_id'];
            $paymentMethod = $data['payment_method'] ?? 'CASH';

            // Verify user exists and get branch/gym details
            $user = $this->model->getUserById($userId);
            if (!$user) {
                throw new Exception("User not found", 404);
            }

            $gymId = (int)$user['gym_id'];
            $branchId = (int)$user['branch_id'];

            // Ensure member has a profile in users_profile
            $profileId = $this->model->getProfileIdByUserId($userId);
            if (!$profileId) {
                throw new Exception("Selected member does not have a profile in the users_profile directory", 400);
            }

            // 1. Gatekeeper check: Verify active base membership
            $activeBase = $this->model->getUserActiveBaseMembership($userId);
            if (!$activeBase) {
                throw new Exception("Action Blocked: Member does not have an active Base Membership", 403);
            }

            // Retrieve PT plan details
            $plan = $this->model->getMembershipPlanById($planId);
            if (!$plan || (int)$plan['status'] !== 1) {
                throw new Exception("Invalid or inactive membership plan", 404);
            }
            if ($plan['plan_type'] !== 'PT_UPGRADE') {
                throw new Exception("Selected plan is not a Personal Training Upgrade", 400);
            }

            $durationMonths = (int)($plan['duration_months'] ?: 1);

            // Determine Trainer ID (trainer_profile_id)
            $trainerInputId = isset($data['trainer_id']) ? (int)$data['trainer_id'] : 0;
            $trainerId = 0;
            if ($trainerInputId) {
                // Check if the input ID is directly a valid trainer_profile_id
                if ($this->model->getTrainerProfileById($trainerInputId)) {
                    $trainerId = $trainerInputId;
                } else {
                    // Otherwise, treat it as a trainer's user_id
                    $trainerId = $this->model->getTrainerProfileIdByUserId($trainerInputId);
                }
            } else {
                $trainerId = $this->model->getMemberActiveTrainerProfileId($profileId);
            }
            if (!$trainerId) {
                throw new Exception("Selected trainer does not have an active trainer profile", 400);
            }

            // Get plan entitlements
            $entitlements = $this->model->getPlanEntitlements($planId);
            if (empty($entitlements)) {
                throw new Exception("No entitlements configured for this plan", 400);
            }

            // 2. Fetch taxes & reverse tax math
            $taxRates = $this->model->getTaxRatesForGym($gymId, 'SUBSCRIPTIONS');
            if (empty($taxRates)) {
                $taxRates = [
                    ['tax_name' => 'CGST', 'percentage' => 9.00],
                    ['tax_name' => 'SGST', 'percentage' => 9.00]
                ];
            }

            $totalTaxRate = 0.0;
            foreach ($taxRates as $tr) {
                $totalTaxRate += (float)$tr['percentage'];
            }

            $inclusivePrice = (float)$plan['price'];
            $basePrice = round($inclusivePrice / (1 + ($totalTaxRate / 100)), 2);
            $totalTaxAmount = round($inclusivePrice - $basePrice, 2);

            $taxBreakdown = [];
            $accumulatedTax = 0.0;
            $countRates = count($taxRates);
            for ($i = 0; $i < $countRates; $i++) {
                $tr = $taxRates[$i];
                $ratePct = (float)$tr['percentage'];
                $rateName = trim($tr['tax_name']);
                
                if ($i === $countRates - 1) {
                    $rateAmount = round($totalTaxAmount - $accumulatedTax, 2);
                } else {
                    $rateAmount = round($inclusivePrice * ($ratePct / (100 + $totalTaxRate)), 2);
                    $accumulatedTax += $rateAmount;
                }
                
                $key = str_replace(['.', '-'], '_', strtoupper($rateName) . '_' . (int)$ratePct);
                $taxBreakdown[$key] = $rateAmount;
            }

            $this->model->beginTransaction();

            // 3. Write Financial Records
            $invoiceNumber = 'INV-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(4)));
            $invoiceId = $this->model->createInvoice([
                'user_id'        => $userId,
                'invoice_number' => $invoiceNumber,
                'total_amount'   => $basePrice,
                'tax_amount'     => $totalTaxAmount,
                'tax_breakdown'  => $taxBreakdown,
                'final_amount'   => $inclusivePrice,
                'status'         => 'PAID'
            ]);

            $this->model->createInvoiceItem([
                'invoice_id'     => $invoiceId,
                'item_type'      => 'PT_PACKAGE',
                'reference_id'   => $planId,
                'item_name'      => $plan['plan_name'],
                'quantity'       => 1,
                'unit_price'     => $basePrice,
                'tax_percentage' => $totalTaxRate,
                'tax_amount'     => $totalTaxAmount,
                'tax_breakdown'  => $taxBreakdown,
                'total_price'    => $inclusivePrice
            ]);

            $payMode = 'Online';
            $payMethod = strtoupper(trim($paymentMethod));
            if ($payMethod === 'CASH') $payMode = 'Cash';
            elseif ($payMethod === 'CARD') $payMode = 'Card';
            elseif ($payMethod === 'UPI') $payMode = 'UPI';

            $this->model->createPaymentTransaction([
                'gym_id'          => $gymId,
                'branch_id'       => $branchId,
                'invoice_id'      => $invoiceId,
                'paid_by_user_id' => $userId,
                'amount'          => $inclusivePrice,
                'payment_mode'    => $payMode,
                'payment_status'  => 'SUCCESS',
                'transaction_ref' => 'TXN-' . date('YmdHis') . '-' . rand(100, 999)
            ]);

            $flMethod = 'BANK_TRANSFER';
            if ($payMethod === 'CASH') $flMethod = 'CASH';
            elseif ($payMethod === 'CARD') $flMethod = 'CARD';
            elseif ($payMethod === 'UPI') $flMethod = 'UPI';

            $this->model->createFinancialLedgerEntry([
                'gym_id'           => $gymId,
                'branch_id'        => $branchId,
                'transaction_type' => 'INFLOW',
                'category'         => 'REVENUE',
                'amount'           => $inclusivePrice,
                'reference_table'  => 'invoices',
                'reference_id'     => $invoiceId,
                'payment_method'   => $flMethod
            ]);

            // 4. Trigger 70% Trainer Commission
            $commissionAmount = round($inclusivePrice * 0.70, 2);
            $this->model->createTrainerCommission([
                'gym_id'            => $gymId,
                'branch_id'         => $branchId,
                'trainer_id'        => $trainerId,
                'invoice_id'        => $invoiceId,
                'commission_amount' => $commissionAmount
            ]);

            // 5. Activate subscription record
            $startDate = date('Y-m-d');
            $endDate = date('Y-m-d', strtotime("+$durationMonths months"));

            $subId = $this->model->insertSubscription([
                'gym_id'     => $gymId,
                'branch_id'  => $branchId,
                'user_id'    => $userId,
                'plan_id'    => $planId,
                'start_date' => $startDate,
                'end_date'   => $endDate,
                'status'     => 1
            ]);

            // 6. Provision credits in client_wallet_credits
            foreach ($entitlements as $ent) {
                $qty = (int)$ent['quantity'];
                $validDays = (int)$ent['valid_days'];
                $expirationDate = date('Y-m-d', strtotime("+$validDays days"));
                
                $isUnlimited = ($ent['entitlement_type'] === 'GYM_ACCESS') ? 1 : 0;

                $this->model->insertClientWalletCredit([
                    'subscription_id'    => $subId,
                    'user_id'            => $userId,
                    'entitlement_type'   => $ent['entitlement_type'],
                    'is_unlimited'       => $isUnlimited,
                    'original_quantity'  => $qty,
                    'remaining_quantity' => $qty,
                    'expiration_date'    => $expirationDate,
                    'status'             => 1
                ]);
            }

            $this->model->commit();

            return [
                "status"          => "success",
                "message"         => "Manual PT purchase and credit provisioning completed successfully",
                "subscription_id" => $subId,
                "invoice_id"      => $invoiceId
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404, 409]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }


    /**
     * API 2: Balanced Trainer Assignment (Capacity Guardrail)
     */
    public function assignTrainer(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (empty($data['member_id']) || empty($data['trainer_id'])) {
                throw new Exception("member_id and trainer_id are required", 400);
            }

            $memberUserId = (int) $data['member_id'];
            $trainerUserId = (int) $data['trainer_id'];

            // Resolve trainer user ID to trainer_profile_id
            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Selected trainer does not have an active trainer profile", 404);
            }

            // Resolve member user ID to profile_id
            $memberProfileId = $this->model->getProfileIdByUserId($memberUserId);
            if (!$memberProfileId) {
                throw new Exception("Selected member does not have a profile configured", 404);
            }

            // Capacity check guardrail using trainer_profile_id
            $activeCount = $this->model->getTrainerActiveAssignmentsCount($trainerProfileId);
            if ($activeCount >= self::MAX_CLIENTS_PER_TRAINER) {
                throw new Exception("Trainer has reached maximum client assignment load", 400);
            }

            // Fetch trainer details to get gym_id and branch_id
            $trainerGymBranch = $this->model->getTrainerGymBranch($trainerProfileId);
            if (!$trainerGymBranch) {
                throw new Exception("Failed to retrieve gym/branch mapping for the trainer profile", 400);
            }

            $this->model->beginTransaction();

            // Soft delete previous primary assignments using member profile_id
            $this->model->deactivateMemberPrimaryAssignments($memberProfileId);

            // Create new assignment
            $assignmentId = $this->model->insertMemberTrainerAssignment([
                'gym_id' => $trainerGymBranch['gym_id'],
                'branch_id' => $trainerGymBranch['branch_id'],
                'member_id' => $memberProfileId,
                'trainer_id' => $trainerProfileId
            ]);

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "Trainer assigned successfully to client",
                "assignment_id" => $assignmentId
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404, 409]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * API 3: Set Baseline Weekly Repeating Layout
     */
    public function setWeeklyTemplate(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int) $decoded->sub;

            // Resolve trainer user ID to trainer_profile_id
            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Trainer profile not found in database", 404);
            }

            $rawList = $data['availability'] ?? $data['days'] ?? null;
            if (!is_array($rawList)) {
                throw new Exception("availability or days list is required", 400);
            }

            $availability = [];
            foreach ($rawList as $item) {
                $day = isset($item['day_of_week']) ? (int) $item['day_of_week'] : null;
                if (!$day || $day < 1 || $day > 7) {
                    throw new Exception("day_of_week must be between 1 (Monday) and 7 (Sunday)", 400);
                }

                if (isset($item['slots']) && is_array($item['slots'])) {
                    foreach ($item['slots'] as $sId) {
                        $availability[] = [
                            'day_of_week' => $day,
                            'slot_id' => (int) $sId
                        ];
                    }
                } elseif (isset($item['slot_id'])) {
                    $availability[] = [
                        'day_of_week' => $day,
                        'slot_id' => (int) $item['slot_id']
                    ];
                }
            }

            if (empty($availability)) {
                throw new Exception("No valid slot entries provided in template data", 400);
            }

            // Validate all slot IDs exist
            foreach ($availability as $item) {
                $slotId = $item['slot_id'];
                if (!$this->model->slotExists($slotId)) {
                    throw new Exception("slot_id $slotId does not exist in PT slots database", 400);
                }
            }

            $this->model->beginTransaction();

            // Clear old templates using trainer_profile_id
            $this->model->clearTrainerWeeklyAvailability($trainerProfileId);

            // Bulk insert new template grid entries using trainer_profile_id
            foreach ($availability as $item) {
                $this->model->insertTrainerWeeklyAvailability(
                    $trainerProfileId,
                    $item['day_of_week'],
                    $item['slot_id']
                );
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "Weekly recurring availability template saved successfully"
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404, 409]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * API 4: View Daily Assigned Booking Roster
     */
    public function getTrainerRoster(string $accessToken, ?string $date): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int) $decoded->sub;

            // Resolve trainer user ID to trainer_profile_id
            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Trainer profile not found in database", 404);
            }

            if (empty($date)) {
                $date = date('Y-m-d');
            }

            // Validate date format YYYY-MM-DD
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                throw new Exception("Date parameter must follow YYYY-MM-DD format", 400);
            }

            $roster = $this->model->getTrainerPtScheduleForDate($trainerProfileId, $date);

            return [
                "status" => "success",
                "message" => "Daily booking roster fetched successfully",
                "date" => $date,
                "count" => count($roster),
                "data" => $roster
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * API 5: Fetch Available 1.5-Hour Blocks for Calendar View
     */
    public function getMemberAvailableSlots(string $accessToken, ?string $date): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int) $decoded->sub;

            // Resolve member user ID to profile_id
            $memberProfileId = $this->model->getProfileIdByUserId($memberUserId);
            if (!$memberProfileId) {
                throw new Exception("Member profile not found in database", 404);
            }

            if (empty($date)) {
                $date = date('Y-m-d');
            }

            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                throw new Exception("Date parameter must follow YYYY-MM-DD format", 400);
            }

            // Retrieve assigned trainer_profile_id using member profile_id
            $trainerProfileId = $this->model->getMemberAssignedTrainer($memberProfileId);
            if (!$trainerProfileId) {
                throw new Exception("No personal trainer is currently assigned to this member", 400);
            }

            $slots = $this->model->getAvailablePtSlotsForTrainerAndDate($trainerProfileId, $date);

            return [
                "status" => "success",
                "message" => "Available personal training slots fetched successfully",
                "date" => $date,
                "trainer_id" => $trainerProfileId,
                "count" => count($slots),
                "data" => $slots
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * API 6: Claim and Book a Predefined PT Slot
     */
    public function bookSlot(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int) $decoded->sub;

            // Resolve member user ID to profile_id
            $memberProfileId = $this->model->getProfileIdByUserId($memberUserId);
            if (!$memberProfileId) {
                throw new Exception("Member profile not found in database", 404);
            }

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];

            // 1. Verify client possesses an active wallet credit (uses users.user_id)
            $credit = $this->model->getMemberActiveCredit($memberUserId, 'PT_1ON1');
            if (!$credit) {
                throw new Exception("No active PT credits available or credits have expired", 400);
            }
            $creditId = (int) $credit['credit_id'];

            // 2. Fetch the session details to get target date & availability status
            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Selected schedule slot does not exist", 404);
            }
            if ($session['session_status'] !== 'AVAILABLE') {
                throw new Exception("Selected slot has already been booked or is unavailable", 400);
            }

            $targetDate = $session['session_date'];

            // 3. Daily Limit Policy Check using member profile_id
            $activeBookingCount = $this->model->getMemberActiveBookingCountOnDate($memberProfileId, $targetDate);
            if ($activeBookingCount > 0) {
                throw new Exception("Daily booking allocation limit reached. One session allowed per day.", 400);
            }

            $this->model->beginTransaction();

            // 4. Perform atomic update lock storing member profile_id
            $success = $this->model->bookPtSlot($scheduleId, $memberProfileId, $creditId);
            if (!$success) {
                throw new Exception("Booking failed. The slot may have been booked by another user.", 400);
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "PT slot booked successfully",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * API 7: Initiate Completion & Generate PIN Token
     */
    public function initiateSessionComplete(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int) $decoded->sub;

            // Resolve trainer user ID to trainer_profile_id
            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Trainer profile not found in database", 404);
            }

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $workoutSummary = $data['workout_summary'] ?? '';

            // Fetch session
            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session || (int) $session['trainer_id'] !== $trainerProfileId) {
                throw new Exception("Session not found or not mapped to this trainer", 404);
            }

            if ($session['session_status'] !== 'PENDING') {
                throw new Exception("Only sessions in PENDING status can be completed", 400);
            }

            // Generate short-lived random 4-digit PIN (1000 - 9999)
            $pin = rand(1000, 9999);

            $this->model->beginTransaction();

            $success = $this->model->setVerificationPin($scheduleId, $trainerProfileId, $pin, $workoutSummary);
            if (!$success) {
                throw new Exception("Failed to set verification PIN", 500);
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "Completion handshake initiated successfully",
                "schedule_id" => $scheduleId,
                "verification_pin" => $pin
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * API 8: Verify PIN and Finalize Ledger Transaction
     */
    public function verifySessionCompletion(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER', 'TRAINER']);
            $userId = (int) $decoded->sub;
            $role = strtoupper($decoded->role);

            if (empty($data['schedule_id']) || !isset($data['entered_pin'])) {
                throw new Exception("schedule_id and entered_pin are required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $enteredPin = (int) $data['entered_pin'];

            // Fetch session details
            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Selected session does not exist", 404);
            }

            // Security check: ensure caller belongs to the booking
            if ($role === 'TRAINER') {
                $trainerProfileId = $this->model->getTrainerProfileIdByUserId($userId);
                if (!$trainerProfileId || (int) $session['trainer_id'] !== $trainerProfileId) {
                    throw new Exception("Access denied: You are not the trainer for this session", 403);
                }
            } else if ($role === 'MEMBER') {
                $memberProfileId = $this->model->getProfileIdByUserId($userId);
                if (!$memberProfileId || (int) $session['member_id'] !== $memberProfileId) {
                    throw new Exception("Access denied: You are not the member for this session", 403);
                }
            }

            if ($session['session_status'] !== 'PENDING') {
                throw new Exception("Only sessions in PENDING status can be verified", 400);
            }

            if ($session['verification_pin'] === null || (int) $session['verification_pin'] !== $enteredPin) {
                throw new Exception("Invalid or expired verification token submitted.", 400);
            }

            $creditId = (int) $session['credit_id'];
            if (!$creditId) {
                throw new Exception("No credit associated with this session booking", 400);
            }

            $this->model->beginTransaction();

            // A: Update schedule record status to ATTENDED
            $successStatus = $this->model->finalizeSessionStatus($scheduleId, $enteredPin);
            if (!$successStatus) {
                throw new Exception("Failed to finalize session status. Invalid PIN.", 400);
            }

            // B: Deduct credit from member wallet
            $successDeduct = $this->model->deductWalletCredit($creditId);
            if (!$successDeduct) {
                throw new Exception("Credit deduction failed. Wallet might have empty balance or expired.", 400);
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "PIN verified. Session attendance recorded and 1 credit deducted successfully.",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Admin Helper: Generate PT Schedule Slots from Trainer templates
     */
    public function generateSchedule(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (empty($data['trainer_id']) || empty($data['start_date']) || empty($data['end_date'])) {
                throw new Exception("trainer_id, start_date and end_date are required", 400);
            }

            $trainerUserId = (int) $data['trainer_id'];
            $startDateStr = $data['start_date'];
            $endDateStr = $data['end_date'];

            // Resolve trainer user ID to trainer_profile_id
            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Selected trainer does not have an active trainer profile", 404);
            }

            // Fetch trainer details to get gym_id and branch_id
            $trainerGymBranch = $this->model->getTrainerGymBranch($trainerProfileId);
            if (!$trainerGymBranch) {
                throw new Exception("Failed to retrieve gym/branch mapping for the trainer profile", 400);
            }

            $gymId = (int) $trainerGymBranch['gym_id'];
            $branchId = (int) $trainerGymBranch['branch_id'];

            $start = new DateTime($startDateStr);
            $end = new DateTime($endDateStr);
            $interval = new DateInterval('P1D');
            $period = new DatePeriod($start, $interval, $end->modify('+1 day')); // Inclusive of end date

            $createdCount = 0;

            $this->model->beginTransaction();

            foreach ($period as $dateObj) {
                $dateStr = $dateObj->format('Y-m-d');
                // day of week representation (N: 1 for Monday to 7 for Sunday)
                $dayOfWeek = (int) $dateObj->format('N');

                // Get weekly availability templates for this day of week
                $templates = $this->model->getTrainerTemplatesForDay($trainerProfileId, $dayOfWeek);

                foreach ($templates as $slotId) {
                    // Check if already created
                    if (!$this->model->scheduleItemExists($trainerProfileId, $dateStr, $slotId)) {
                        $this->model->insertScheduleItem([
                            'gym_id' => $gymId,
                            'branch_id' => $branchId,
                            'trainer_id' => $trainerProfileId,
                            'session_date' => $dateStr,
                            'slot_id' => $slotId
                        ]);
                        $createdCount++;
                    }
                }
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "PT Schedule slots generated successfully",
                "slots_created" => $createdCount
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /* ========================================================================= */
    /* ========================= LIFECYCLE ACTION WORKFLOWS ==================== */
    /* ========================================================================= */

    /**
     * Action M3: Report Individual Trainer Absence (Member)
     */
    public function reportTrainerAbsence(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int) $decoded->sub;

            $memberProfileId = $this->model->getProfileIdByUserId($memberUserId);
            if (!$memberProfileId) {
                throw new Exception("Member profile not found in database", 404);
            }

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Session not found", 404);
            }

            if ($session['session_status'] !== 'PENDING') {
                throw new Exception("Only PENDING sessions can be marked as trainer absent", 400);
            }

            $success = $this->model->reportTrainerAbsence($scheduleId, $memberProfileId);
            if (!$success) {
                throw new Exception("Failed to report trainer absence. Session may not belong to this member or is not in PENDING status.", 400);
            }

            return [
                "status" => "success",
                "message" => "Trainer absence reported successfully",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Action M4: Contest No-Show Claim / Dispute Trigger (Member)
     */
    public function disputeNoShow(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int) $decoded->sub;

            $memberProfileId = $this->model->getProfileIdByUserId($memberUserId);
            if (!$memberProfileId) {
                throw new Exception("Member profile not found in database", 404);
            }

            if (empty($data['schedule_id']) || empty($data['reason'])) {
                throw new Exception("schedule_id and reason are required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $counterReason = trim($data['reason']);

            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Session not found", 404);
            }

            if ($session['session_status'] !== 'MEMBER_NO_SHOW') {
                throw new Exception("Only MEMBER_NO_SHOW sessions can be disputed", 400);
            }

            $success = $this->model->disputeNoShow($scheduleId, $memberProfileId, $counterReason);
            if (!$success) {
                throw new Exception("Failed to lodge dispute. Session may not belong to this member or status is not MEMBER_NO_SHOW.", 400);
            }

            return [
                "status" => "success",
                "message" => "No-show claim disputed successfully. Case submitted for admin review.",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Action T2: Mutual Absence Release / Soft Cancel (Trainer)
     */
    public function releaseSession(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int) $decoded->sub;

            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Trainer profile not found in database", 404);
            }

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];

            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Session not found", 404);
            }

            if ($session['session_status'] !== 'PENDING') {
                throw new Exception("Only PENDING sessions can be released", 400);
            }

            $success = $this->model->releaseSession($scheduleId, $trainerProfileId);
            if (!$success) {
                throw new Exception("Failed to release session. Session may not belong to this trainer.", 400);
            }

            return [
                "status" => "success",
                "message" => "Session released successfully. Block is now AVAILABLE.",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Action T3: Flag Client Individual Absence / No-Show Claim (Trainer)
     */
    public function flagNoShow(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int) $decoded->sub;

            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Trainer profile not found in database", 404);
            }

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $trainerReason = !empty($data['reason']) ? trim($data['reason']) : 'Client did not show up for session';

            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Session not found", 404);
            }

            if ($session['session_status'] !== 'PENDING') {
                throw new Exception("Only PENDING sessions can be marked as MEMBER_NO_SHOW", 400);
            }

            $creditId = (int) $session['credit_id'];

            $this->model->beginTransaction();

            $success = $this->model->flagNoShow($scheduleId, $trainerProfileId, $trainerReason);
            if (!$success) {
                throw new Exception("Failed to flag client no-show", 400);
            }

            if ($creditId) {
                $this->model->deductWalletCredit($creditId);
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "Client no-show flagged successfully and session credit consumed.",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Action A1: Resolve Dispute in Favor of Trainer (Admin)
     */
    public function resolveDisputeTrainer(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Session not found", 404);
            }

            if ($session['session_status'] !== 'DISPUTED') {
                throw new Exception("Only DISPUTED sessions can be resolved", 400);
            }

            $success = $this->model->resolveDisputeTrainer($scheduleId);
            if (!$success) {
                throw new Exception("Failed to resolve dispute", 400);
            }

            return [
                "status" => "success",
                "message" => "Dispute resolved in favor of trainer. Status set to RESOLVED_BY_ADMIN.",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Action A2: Resolve Dispute in Favor of Member / Refund Credit (Admin)
     */
    public function resolveDisputeMember(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            if (empty($data['schedule_id'])) {
                throw new Exception("schedule_id is required", 400);
            }

            $scheduleId = (int) $data['schedule_id'];
            $session = $this->model->getPtScheduleItem($scheduleId);
            if (!$session) {
                throw new Exception("Session not found", 404);
            }

            if ($session['session_status'] !== 'DISPUTED') {
                throw new Exception("Only DISPUTED sessions can be resolved", 400);
            }

            $creditId = (int) $session['credit_id'];

            $this->model->beginTransaction();

            $success = $this->model->resolveDisputeMember($scheduleId);
            if (!$success) {
                throw new Exception("Failed to resolve dispute", 400);
            }

            if ($creditId) {
                $this->model->refundWalletCredit($creditId);
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "Dispute resolved in favor of member. Credit refunded and status set to RESOLVED_BY_ADMIN.",
                "schedule_id" => $scheduleId
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Nightly System Evaluation (11:59 PM cron trigger)
     */
    public function nightlyEvaluation(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            // Evaluation date defaults to today
            $evalDate = !empty($data['evaluation_date']) ? trim($data['evaluation_date']) : date('Y-m-d');

            // Find all PENDING slots where session_date < evalDate
            $sessions = $this->model->getUnresolvedPastSessions($evalDate);

            $mutualAbsenceCount = 0;
            $expiredUnclaimedCount = 0;

            $this->model->beginTransaction();

            foreach ($sessions as $session) {
                $scheduleId = (int) $session['schedule_id'];
                $creditId = (int) $session['credit_id'];

                $isPackageActive = false;
                if ($creditId > 0) {
                    $credit = $this->model->getWalletCredit($creditId);
                    if ($credit && (int) $credit['status'] === 1 && $credit['expiration_date'] >= $evalDate) {
                        $isPackageActive = true;
                    }
                }

                if ($isPackageActive) {
                    $status = 'MUTUAL_ABSENCE';
                    $mutualAbsenceCount++;
                } else {
                    $status = 'EXPIRED_UNCLAIMED';
                    $expiredUnclaimedCount++;
                }

                $this->model->updateSessionStatusAndClearPin($scheduleId, $status);
            }

            $this->model->commit();

            return [
                "status" => "success",
                "message" => "Nightly evaluation processed successfully",
                "evaluation_date" => $evalDate,
                "sessions_processed" => count($sessions),
                "mutual_absence_count" => $mutualAbsenceCount,
                "expired_unclaimed_count" => $expiredUnclaimedCount
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Retrieve the weekly template availability for the logged-in trainer.
     */
    public function getWeeklyTemplate(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['TRAINER']);
            $trainerUserId = (int) $decoded->sub;

            // Resolve trainer user ID to trainer_profile_id
            $trainerProfileId = $this->model->getTrainerProfileIdByUserId($trainerUserId);
            if (!$trainerProfileId) {
                throw new Exception("Trainer profile not found in database", 404);
            }

            $rawAvailability = $this->model->getTrainerWeeklyAvailability($trainerProfileId);

            // Group by day_of_week for clean calendar layout structure (1 = Monday, 7 = Sunday)
            $grouped = [
                1 => [],
                2 => [],
                3 => [],
                4 => [],
                5 => [],
                6 => [],
                7 => []
            ];

            foreach ($rawAvailability as $item) {
                $day = $item['day_of_week'];
                if (isset($grouped[$day])) {
                    $grouped[$day][] = [
                        'slot_id' => $item['slot_id'],
                        'slot_name' => $item['slot_name'],
                        'start_time' => $item['start_time'],
                        'end_time' => $item['end_time']
                    ];
                }
            }

            return [
                "status" => "success",
                "message" => "Weekly recurring template availability fetched successfully",
                "data" => $grouped
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get the active trainers and their assigned client counts (Admin capacity check).
     */
    public function getTrainersCapacity(string $accessToken): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $trainers = $this->model->getTrainersWithClientCount();

            return [
                "status" => "success",
                "message" => "Trainers list and client assignment capacities fetched successfully",
                "data" => $trainers
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get system-wide personal training metrics for admin dashboard.
     */
    public function getDashboardStats(string $accessToken): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $stats = $this->model->getPtDashboardMetrics();

            return [
                "status" => "success",
                "message" => "PT management dashboard statistics fetched successfully",
                "data" => $stats
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get a filterable list of all PT sessions in the system.
     */
    public function getSessions(string $accessToken, array $filters): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            // Validate date filters if passed
            if (!empty($filters['start_date']) && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $filters['start_date'])) {
                throw new Exception("start_date filter must be in YYYY-MM-DD format", 400);
            }
            if (!empty($filters['end_date']) && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $filters['end_date'])) {
                throw new Exception("end_date filter must be in YYYY-MM-DD format", 400);
            }

            $sessions = $this->model->getFilteredPtSessions($filters);

            return [
                "status" => "success",
                "message" => "PT sessions list fetched successfully",
                "count" => count($sessions),
                "data" => $sessions
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get all currently DISPUTED sessions.
     */
    public function getDisputes(string $accessToken): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $disputes = $this->model->getDisputedPtSessions();

            return [
                "status" => "success",
                "message" => "Disputed PT sessions fetched successfully",
                "count" => count($disputes),
                "data" => $disputes
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get PT subscriptions list only (Admin dashboard helper).
     */
    public function getPtSubscriptions(string $accessToken, array $filters): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN']);

            $subscriptions = $this->model->getPtSubscriptions($filters);

            return [
                "status" => "success",
                "message" => "PT subscriptions fetched successfully",
                "count" => count($subscriptions),
                "data" => $subscriptions
            ];

        } catch (\Throwable $e) {
            $this->setResponseCode(in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}

