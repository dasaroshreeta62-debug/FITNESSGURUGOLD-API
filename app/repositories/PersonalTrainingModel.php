<?php

require_once __DIR__ . '/model.php';

class PersonalTrainingModel extends Model
{
    protected PDO $db;

    public function __construct()
    {
        parent::__construct();
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

    public function inTransaction(): bool
    {
        return $this->db->inTransaction();
    }

    /**
     * Resolve user_id from users table to profile_id in users_profile table.
     */
    public function getProfileIdByUserId(int $userId): ?int
    {
        $stmt = $this->db->prepare("SELECT profile_id FROM users_profile WHERE user_id = :id LIMIT 1");
        $stmt->execute(['id' => $userId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int) $val : null;
    }

    /**
     * Resolve user_id from users table to trainer_profile_id in trainer_profiles table.
     */
    public function getTrainerProfileIdByUserId(int $userId): ?int
    {
        $stmt = $this->db->prepare("
            SELECT tp.trainer_profile_id 
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            WHERE e.user_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $userId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int) $val : null;
    }

    /**
     * Get trainer profile by trainer_profile_id.
     */
    public function getTrainerProfileById(int $trainerProfileId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT tp.* 
            FROM trainer_profiles tp
            WHERE tp.trainer_profile_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $trainerProfileId]);
        $val = $stmt->fetch(PDO::FETCH_ASSOC);
        return $val !== false ? $val : null;
    }

    /**
     * Resolve profile_id from users_profile to user_id from users.
     */
    public function getUserIdByProfileId(int $profileId): ?int
    {
        $stmt = $this->db->prepare("SELECT user_id FROM users_profile WHERE profile_id = :id LIMIT 1");
        $stmt->execute(['id' => $profileId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int) $val : null;
    }

    /**
     * Resolve trainer_profile_id to user_id from users.
     */
    public function getUserIdByTrainerProfileId(int $trainerProfileId): ?int
    {
        $stmt = $this->db->prepare("
            SELECT e.user_id 
            FROM employees e
            JOIN trainer_profiles tp ON tp.employee_id = e.employee_id
            WHERE tp.trainer_profile_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $trainerProfileId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int) $val : null;
    }

    /**
     * Get trainer's gym_id and branch_id from employee profile.
     */
    public function getTrainerGymBranch(int $trainerProfileId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT e.gym_id, e.branch_id 
            FROM employees e
            JOIN trainer_profiles tp ON tp.employee_id = e.employee_id
            WHERE tp.trainer_profile_id = :id
            LIMIT 1
        ");
        $stmt->execute(['id' => $trainerProfileId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function getMemberActiveTrainerProfileId(int $memberProfileId): ?int
    {
        $stmt = $this->db->prepare("
            SELECT trainer_id 
            FROM member_trainer_assignments 
            WHERE member_id = :member_id 
              AND status = 1 
            ORDER BY assignment_id DESC 
            LIMIT 1
        ");
        $stmt->execute(['member_id' => $memberProfileId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int)$val : null;
    }

    /**
     * Get user record by ID.
     */
    public function getUserById(int $userId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE user_id = :id LIMIT 1");
        $stmt->execute(['id' => $userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Get membership plan by ID.
     */
    public function getMembershipPlanById(int $planId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM membership_plans WHERE plan_id = :id LIMIT 1");
        $stmt->execute(['id' => $planId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Get plan entitlements by plan ID.
     */
    public function getPlanEntitlements(int $planId): array
    {
        $stmt = $this->db->prepare("SELECT * FROM plan_entitlements WHERE plan_id = :plan_id");
        $stmt->execute(['plan_id' => $planId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Insert a subscription record.
     */
    public function insertSubscription(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO subscriptions (
                gym_id, branch_id, user_id, plan_id, start_date, end_date, status
            ) VALUES (
                :gym_id, :branch_id, :user_id, :plan_id, :start_date, :end_date, :status
            )
        ");
        $stmt->execute([
            'gym_id' => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'user_id' => $data['user_id'],
            'plan_id' => $data['plan_id'],
            'start_date' => $data['start_date'],
            'end_date' => $data['end_date'],
            'status' => $data['status']
        ]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * Insert client wallet credit record.
     */
    public function insertClientWalletCredit(array $data): bool
    {
        $stmt = $this->db->prepare("
            INSERT INTO client_wallet_credits (
                subscription_id, user_id, entitlement_type, is_unlimited, original_quantity, remaining_quantity, expiration_date, status
            ) VALUES (
                :subscription_id, :user_id, :entitlement_type, :is_unlimited, :original_quantity, :remaining_quantity, :expiration_date, :status
            )
        ");
        return $stmt->execute([
            'subscription_id' => $data['subscription_id'],
            'user_id' => $data['user_id'], // users.user_id
            'entitlement_type' => $data['entitlement_type'],
            'is_unlimited' => $data['is_unlimited'],
            'original_quantity' => $data['original_quantity'],
            'remaining_quantity' => $data['remaining_quantity'],
            'expiration_date' => $data['expiration_date'],
            'status' => $data['status']
        ]);
    }

    /**
     * Count active assignments for a trainer (using trainer_profile_id).
     */
    public function getTrainerActiveAssignmentsCount(int $trainerProfileId): int
    {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) 
            FROM member_trainer_assignments 
            WHERE trainer_id = :trainer_id 
              AND status = 1 
              AND assignment_type = 'PRIMARY'
        ");
        $stmt->execute(['trainer_id' => $trainerProfileId]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * Deactivate existing primary assignments for a member (using profile_id).
     */
    public function deactivateMemberPrimaryAssignments(int $profileId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE member_trainer_assignments 
            SET status = 0 
            WHERE member_id = :member_id 
              AND assignment_type = 'PRIMARY' 
              AND status = 1
        ");
        return $stmt->execute(['member_id' => $profileId]);
    }

    /**
     * Insert member trainer assignment (storing profile_id and trainer_profile_id).
     */
    public function insertMemberTrainerAssignment(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO member_trainer_assignments (
                gym_id, branch_id, member_id, trainer_id, assignment_type, status
            ) VALUES (
                :gym_id, :branch_id, :member_id, :trainer_id, 'PRIMARY', 1
            )
        ");
        $stmt->execute([
            'gym_id' => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'member_id' => $data['member_id'], // profile_id
            'trainer_id' => $data['trainer_id'] // trainer_profile_id
        ]);
        return (int) $this->db->lastInsertId();
    }

    /**
     * Clear trainer availability template (using trainer_profile_id).
     */
    public function clearTrainerWeeklyAvailability(int $trainerProfileId): bool
    {
        $stmt = $this->db->prepare("DELETE FROM trainer_weekly_availability WHERE trainer_id = :trainer_id");
        return $stmt->execute(['trainer_id' => $trainerProfileId]);
    }

    /**
     * Insert trainer weekly availability entry (using trainer_profile_id).
     */
    public function insertTrainerWeeklyAvailability(int $trainerProfileId, int $dayOfWeek, int $slotId): bool
    {
        $stmt = $this->db->prepare("
            INSERT INTO trainer_weekly_availability (
                trainer_id, day_of_week, slot_id, is_active
            ) VALUES (
                :trainer_id, :day_of_week, :slot_id, 1
            )
        ");
        return $stmt->execute([
            'trainer_id' => $trainerProfileId,
            'day_of_week' => $dayOfWeek,
            'slot_id' => $slotId
        ]);
    }

    /**
     * View trainer roster for a date (using trainer_profile_id).
     */
    public function getTrainerPtScheduleForDate(int $trainerProfileId, string $date): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                s.schedule_id,
                s.session_date,
                s.session_status,
                s.session_note AS workout_summary,
                s.verification_pin,
                s.member_id, -- profile_id
                u.name AS member_name,
                u.email AS member_email,
                u.phone AS member_phone,
                s.slot_id,
                slot.slot_name,
                slot.start_time,
                slot.end_time
            FROM trainer_pt_schedule s
            LEFT JOIN users_profile up ON up.profile_id = s.member_id
            LEFT JOIN users u ON u.user_id = up.user_id
            LEFT JOIN gym_pt_slots slot ON slot.slot_id = s.slot_id
            WHERE s.trainer_id = :trainer_id AND s.session_date = :date
            ORDER BY slot.start_time ASC
        ");
        $stmt->execute([
            'trainer_id' => $trainerProfileId,
            'date' => $date
        ]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Normalize data types
        return array_map(function ($r) {
            return [
                'schedule_id' => (int) $r['schedule_id'],
                'session_date' => $r['session_date'],
                'session_status' => $r['session_status'],
                'workout_summary' => $r['workout_summary'],
                'verification_pin' => $r['verification_pin'] !== null ? (int) $r['verification_pin'] : null,
                'member_id' => $r['member_id'] !== null ? (int) $r['member_id'] : null,
                'member_name' => $r['member_name'],
                'member_email' => $r['member_email'],
                'member_phone' => $r['member_phone'],
                'slot_id' => (int) $r['slot_id'],
                'slot_name' => $r['slot_name'],
                'start_time' => $r['start_time'],
                'end_time' => $r['end_time']
            ];
        }, $rows);
    }

    /**
     * Get member's assigned trainer (using profile_id, returns trainer_profile_id).
     */
    public function getMemberAssignedTrainer(int $profileId): ?int
    {
        $stmt = $this->db->prepare("
            SELECT trainer_id 
            FROM member_trainer_assignments 
            WHERE member_id = :member_id 
              AND status = 1 
              AND assignment_type = 'PRIMARY'
            LIMIT 1
        ");
        $stmt->execute(['member_id' => $profileId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int) $val : null;
    }

    /**
     * Get available PT slots for a trainer on a specific date (using trainer_profile_id).
     */
    public function getAvailablePtSlotsForTrainerAndDate(int $trainerProfileId, string $date): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                s.schedule_id, 
                s.slot_id,
                slot.slot_name,
                slot.start_time,
                slot.end_time
            FROM trainer_pt_schedule s
            LEFT JOIN gym_pt_slots slot ON slot.slot_id = s.slot_id
            WHERE s.trainer_id = :trainer_id 
              AND s.session_date = :date 
              AND s.session_status = 'AVAILABLE'
            ORDER BY slot.start_time ASC
        ");
        $stmt->execute([
            'trainer_id' => $trainerProfileId,
            'date' => $date
        ]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($r) {
            return [
                'schedule_id' => (int) $r['schedule_id'],
                'slot_id' => (int) $r['slot_id'],
                'slot_name' => $r['slot_name'],
                'start_time' => $r['start_time'],
                'end_time' => $r['end_time']
            ];
        }, $rows);
    }

    /**
     * Get member's earliest expiring active wallet credit (using users.user_id).
     */
    public function getMemberActiveCredit(int $userId, string $entitlementType): ?array
    {
        $stmt = $this->db->prepare("
            SELECT credit_id, remaining_quantity 
            FROM client_wallet_credits 
            WHERE user_id = :user_id 
              AND entitlement_type = :type 
              AND remaining_quantity > 0 
              AND expiration_date >= CURDATE()
              AND status = 1
            ORDER BY expiration_date ASC 
            LIMIT 1
        ");
        $stmt->execute([
            'user_id' => $userId,
            'type' => $entitlementType
        ]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Count member's active bookings on a specific date (using profile_id).
     */
    public function getMemberActiveBookingCountOnDate(int $profileId, string $date): int
    {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) 
            FROM trainer_pt_schedule 
            WHERE member_id = :member_id 
              AND session_date = :date 
              AND session_status IN ('PENDING', 'ATTENDED', 'CLIENT_LATE_CANCEL', 'NO_SHOW')
        ");
        $stmt->execute([
            'member_id' => $profileId,
            'date' => $date
        ]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * Get specific schedule item.
     */
    public function getPtScheduleItem(int $scheduleId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM trainer_pt_schedule WHERE schedule_id = :id LIMIT 1");
        $stmt->execute(['id' => $scheduleId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Perform slot booking (storing profile_id).
     */
    public function bookPtSlot(int $scheduleId, int $profileId, int $creditId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET member_id = :member_id, 
                credit_id = :credit_id, 
                session_status = 'PENDING'
            WHERE schedule_id = :schedule_id 
              AND session_status = 'AVAILABLE'
        ");
        return $stmt->execute([
            'member_id' => $profileId,
            'credit_id' => $creditId,
            'schedule_id' => $scheduleId
        ]) && $stmt->rowCount() === 1;
    }

    /**
     * Set verification PIN and workout summary (using trainer_profile_id).
     */
    public function setVerificationPin(int $scheduleId, int $trainerProfileId, int $pin, string $summary = ''): bool
    {
        $sql = "UPDATE trainer_pt_schedule SET verification_pin = :pin";
        $params = [
            'pin' => $pin,
            'schedule_id' => $scheduleId,
            'trainer_id' => $trainerProfileId
        ];

        if (!empty($summary)) {
            $sql .= ", session_note = CONCAT(IFNULL(session_note, ''), ' // ', :summary)";
            $params['summary'] = trim($summary);
        }

        $sql .= " WHERE schedule_id = :schedule_id AND trainer_id = :trainer_id AND session_status = 'PENDING'";

        $stmt = $this->db->prepare($sql);
        return $stmt->execute($params) && $stmt->rowCount() === 1;
    }

    /**
     * Finalize the PT session completion status.
     */
    public function finalizeSessionStatus(int $scheduleId, int $pin): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'ATTENDED', 
                verification_pin = NULL 
            WHERE schedule_id = :schedule_id 
              AND verification_pin = :pin
        ");
        return $stmt->execute([
            'schedule_id' => $scheduleId,
            'pin' => $pin
        ]) && $stmt->rowCount() === 1;
    }

    /**
     * Deduct one session credit from wallet.
     */
    public function deductWalletCredit(int $creditId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE client_wallet_credits 
            SET remaining_quantity = remaining_quantity - 1 
            WHERE credit_id = :credit_id 
              AND remaining_quantity > 0
        ");
        return $stmt->execute(['credit_id' => $creditId]) && $stmt->rowCount() === 1;
    }

    /**
     * Check if a slot_id exists.
     */
    public function slotExists(int $slotId): bool
    {
        $stmt = $this->db->prepare("SELECT COUNT(*) FROM gym_pt_slots WHERE slot_id = :id");
        $stmt->execute(['id' => $slotId]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /**
     * Get a specific slot.
     */
    public function getSlot(int $slotId): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM gym_pt_slots WHERE slot_id = :id LIMIT 1");
        $stmt->execute(['id' => $slotId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Get templates for trainer availability by day of week (using trainer_profile_id).
     */
    public function getTrainerTemplatesForDay(int $trainerProfileId, int $dayOfWeek): array
    {
        $stmt = $this->db->prepare("
            SELECT slot_id 
            FROM trainer_weekly_availability 
            WHERE trainer_id = :trainer_id 
              AND day_of_week = :day 
              AND is_active = 1
        ");
        $stmt->execute([
            'trainer_id' => $trainerProfileId,
            'day' => $dayOfWeek
        ]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /**
     * Check if schedule item already exists (using trainer_profile_id).
     */
    public function scheduleItemExists(int $trainerProfileId, string $date, int $slotId): bool
    {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) 
            FROM trainer_pt_schedule 
            WHERE trainer_id = :trainer_id 
              AND session_date = :date 
              AND slot_id = :slot_id
        ");
        $stmt->execute([
            'trainer_id' => $trainerProfileId,
            'date' => $date,
            'slot_id' => $slotId
        ]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /**
     * Insert schedule item (using trainer_profile_id).
     */
    public function insertScheduleItem(array $data): bool
    {
        $stmt = $this->db->prepare("
            INSERT INTO trainer_pt_schedule (
                gym_id, branch_id, trainer_id, session_date, slot_id, session_status
            ) VALUES (
                :gym_id, :branch_id, :trainer_id, :session_date, :slot_id, 'AVAILABLE'
            )
        ");
        return $stmt->execute([
            'gym_id' => $data['gym_id'],
            'branch_id' => $data['branch_id'],
            'trainer_id' => $data['trainer_id'], // trainer_profile_id
            'session_date' => $data['session_date'],
            'slot_id' => $data['slot_id']
        ]);
    }

    /* ========================================================================= */
    /* ========================= PT LIFECYCLE MUTATIONS ======================== */
    /* ========================================================================= */

    /**
     * Action M3: Member reports individual trainer absence.
     */
    public function reportTrainerAbsence(int $scheduleId, int $memberProfileId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'TRAINER_ABSENT' 
            WHERE schedule_id = :schedule_id 
              AND member_id = :member_id 
              AND session_status = 'PENDING'
        ");
        $stmt->execute([
            'schedule_id' => $scheduleId,
            'member_id' => $memberProfileId
        ]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Action M4: Member contests no-show claim (dispute trigger).
     */
    public function disputeNoShow(int $scheduleId, int $memberProfileId, string $counterReason): bool
    {
        $formattedReason = " // [M-D-L]: " . trim($counterReason);
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'DISPUTED',
                session_note = CONCAT(IFNULL(session_note, ''), :reason)
            WHERE schedule_id = :schedule_id 
              AND member_id = :member_id 
              AND session_status = 'MEMBER_NO_SHOW'
        ");
        $stmt->execute([
            'schedule_id' => $scheduleId,
            'member_id' => $memberProfileId,
            'reason' => $formattedReason
        ]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Action T2: Trainer mutual absence release (soft cancel).
     */
    public function releaseSession(int $scheduleId, int $trainerProfileId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'AVAILABLE', 
                member_id = NULL, 
                credit_id = NULL, 
                verification_pin = NULL 
            WHERE schedule_id = :schedule_id 
              AND trainer_id = :trainer_id 
              AND session_status = 'PENDING'
        ");
        $stmt->execute([
            'schedule_id' => $scheduleId,
            'trainer_id' => $trainerProfileId
        ]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Action T3: Trainer flags client no-show.
     */
    public function flagNoShow(int $scheduleId, int $trainerProfileId, string $trainerReason): bool
    {
        $formattedReason = " // [T-D-L]: " . trim($trainerReason);
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'MEMBER_NO_SHOW',
                session_note = CONCAT(IFNULL(session_note, ''), :reason)
            WHERE schedule_id = :schedule_id 
              AND trainer_id = :trainer_id 
              AND session_status = 'PENDING'
        ");
        $stmt->execute([
            'schedule_id' => $scheduleId,
            'trainer_id' => $trainerProfileId,
            'reason' => $formattedReason
        ]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Action A1: Admin resolves dispute in favor of trainer.
     */
    public function resolveDisputeTrainer(int $scheduleId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'RESOLVED_BY_ADMIN' 
            WHERE schedule_id = :schedule_id 
              AND session_status = 'DISPUTED'
        ");
        $stmt->execute(['schedule_id' => $scheduleId]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Action A2: Admin resolves dispute in favor of member.
     */
    public function resolveDisputeMember(int $scheduleId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = 'RESOLVED_BY_ADMIN' 
            WHERE schedule_id = :schedule_id 
              AND session_status = 'DISPUTED'
        ");
        $stmt->execute(['schedule_id' => $scheduleId]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Refund 1 credit to client wallet credit profile.
     */
    public function refundWalletCredit(int $creditId): bool
    {
        $stmt = $this->db->prepare("
            UPDATE client_wallet_credits 
            SET remaining_quantity = remaining_quantity + 1 
            WHERE credit_id = :credit_id
        ");
        $stmt->execute(['credit_id' => $creditId]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Nightly Evaluation: Get all pending sessions older than a specific date.
     */
    public function getUnresolvedPastSessions(string $date): array
    {
        $stmt = $this->db->prepare("
            SELECT * 
            FROM trainer_pt_schedule 
            WHERE session_status = 'PENDING' 
              AND session_date < :date
        ");
        $stmt->execute(['date' => $date]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Nightly Evaluation: Get wallet credit by credit_id.
     */
    public function getWalletCredit(int $creditId): ?array
    {
        $stmt = $this->db->prepare("
            SELECT * 
            FROM client_wallet_credits 
            WHERE credit_id = :credit_id 
            LIMIT 1
        ");
        $stmt->execute(['credit_id' => $creditId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Nightly Evaluation: Update session status and set verification_pin to NULL.
     */
    public function updateSessionStatusAndClearPin(int $scheduleId, string $status): bool
    {
        $stmt = $this->db->prepare("
            UPDATE trainer_pt_schedule 
            SET session_status = :status,
                verification_pin = NULL
            WHERE schedule_id = :schedule_id
        ");
        return $stmt->execute([
            'status' => $status,
            'schedule_id' => $scheduleId
        ]);
    }

    /**
     * Retrieve the weekly recurring availability template for a trainer.
     */
    public function getTrainerWeeklyAvailability(int $trainerProfileId): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                wa.day_of_week, 
                wa.slot_id, 
                wa.is_active,
                slot.slot_name,
                slot.start_time,
                slot.end_time
            FROM trainer_weekly_availability wa
            JOIN gym_pt_slots slot ON slot.slot_id = wa.slot_id
            WHERE wa.trainer_id = :trainer_id AND wa.is_active = 1
            ORDER BY wa.day_of_week ASC, slot.start_time ASC
        ");
        $stmt->execute(['trainer_id' => $trainerProfileId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($r) {
            return [
                'day_of_week' => (int) $r['day_of_week'],
                'slot_id' => (int) $r['slot_id'],
                'is_active' => (int) $r['is_active'],
                'slot_name' => $r['slot_name'],
                'start_time' => $r['start_time'],
                'end_time' => $r['end_time']
            ];
        }, $rows);
    }

    /**
     * Get a list of active trainers and count of assigned clients.
     */
    public function getTrainersWithClientCount(): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                u.user_id,
                u.user_id AS trainer_user_id,
                tp.trainer_profile_id AS trainer_id,
                tp.trainer_profile_id,
                e.employee_id,
                e.employee_code,
                e.profile_photo,
                u.name AS trainer_name,
                u.email AS trainer_email,
                u.phone AS trainer_phone,
                tp.specialization,
                tp.experience,
                tp.certifications,
                tp.bio,
                tp.showcase_photo,
                tp.availability_status,
                tp.rating,
                COUNT(mta.assignment_id) AS assigned_clients_count
            FROM trainer_profiles tp
            JOIN employees e ON e.employee_id = tp.employee_id
            JOIN users u ON u.user_id = e.user_id
            LEFT JOIN member_trainer_assignments mta 
                ON mta.trainer_id = tp.trainer_profile_id 
                AND mta.status = 1 
                AND mta.assignment_type = 'PRIMARY'
            GROUP BY 
                tp.trainer_profile_id, 
                u.user_id, 
                u.name, 
                u.email, 
                u.phone,
                e.employee_id, 
                e.employee_code, 
                e.profile_photo,
                tp.specialization, 
                tp.experience, 
                tp.certifications, 
                tp.bio, 
                tp.showcase_photo, 
                tp.availability_status, 
                tp.rating
            ORDER BY trainer_name ASC
        ");
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($r) {
            return [
                'user_id' => (int) $r['user_id'],
                'trainer_user_id' => (int) $r['trainer_user_id'],
                'employee_id' => (int) $r['employee_id'],
                'employee_code' => $r['employee_code'],
                'trainer_id' => (int) $r['trainer_id'],
                'trainer_profile_id' => (int) $r['trainer_profile_id'],
                'trainer_name' => $r['trainer_name'],
                'trainer_email' => $r['trainer_email'],
                'trainer_phone' => $r['trainer_phone'],
                'profile_photo_url' => $r['profile_photo'],
                'pose_photo_url' => $r['showcase_photo'],
                'specialization' => $r['specialization'],
                'experience' => $r['experience'] !== null ? (int) $r['experience'] : null,
                'certifications' => $r['certifications'],
                'bio' => $r['bio'],
                'availability_status' => $r['availability_status'],
                'rating' => $r['rating'] !== null ? (float) $r['rating'] : 0.0,
                'assigned_clients_count' => (int) $r['assigned_clients_count']
            ];
        }, $rows);
    }

    /**
     * Get system-wide personal training dashboard metrics.
     */
    public function getPtDashboardMetrics(): array
    {
        // 1. Session status counts
        $stmt = $this->db->query("
            SELECT session_status, COUNT(*) as cnt 
            FROM trainer_pt_schedule 
            GROUP BY session_status
        ");
        $statusCounts = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $statusBreakdown = [];
        foreach ($statusCounts as $row) {
            $statusBreakdown[$row['session_status']] = (int) $row['cnt'];
        }

        // 2. Active assignments count
        $stmt = $this->db->query("
            SELECT COUNT(*) 
            FROM member_trainer_assignments 
            WHERE status = 1 AND assignment_type = 'PRIMARY'
        ");
        $activeAssignments = (int) $stmt->fetchColumn();

        // 3. Active trainers count
        $stmt = $this->db->query("SELECT COUNT(*) FROM trainer_profiles");
        $activeTrainers = (int) $stmt->fetchColumn();

        // 4. Remaining unused credits in member wallets
        $stmt = $this->db->query("
            SELECT SUM(remaining_quantity) 
            FROM client_wallet_credits 
            WHERE entitlement_type = 'PT_1ON1' 
              AND remaining_quantity > 0 
              AND expiration_date >= CURDATE() 
              AND status = 1
        ");
        $totalUnusedCredits = (int) $stmt->fetchColumn();

        return [
            'sessions_status_breakdown' => $statusBreakdown,
            'active_assignments_count' => $activeAssignments,
            'active_trainers_count' => $activeTrainers,
            'total_unused_credits' => $totalUnusedCredits
        ];
    }

    /**
     * Retrieve a filterable list of PT schedule sessions.
     */
    public function getFilteredPtSessions(array $filters): array
    {
        $sql = "
            SELECT 
                s.schedule_id,
                s.session_date,
                s.session_status,
                s.session_note AS workout_summary,
                s.session_note,
                s.verification_pin,
                s.member_id, -- profile_id
                mu.name AS member_name,
                mu.email AS member_email,
                s.trainer_id, -- trainer_profile_id
                tu.name AS trainer_name,
                tu.email AS trainer_email,
                s.slot_id,
                slot.slot_name,
                slot.start_time,
                slot.end_time
            FROM trainer_pt_schedule s
            LEFT JOIN users_profile up ON up.profile_id = s.member_id
            LEFT JOIN users mu ON mu.user_id = up.user_id
            LEFT JOIN trainer_profiles tp ON tp.trainer_profile_id = s.trainer_id
            LEFT JOIN employees e ON e.employee_id = tp.employee_id
            LEFT JOIN users tu ON tu.user_id = e.user_id
            LEFT JOIN gym_pt_slots slot ON slot.slot_id = s.slot_id
            WHERE 1=1
        ";
        $params = [];

        if (!empty($filters['status'])) {
            $sql .= " AND s.session_status = :status";
            $params['status'] = $filters['status'];
        }
        if (!empty($filters['trainer_id'])) {
            $sql .= " AND s.trainer_id = :trainer_id";
            $params['trainer_id'] = (int) $filters['trainer_id'];
        }
        if (!empty($filters['member_id'])) {
            $sql .= " AND s.member_id = :member_id";
            $params['member_id'] = (int) $filters['member_id'];
        }
        if (!empty($filters['start_date'])) {
            $sql .= " AND s.session_date >= :start_date";
            $params['start_date'] = $filters['start_date'];
        }
        if (!empty($filters['end_date'])) {
            $sql .= " AND s.session_date <= :end_date";
            $params['end_date'] = $filters['end_date'];
        }

        $sql .= " ORDER BY s.session_date DESC, slot.start_time ASC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($r) {
            return [
                'schedule_id' => (int) $r['schedule_id'],
                'session_date' => $r['session_date'],
                'session_status' => $r['session_status'],
                'workout_summary' => $r['workout_summary'],
                'session_note' => $r['session_note'],
                'verification_pin' => $r['verification_pin'] !== null ? (int) $r['verification_pin'] : null,
                'member_id' => $r['member_id'] !== null ? (int) $r['member_id'] : null,
                'member_name' => $r['member_name'],
                'member_email' => $r['member_email'],
                'trainer_id' => (int) $r['trainer_id'],
                'trainer_name' => $r['trainer_name'],
                'trainer_email' => $r['trainer_email'],
                'slot_id' => (int) $r['slot_id'],
                'slot_name' => $r['slot_name'],
                'start_time' => $r['start_time'],
                'end_time' => $r['end_time']
            ];
        }, $rows);
    }

    /**
     * Retrieve all PT sessions marked as DISPUTED.
     */
    public function getDisputedPtSessions(): array
    {
        $stmt = $this->db->prepare("
            SELECT 
                s.schedule_id,
                s.session_date,
                s.session_status,
                s.session_note,
                s.member_id,
                mu.name AS member_name,
                mu.email AS member_email,
                s.trainer_id,
                tu.name AS trainer_name,
                tu.email AS trainer_email,
                s.slot_id,
                slot.slot_name,
                slot.start_time,
                slot.end_time
            FROM trainer_pt_schedule s
            LEFT JOIN users_profile up ON up.profile_id = s.member_id
            LEFT JOIN users mu ON mu.user_id = up.user_id
            LEFT JOIN trainer_profiles tp ON tp.trainer_profile_id = s.trainer_id
            LEFT JOIN employees e ON e.employee_id = tp.employee_id
            LEFT JOIN users tu ON tu.user_id = e.user_id
            LEFT JOIN gym_pt_slots slot ON slot.slot_id = s.slot_id
            WHERE s.session_status = 'DISPUTED'
            ORDER BY s.session_date DESC, slot.start_time ASC
        ");
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($r) {
            return [
                'schedule_id' => (int) $r['schedule_id'],
                'session_date' => $r['session_date'],
                'session_status' => $r['session_status'],
                'session_note' => $r['session_note'],
                'member_id' => (int) $r['member_id'],
                'member_name' => $r['member_name'],
                'member_email' => $r['member_email'],
                'trainer_id' => (int) $r['trainer_id'],
                'trainer_name' => $r['trainer_name'],
                'trainer_email' => $r['trainer_email'],
                'slot_id' => (int) $r['slot_id'],
                'slot_name' => $r['slot_name'],
                'start_time' => $r['start_time'],
                'end_time' => $r['end_time']
            ];
        }, $rows);
    }

    /**
     * Get only PT subscriptions with details.
     */
    public function getPtSubscriptions(array $filters = []): array
    {
        $sql = "
            SELECT 
                s.subscription_id,
                s.user_id AS member_user_id,
                s.plan_id,
                s.gym_id,
                s.branch_id,
                s.start_date,
                s.end_date,
                s.status AS subscription_status,
                s.createdDate AS subscription_created_date,
                s.createdTime AS subscription_created_time,
                
                -- Member Details
                u.name AS member_name,
                u.email AS member_email,
                u.phone AS member_phone,
                up.profile_id AS member_profile_id,
                
                -- Plan Details
                mp.plan_name,
                mp.plan_type,
                mp.price AS plan_price,
                mp.duration_months,
                
                -- Trainer Assignment Details
                mta.assignment_id,
                mta.assignment_type,
                mta.status AS assignment_status,
                mta.assigned_at,
                tp.trainer_profile_id,
                tu.user_id AS trainer_user_id,
                tu.name AS trainer_name,
                tu.email AS trainer_email,
                tu.phone AS trainer_phone
                
            FROM subscriptions s
            JOIN users u ON u.user_id = s.user_id
            JOIN membership_plans mp ON mp.plan_id = s.plan_id
            LEFT JOIN users_profile up ON up.user_id = u.user_id
            LEFT JOIN member_trainer_assignments mta 
                ON mta.member_id = up.profile_id 
                AND mta.status = 1
                AND mta.assignment_type = 'PRIMARY'
            LEFT JOIN trainer_profiles tp ON tp.trainer_profile_id = mta.trainer_id
            LEFT JOIN employees te ON te.employee_id = tp.employee_id
            LEFT JOIN users tu ON tu.user_id = te.user_id
            WHERE mp.plan_type = 'PT_UPGRADE'
        ";
        $params = [];

        if (isset($filters['status']) && $filters['status'] !== '') {
            $sql .= " AND s.status = :status";
            $params['status'] = (int)$filters['status'];
        }

        if (!empty($filters['user_id'])) {
            $sql .= " AND s.user_id = :user_id";
            $params['user_id'] = (int)$filters['user_id'];
        }

        if (!empty($filters['plan_id'])) {
            $sql .= " AND s.plan_id = :plan_id";
            $params['plan_id'] = (int)$filters['plan_id'];
        }

        if (!empty($filters['gym_id'])) {
            $sql .= " AND s.gym_id = :gym_id";
            $params['gym_id'] = (int)$filters['gym_id'];
        }

        if (!empty($filters['branch_id'])) {
            $sql .= " AND s.branch_id = :branch_id";
            $params['branch_id'] = (int)$filters['branch_id'];
        }

        $sql .= " ORDER BY s.subscription_id DESC";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $results = [];
        foreach ($rows as $r) {
            $invoices = $this->getSubscriptionInvoices((int)$r['member_user_id'], (int)$r['plan_id'], $r['start_date']);
            $walletCredits = $this->getSubscriptionWalletCredits((int)$r['subscription_id']);
            
            $results[] = [
                'subscription_id' => (int) $r['subscription_id'],
                'gym_id' => (int) $r['gym_id'],
                'branch_id' => (int) $r['branch_id'],
                'start_date' => $r['start_date'],
                'end_date' => $r['end_date'],
                'status' => (int) $r['subscription_status'],
                'created_at' => $r['subscription_created_date'] !== null ? ($r['subscription_created_date'] . ' ' . ($r['subscription_created_time'] ?? '00:00:00')) : null,
                'member' => [
                    'user_id' => (int) $r['member_user_id'],
                    'profile_id' => $r['member_profile_id'] !== null ? (int)$r['member_profile_id'] : null,
                    'name' => $r['member_name'],
                    'email' => $r['member_email'],
                    'phone' => $r['member_phone']
                ],
                'plan' => [
                    'plan_id' => (int) $r['plan_id'],
                    'plan_name' => $r['plan_name'],
                    'plan_type' => $r['plan_type'],
                    'price' => (float) $r['plan_price'],
                    'duration_months' => (int) $r['duration_months']
                ],
                'trainer_assignment' => $r['trainer_profile_id'] !== null ? [
                    'assignment_id' => (int) $r['assignment_id'],
                    'trainer_profile_id' => (int) $r['trainer_profile_id'],
                    'trainer_user_id' => (int) $r['trainer_user_id'],
                    'trainer_name' => $r['trainer_name'],
                    'trainer_email' => $r['trainer_email'],
                    'trainer_phone' => $r['trainer_phone'],
                    'assignment_type' => $r['assignment_type'],
                    'assigned_at' => $r['assigned_at']
                ] : null,
                'invoices' => $invoices,
                'wallet_credits' => $walletCredits
            ];
        }

        return $results;
    }

    /**
     * Fetch invoices matching the subscription user, plan, and purchase date (helper).
     */
    public function getSubscriptionInvoices(int $userId, int $planId, string $startDate): array
    {
        $stmt = $this->db->prepare("
            SELECT i.invoice_id, i.invoice_number, i.final_amount, i.issued_at, i.status
            FROM invoices i
            JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
            WHERE i.user_id = :user_id
              AND ii.reference_id = :plan_id
              AND ii.item_type IN ('SUBSCRIPTION', 'PT_PACKAGE')
            ORDER BY ABS(DATEDIFF(i.issued_at, :start_date)) ASC, i.invoice_id DESC
        ");
        $stmt->execute([
            'user_id'    => $userId,
            'plan_id'    => $planId,
            'start_date' => $startDate
        ]);
        $invoices = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($invoices as &$inv) {
            $inv['invoice_id'] = (int)$inv['invoice_id'];
            $inv['final_amount'] = (float)$inv['final_amount'];
        }
        return $invoices;
    }

    /**
     * Fetch wallet credits associated with a subscription ID (helper).
     */
    public function getSubscriptionWalletCredits(int $subId): array
    {
        $stmt = $this->db->prepare("SELECT * FROM client_wallet_credits WHERE subscription_id = :sub_id");
        $stmt->execute(['sub_id' => $subId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as &$row) {
            $row['credit_id'] = (int)$row['credit_id'];
            $row['subscription_id'] = (int)$row['subscription_id'];
            $row['user_id'] = (int)$row['user_id'];
            $row['is_unlimited'] = (int)$row['is_unlimited'];
            $row['original_quantity'] = (int)$row['original_quantity'];
            $row['remaining_quantity'] = (int)$row['remaining_quantity'];
            $row['status'] = (int)$row['status'];
        }

        return $rows;
    }

    /**
     * Fetch all active PT subscriptions whose end_date has passed the target_date.
     * Also retrieves associated invoice and primary trainer assignment.
     */
    public function getExpiredPtSubscriptions(string $targetDate): array
    {
        $stmt = $this->db->prepare("
            SELECT
                s.subscription_id,
                s.user_id,
                s.plan_id,
                s.gym_id,
                s.branch_id,
                s.end_date,
                mp.plan_name,
                up.profile_id,
                (
                    SELECT i.invoice_id
                    FROM invoices i
                    JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
                    WHERE i.user_id = s.user_id
                      AND ii.item_type = 'PT_PACKAGE'
                      AND ii.reference_id = s.plan_id
                      AND i.status = 'PAID'
                    ORDER BY i.invoice_id DESC
                    LIMIT 1
                ) AS invoice_id,
                (
                    SELECT i.final_amount
                    FROM invoices i
                    JOIN invoice_items ii ON ii.invoice_id = i.invoice_id
                    WHERE i.user_id = s.user_id
                      AND ii.item_type = 'PT_PACKAGE'
                      AND ii.reference_id = s.plan_id
                      AND i.status = 'PAID'
                    ORDER BY i.invoice_id DESC
                    LIMIT 1
                ) AS invoice_amount,
                (
                    SELECT mta.trainer_id
                    FROM member_trainer_assignments mta
                    WHERE mta.member_id = up.profile_id
                      AND mta.assignment_type = 'PRIMARY'
                      AND mta.status = 'ACTIVE'
                    ORDER BY mta.assignment_id DESC
                    LIMIT 1
                ) AS trainer_id
            FROM subscriptions s
            JOIN membership_plans mp ON mp.plan_id = s.plan_id
            LEFT JOIN users_profile up ON up.user_id = s.user_id
            WHERE mp.plan_type = 'PT_UPGRADE'
              AND s.status = 1
              AND s.end_date <= :target_date
        ");
        $stmt->execute(['target_date' => $targetDate]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Check if a trainer commission already exists for a given invoice_id.
     * Used to prevent double-booking.
     */
    public function commissionExistsForInvoice(int $invoiceId): bool
    {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) FROM trainer_commissions WHERE invoice_id = :invoice_id
        ");
        $stmt->execute(['invoice_id' => $invoiceId]);
        return (int)$stmt->fetchColumn() > 0;
    }

    /**
     * Insert a new trainer commission row (status = UNPAID).
     */
    public function insertTrainerCommission(array $data): int
    {
        $stmt = $this->db->prepare("
            INSERT INTO trainer_commissions (
                gym_id, branch_id, trainer_id, invoice_id, commission_amount, status, created_at
            ) VALUES (
                :gym_id, :branch_id, :trainer_id, :invoice_id, :commission_amount, 'UNPAID', NOW()
            )
        ");
        $stmt->execute([
            'gym_id'            => (int)$data['gym_id'],
            'branch_id'         => (int)$data['branch_id'],
            'trainer_id'        => (int)$data['trainer_id'],
            'invoice_id'        => (int)$data['invoice_id'],
            'commission_amount' => (float)$data['commission_amount']
        ]);
        return (int)$this->db->lastInsertId();
    }

    /**
     * Update the status of a subscription by ID.
     * status: 1 = active, 2 = completed, 0 = cancelled.
     */
    public function updateSubscriptionStatus(int $subId, int $status): bool
    {
        $stmt = $this->db->prepare("UPDATE subscriptions SET status = :status WHERE subscription_id = :id");
        return $stmt->execute(['status' => $status, 'id' => $subId]);
    }
}
