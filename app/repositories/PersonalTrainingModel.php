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
        return $val !== false ? (int)$val : null;
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
        return $val !== false ? (int)$val : null;
    }

    /**
     * Resolve profile_id from users_profile to user_id from users.
     */
    public function getUserIdByProfileId(int $profileId): ?int
    {
        $stmt = $this->db->prepare("SELECT user_id FROM users_profile WHERE profile_id = :id LIMIT 1");
        $stmt->execute(['id' => $profileId]);
        $val = $stmt->fetchColumn();
        return $val !== false ? (int)$val : null;
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
        return $val !== false ? (int)$val : null;
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
            'gym_id'     => $data['gym_id'],
            'branch_id'  => $data['branch_id'],
            'user_id'    => $data['user_id'],
            'plan_id'    => $data['plan_id'],
            'start_date' => $data['start_date'],
            'end_date'   => $data['end_date'],
            'status'     => $data['status']
        ]);
        return (int)$this->db->lastInsertId();
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
            'subscription_id'    => $data['subscription_id'],
            'user_id'            => $data['user_id'], // users.user_id
            'entitlement_type'   => $data['entitlement_type'],
            'is_unlimited'       => $data['is_unlimited'],
            'original_quantity'  => $data['original_quantity'],
            'remaining_quantity' => $data['remaining_quantity'],
            'expiration_date'    => $data['expiration_date'],
            'status'             => $data['status']
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
        return (int)$stmt->fetchColumn();
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
            'gym_id'     => $data['gym_id'],
            'branch_id'  => $data['branch_id'],
            'member_id'  => $data['member_id'], // profile_id
            'trainer_id' => $data['trainer_id'] // trainer_profile_id
        ]);
        return (int)$this->db->lastInsertId();
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
            'trainer_id'  => $trainerProfileId,
            'day_of_week' => $dayOfWeek,
            'slot_id'     => $slotId
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
                s.workout_summary,
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
            'date'       => $date
        ]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Normalize data types
        return array_map(function ($r) {
            return [
                'schedule_id'      => (int)$r['schedule_id'],
                'session_date'     => $r['session_date'],
                'session_status'   => $r['session_status'],
                'workout_summary'  => $r['workout_summary'],
                'verification_pin' => $r['verification_pin'] !== null ? (int)$r['verification_pin'] : null,
                'member_id'        => $r['member_id'] !== null ? (int)$r['member_id'] : null,
                'member_name'      => $r['member_name'],
                'member_email'     => $r['member_email'],
                'member_phone'     => $r['member_phone'],
                'slot_id'          => (int)$r['slot_id'],
                'slot_name'        => $r['slot_name'],
                'start_time'       => $r['start_time'],
                'end_time'         => $r['end_time']
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
        return $val !== false ? (int)$val : null;
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
            'date'       => $date
        ]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return array_map(function ($r) {
            return [
                'schedule_id' => (int)$r['schedule_id'],
                'slot_id'     => (int)$r['slot_id'],
                'slot_name'   => $r['slot_name'],
                'start_time'  => $r['start_time'],
                'end_time'    => $r['end_time']
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
            'type'    => $entitlementType
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
            'date'      => $date
        ]);
        return (int)$stmt->fetchColumn();
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
            'member_id'   => $profileId,
            'credit_id'   => $creditId,
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
            'pin'         => $pin,
            'schedule_id' => $scheduleId,
            'trainer_id'  => $trainerProfileId
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
            'pin'         => $pin
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
        return (int)$stmt->fetchColumn() > 0;
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
            'day'        => $dayOfWeek
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
            'date'       => $date,
            'slot_id'    => $slotId
        ]);
        return (int)$stmt->fetchColumn() > 0;
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
            'gym_id'       => $data['gym_id'],
            'branch_id'    => $data['branch_id'],
            'trainer_id'   => $data['trainer_id'], // trainer_profile_id
            'session_date' => $data['session_date'],
            'slot_id'      => $data['slot_id']
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
            'member_id'   => $memberProfileId
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
            'member_id'   => $memberProfileId,
            'reason'      => $formattedReason
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
            'trainer_id'  => $trainerProfileId
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
            'trainer_id'  => $trainerProfileId,
            'reason'      => $formattedReason
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
            'status'      => $status,
            'schedule_id' => $scheduleId
        ]);
    }
}
