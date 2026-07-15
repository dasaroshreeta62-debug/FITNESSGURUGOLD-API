# Personal Training (PT) Module - New API Documentation

This document describes the request/response payloads, authentication, query filters, and usage details for the five newly introduced PT endpoints.

---

## 1. Get Trainer's Weekly Template Availability
Retrieve the logged-in trainer's baseline repeating weekly availability slot settings.

* **URL**: `/api/trainer/availability/template`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <TRAINER_JWT_TOKEN>`
* **Query Parameters**: None
* **Role Allowed**: `TRAINER`

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Weekly recurring template availability fetched successfully",
  "data": {
    "1": [
      {
        "slot_id": 16,
        "slot_name": "Morning Slot 1",
        "start_time": "06:00:00",
        "end_time": "07:30:00"
      }
    ],
    "2": [],
    "3": [
      {
        "slot_id": 18,
        "slot_name": "Evening Slot 1",
        "start_time": "18:00:00",
        "end_time": "19:30:00"
      }
    ],
    "4": [],
    "5": [],
    "6": [],
    "7": []
  }
}
```

---

## 2. Get Trainers List with Assigned Client Capacity (Admin dropdown helper)
Retrieve a list of all active trainers and the count of their primary client assignments to determine capacity.

* **URL**: `/api/admin/pt/trainers-capacity`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Query Parameters**: None
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Trainers list and client assignment capacities fetched successfully",
  "data": [
    {
      "user_id": 489,
      "trainer_user_id": 489,
      "employee_id": 12,
      "employee_code": "EMP0489",
      "trainer_id": 5,
      "trainer_profile_id": 5,
      "trainer_name": "Abhinav Senapati",
      "trainer_email": "abhinavsenapati@fg.org.in",
      "trainer_phone": "+919876543210",
      "profile_photo_url": "uploads/trainers/abhinav_profile.jpg",
      "pose_photo_url": "uploads/trainers/abhinav.jpg",
      "specialization": "Strength & Conditioning",
      "experience": 5,
      "certifications": "ACE Certified, CPR/AED",
      "bio": "Passionate about health and fitness.",
      "availability_status": "AVAILABLE",
      "rating": 4.8,
      "assigned_clients_count": 2
    },
    {
      "user_id": 567,
      "trainer_user_id": 567,
      "employee_id": 18,
      "employee_code": "EMP0567",
      "trainer_id": 2,
      "trainer_profile_id": 2,
      "trainer_name": "bidyulata biswal",
      "trainer_email": "bidyu49@gmail.com",
      "trainer_phone": "+919876543211",
      "profile_photo_url": null,
      "pose_photo_url": null,
      "specialization": "Yoga & Pilates",
      "experience": 3,
      "certifications": "RYT 200, First Aid",
      "bio": "Helping you find balance and flexibility.",
      "availability_status": "AVAILABLE",
      "rating": 4.5,
      "assigned_clients_count": 0
    }
  ]
}
```

---

## 2b. Get Trainers with Assigned Members List
Retrieve a structured list of all trainers and the members currently assigned under them for Personal Training (PT). Supports optional filtering by trainer, gym, and branch.

* **URL**: `/api/admin/pt/trainers-members`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Query Parameters (Optional)**:
  * `trainer_id`: Filter by trainer profile ID (integer).
  * `gym_id`: Filter by gym ID (integer).
  * `branch_id`: Filter by branch ID (integer).
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Trainers and their assigned members fetched successfully",
  "data": [
    {
      "trainer_id": 5,
      "trainer_user_id": 489,
      "trainer_name": "Abhinav Senapati",
      "trainer_email": "abhinavsenapati@fg.org.in",
      "trainer_phone": "+919876543210",
      "employee_code": "EMP0489",
      "specialization": "Strength & Conditioning",
      "availability_status": "AVAILABLE",
      "gym_id": 1,
      "branch_id": 1,
      "members": [
        {
          "assignment_id": 4,
          "member_profile_id": 69,
          "member_user_id": 138,
          "member_name": "Ankit Das",
          "member_email": "ankit.das@fg.com",
          "member_phone": "8249801450",
          "assigned_at": "2026-07-04 16:04:51"
        }
      ]
    }
  ]
}
```

---

## 3. Get PT Dashboard Statistics
Retrieve aggregate stats about active member allocations, total trainers, remaining credits, and a session status breakdown.

* **URL**: `/api/admin/pt/dashboard-stats`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Query Parameters**: None
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "PT management dashboard statistics fetched successfully",
  "data": {
    "sessions_status_breakdown": {
      "AVAILABLE": 1,
      "ATTENDED": 1,
      "TRAINER_ABSENT": 1,
      "RESOLVED_BY_ADMIN": 2,
      "MUTUAL_ABSENCE": 1,
      "EXPIRED_UNCLAIMED": 1
    },
    "active_assignments_count": 3,
    "active_trainers_count": 3,
    "total_unused_credits": 20
  }
}
```

---

## 4. Get Filtered PT Sessions
Retrieve a list of PT booking sessions with flexible query filters for date ranges, trainers, members, and status.

* **URL**: `/api/admin/pt/sessions`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`
* **Query Parameters (Optional)**:
  * `status`: Filter by session status (`AVAILABLE`, `PENDING`, `ATTENDED`, `MEMBER_NO_SHOW`, `TRAINER_ABSENT`, `DISPUTED`, `RESOLVED_BY_ADMIN`, `MUTUAL_ABSENCE`, `EXPIRED_UNCLAIMED`).
  * `trainer_id`: Filter by trainer profile ID (integer).
  * `member_id`: Filter by member profile ID (integer).
  * `start_date`: Filter sessions starting from this date (`YYYY-MM-DD`).
  * `end_date`: Filter sessions ending by this date (`YYYY-MM-DD`).

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "PT sessions list fetched successfully",
  "count": 1,
  "data": [
    {
      "schedule_id": 33,
      "session_date": "2026-07-10",
      "session_status": "RESOLVED_BY_ADMIN",
      "workout_summary": " // [T-D-L]: Client did not attend // [M-D-L]: I was present at front desk",
      "session_note": " // [T-D-L]: Client did not attend // [M-D-L]: I was present at front desk",
      "verification_pin": null,
      "member_id": 69,
      "member_name": "Ankit Das",
      "member_email": "ankit.das@fg.com",
      "trainer_id": 5,
      "trainer_name": "Abhinav Senapati",
      "trainer_email": "abhinavsenapati@fg.org.in",
      "slot_id": 16,
      "slot_name": "Morning Slot 1",
      "start_time": "06:00:00",
      "end_time": "07:30:00"
    }
  ]
}
```

---

## 5. Get Disputed PT Sessions
Retrieve a list of sessions that are currently flagged as `DISPUTED`, which requires immediate admin arbitration.

* **URL**: `/api/admin/pt/disputes`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Query Parameters**: None
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Disputed PT sessions fetched successfully",
  "count": 0,
  "data": []
}
```

## 6. Get PT Subscriptions List
Retrieve a list of personal training subscriptions exclusively, along with member details, plan details, active primary trainer assignments, and invoice details.

* **URL**: `/api/admin/pt/subscriptions`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Query Parameters**:
  - `status` (optional): Filter by subscription status (`1` for active, `0` for inactive)
  - `gym_id` (optional): Filter by gym ID
  - `branch_id` (optional): Filter by branch ID
  - `user_id` (optional): Filter by member user ID
  - `plan_id` (optional): Filter by plan ID
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "PT subscriptions fetched successfully",
  "count": 1,
  "data": [
    {
      "subscription_id": 310,
      "gym_id": 1,
      "branch_id": 1,
      "start_date": "2026-07-12",
      "end_date": "2026-08-12",
      "status": 1,
      "created_at": "2026-07-12 03:46:55",
      "member": {
        "user_id": 138,
        "profile_id": 69,
        "name": "Ankit Das",
        "email": "ankit.das@fg.com",
        "phone": "8249801450"
      },
      "plan": {
        "plan_id": 5,
        "plan_name": "Basic Personal Training",
        "plan_type": "PT_UPGRADE",
        "price": 5000,
        "duration_months": 1
      },
      "trainer_assignment": {
        "assignment_id": 4,
        "trainer_profile_id": 5,
        "trainer_user_id": 489,
        "trainer_name": "Abhinav Senapati",
        "trainer_email": "abhinavsenapati@fg.org.in",
        "trainer_phone": "9999999999",
        "assignment_type": "PRIMARY",
        "assigned_at": "2026-07-04 16:04:51"
      },
      "invoices": [
        {
          "invoice_id": 9,
          "invoice_number": "INV-20260712-785356C5",
          "final_amount": 5000,
          "issued_at": "2026-07-12 03:46:55",
          "status": "PAID"
        }
      ]
    }
  ]
}
```

---

## Error Handling Standards
If authorization fails or parameters are invalid, the APIs return standard error payloads:

### Unauthorized Access (`401/403`)
```json
{
  "status": "error",
  "message": "Access denied. Authorized role required."
}
```

### Invalid Arguments / Bad Request (`400`)
```json
{
  "status": "error",
  "message": "start_date filter must be in YYYY-MM-DD format"
}
```

---

# Payroll & Trainer Commissions API Documentation

This section documents the five endpoints introduced for the PT Payroll & Commission Management module.

---

## 7. Nightly PT Package Completion Job(cron job 12:01 am daily)

Scans all active PT subscriptions whose calendar duration expired on the target date, books a 70% trainer commission as `UNPAID`, and marks each subscription as completed. Designed to be called by a server cron at **00:01 AM** daily.

* **URL**: `/api/v1/jobs/pt/process-completed-durations`
* **Method**: `POST`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Request Payload (Optional)
```json
{
  "target_date": "2026-07-11"
}
```
> If `target_date` is omitted, defaults to `CURRENT_DATE - 1 day`.

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "PT package completion sweep executed successfully.",
  "data": {
    "target_date": "2026-07-11",
    "packages_completed": 3,
    "total_commission_booked": "21000.00",
    "commissions_generated": [
      {
        "commission_id": 88,
        "trainer_id": 4,
        "invoice_id": 101,
        "amount": "7000.00"
      }
    ]
  }
}
```

**Notes:**
- Subscriptions with no invoice or no assigned trainer are still marked completed but no commission is booked.
- If a commission already exists for an `invoice_id`, the booking is skipped (double-credit guard).
- All DB operations run inside an atomic transaction.

---

## 8. Get PT Commissions (Admin Audit)

View and audit all generated PT trainer commissions with rich filtering options.

* **URL**: `/api/v1/admin/trainer-commissions`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Query Parameters (All Optional)
| Parameter | Type | Description | Example |
|---|---|---|---|
| `status` | String | Filter by status: `UNPAID`, `PAID`, `VOIDED` | `UNPAID` |
| `time_frame` | String | Shortcuts: `current_month`, `previous_month`, `all` | `current_month` |
| `month` | Integer | Explicit calendar month filter (1–12) | `7` |
| `year` | Integer | Explicit calendar year filter | `2026` |
| `trainer_id` | Integer | Filter commissions for a specific trainer profile ID | `4` |
| `branch_id` | Integer | Filter commissions for a specific gym branch | `1` |
| `page` | Integer | Pagination page (default: 1) | `1` |
| `limit` | Integer | Records per page (default: 20, max: 100) | `50` |

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "data": {
    "pagination": {
      "current_page": 1,
      "limit": 50,
      "total_records": 2,
      "total_pages": 1
    },
    "summary_metrics": {
      "filtered_total_commission_amount": "21000.00"
    },
    "commissions": [
      {
        "commission_id": 88,
        "gym_id": 1,
        "branch_id": 1,
        "trainer_id": 4,
        "trainer_name": "Amit Kumar",
        "invoice_id": 101,
        "invoice_number": "INV-2026-0091",
        "client_name": "Rahul Sharma",
        "commission_amount": "7000.00",
        "status": "UNPAID",
        "payroll_id": null,
        "earned_at": "2026-07-01 00:01:00",
        "paid_at": null
      }
    ]
  }
}
```

---

## 9. Manual Off-Cycle PT Commission Payout

Manually disburse an UNPAID trainer commission immediately (off-cycle, outside the normal payroll run). Records the outflow in `financial_ledger`. The `payroll_id` on the commission remains `NULL` to indicate it was not part of a payroll run.

* **URL**: `/api/v1/admin/trainer-commissions/{commission_id}/pay-early`
* **Method**: `POST`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Request Payload
```json
{
  "payment_method": "BANK_TRANSFER",
  "remarks": "Early payout requested by trainer for Diwali festival"
}
```

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "PT commission disbursed early and recorded in master ledger.",
  "data": {
    "commission_id": 88,
    "trainer_id": 4,
    "amount_paid": "7000.00",
    "payment_method": "BANK_TRANSFER",
    "ledger_reference_id": 612
  }
}
```

### Error: Already Paid (`400`)
```json
{
  "status": "error",
  "message": "This commission has already been disbursed"
}
```

---

## 10. Monthly Payroll Draft Generation(cron job :1st of every month)

Generate DRAFT payroll run rows for all active employees in a branch for a given pay period. Controlled by `include_commissions` flag. Guards against duplicate draft generation.

* **URL**: `/api/v1/jobs/payroll/generate-monthly-drafts`
* **Method**: `POST`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Request Payload
```json
{
  "pay_month": 6,
  "pay_year": 2026,
  "branch_id": 1,
  "include_commissions": true
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `pay_month` | Integer | No | Target month (1–12). Defaults to previous month. |
| `pay_year` | Integer | No | Target 4-digit year. Defaults to previous month's year. |
| `branch_id` | Integer | No | Filter to a specific branch. Omit for all branches. |
| `include_commissions` | Boolean | No | `true` = sum UNPAID PT commissions per trainer into draft. `false` = base salary only. |

### Logic: `include_commissions` Effect
- **`false`**: `commission_amount = 0.00`, trainer's UNPAID commissions remain untouched.
- **`true`**: The backend queries `SUM(commission_amount) FROM trainer_commissions WHERE trainer_id = ? AND status = 'UNPAID'` for each trainer and adds it to the draft. Commissions are NOT yet marked PAID — that happens on `disburse`.

### Success Response (`201 Created`)
```json
{
  "status": "success",
  "message": "Monthly payroll drafts generated successfully.",
  "data": {
    "pay_period": "06/2026",
    "include_commissions": true,
    "total_employees_processed": 14,
    "total_base_salaries": "210000.00",
    "total_unpaid_commissions": "42000.00",
    "total_draft_payout": "252000.00"
  }
}
```

### Error: Duplicate Draft (`400`)
```json
{
  "status": "error",
  "message": "Payroll drafts for 6/2026 (branch_id=1) already exist. Delete or void them before re-generating."
}
```

---

## 11. Salary Disbursement with Split Ledger Accounting

Approves a DRAFT payroll run and disburses salary + PT commissions. Creates two distinct `financial_ledger` entries for transparent accounting.

* **URL**: `/api/v1/admin/payroll/{payroll_id}/disburse`
* **Method**: `POST`
* **Headers**: `Authorization: Bearer <ADMIN_JWT_TOKEN>`
* **Role Allowed**: `ADMIN` or `SUPER-ADMIN`

### Request Payload
```json
{
  "bonus": 1500.00,
  "deductions": 500.00,
  "include_pt_commissions": true,
  "payment_method": "BANK_TRANSFER",
  "remarks": "June 2026 Salary Settlement"
}
```

### Split Ledger Behaviour
| Entry | Condition | Description |
|---|---|---|
| **Entry 1 (Fixed)** | Always (if `base_salary + bonus - deductions > 0`) | `"Staff Base Salary & Bonus - June 2026"` |
| **Entry 2 (Commissions)** | Only if `include_pt_commissions = true` AND trainer has UNPAID commissions | `"Trainer PT Package Commissions - June 2026"` |

All UNPAID commissions for that trainer are bulk-updated to `PAID` and linked with the `payroll_id`.

### Success Response (`200 OK`)
```json
{
  "status": "success",
  "message": "Salary disbursed with split accounting entries successfully.",
  "data": {
    "payroll_id": 18,
    "employee_id": 4,
    "employee_name": "Amit Kumar",
    "total_disbursed": "52000.00",
    "payment_method": "BANK_TRANSFER",
    "ledger_entries_created": [
      {
        "ledger_id": 615,
        "category": "PAYROLL",
        "description": "Staff Base Salary & Bonus - June 2026",
        "amount": "16000.00"
      },
      {
        "ledger_id": 616,
        "category": "PAYROLL",
        "description": "Trainer PT Package Commissions - June 2026",
        "amount": "36000.00"
      }
    ],
    "commissions_locked_count": 3
  }
}
```

### Error: Not a DRAFT (`400`)
```json
{
  "status": "error",
  "message": "Cannot disburse: payroll run status is 'PAID'. Only DRAFT runs can be disbursed."
}
```
