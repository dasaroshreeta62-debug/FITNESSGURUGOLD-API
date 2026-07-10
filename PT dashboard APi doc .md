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
      "trainer_user_id": 489,
      "trainer_profile_id": 5,
      "trainer_name": "Abhinav Senapati",
      "trainer_email": "abhinavsenapati@fg.org.in",
      "assigned_clients_count": 2
    },
    {
      "trainer_user_id": 567,
      "trainer_profile_id": 2,
      "trainer_name": "bidyulata biswal",
      "trainer_email": "bidyu49@gmail.com",
      "assigned_clients_count": 0
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
