<?php

require_once __DIR__ . '/../repositories/AttendanceModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AttendanceWorkflow
{
    private AttendanceModel $model;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';
    private const ALLOWED_SOURCES = ['DEVICE', 'WEB', 'MOBILE', 'DESKTOP', 'ADMIN'];

    public function __construct()
    {
        $this->model = new AttendanceModel();
    }

    private function authenticate(string $token): object
    {
        return JWT::decode($token, new Key(self::JWT_SECRET, 'HS256'));
    }

    public function checkIn(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->authenticate($accessToken);
            $userIdFromToken = (int)($decoded->sub ?? 0);

            $userId = !empty($data['user_id']) ? (int)$data['user_id'] : $userIdFromToken;
            if (!$userId) {
                http_response_code(400);
                return [
                    "status" => "error",
                    "message" => "user_id is required"
                ];
            }

            $gymId = !empty($data['gym_id']) ? (int)$data['gym_id'] : 1;
            $branchId = !empty($data['branch_id']) ? (int)$data['branch_id'] : 1;

            $source = strtoupper($data['source'] ?? 'DEVICE');
            if (!in_array($source, self::ALLOWED_SOURCES, true)) {
                $source = 'DEVICE';
            }

            $result = $this->model->checkIn([
                'user_id'         => $userId,
                'gym_id'          => $gymId,
                'branch_id'       => $branchId,
                'attendance_date' => $data['attendance_date'] ?? date('Y-m-d'),
                'check_in_time'   => $data['check_in_time'] ?? date('Y-m-d H:i:s'),
                'source'          => $source,
                'remarks'         => $data['remarks'] ?? null
            ]);

            if ($result['already_exists']) {
                http_response_code(409);
                return [
                    "status" => "error",
                    "message" => "User already checked in for today (" . ($result['record']['attendance_date'] ?? date('Y-m-d')) . ")",
                    "data" => $result['record']
                ];
            }

            http_response_code(201);
            return [
                "status"  => "success",
                "message" => "Check-in recorded successfully",
                "data"    => $result['record']
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Failed to record check-in",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function checkOut(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->authenticate($accessToken);
            $userIdFromToken = (int)($decoded->sub ?? 0);

            $userId = !empty($data['user_id']) ? (int)$data['user_id'] : $userIdFromToken;
            $attendanceId = !empty($data['attendance_id']) ? (int)$data['attendance_id'] : null;

            if (!$userId && !$attendanceId) {
                http_response_code(400);
                return [
                    "status" => "error",
                    "message" => "user_id or attendance_id is required"
                ];
            }

            $record = $this->model->checkOut([
                'attendance_id'   => $attendanceId,
                'user_id'         => $userId,
                'attendance_date' => $data['attendance_date'] ?? date('Y-m-d'),
                'check_out_time'  => $data['check_out_time'] ?? date('Y-m-d H:i:s'),
                'remarks'         => $data['remarks'] ?? null
            ]);

            if (!$record) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "No active attendance record found for checkout"
                ];
            }

            return [
                "status"  => "success",
                "message" => "Checked out successfully",
                "data"    => $record
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Checkout failed",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function listAttendance(string $accessToken, array $filters): array
    {
        try {
            $this->authenticate($accessToken);

            $result = $this->model->listAttendance($filters);

            return [
                "status"     => "success",
                "pagination" => [
                    "total"       => $result['total'],
                    "page"        => $result['page'],
                    "limit"       => $result['limit'],
                    "total_pages" => $result['total_pages']
                ],
                "data"       => $result['records']
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Failed to fetch attendance list",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function getAttendanceDetails(string $accessToken, ?int $userId = null, ?string $date = null, ?int $attendanceId = null): array
    {
        try {
            $decoded = $this->authenticate($accessToken);

            if (!$userId && !$attendanceId) {
                $userId = (int)($decoded->sub ?? 0);
            }

            if (!$date && !$attendanceId) {
                $date = date('Y-m-d');
            }

            $record = $this->model->getAttendanceDetails($userId, $date, $attendanceId);

            if (!$record) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "Attendance record not found"
                ];
            }

            return [
                "status" => "success",
                "data"   => $record
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Failed to retrieve attendance details",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function markOrUpdateAttendance(string $accessToken, array $data): array
    {
        try {
            $this->authenticate($accessToken);

            if (empty($data['attendance_id']) && empty($data['user_id'])) {
                http_response_code(400);
                return [
                    "status" => "error",
                    "message" => "user_id or attendance_id is required"
                ];
            }

            if (!empty($data['source'])) {
                $source = strtoupper($data['source']);
                if (!in_array($source, self::ALLOWED_SOURCES, true)) {
                    $data['source'] = 'ADMIN';
                } else {
                    $data['source'] = $source;
                }
            } else {
                $data['source'] = 'ADMIN';
            }

            $result = $this->model->markOrUpdateAttendance($data);

            if (!$result['success']) {
                http_response_code(400);
                return [
                    "status"  => "error",
                    "message" => $result['message']
                ];
            }

            return [
                "status"  => "success",
                "message" => $result['message'],
                "data"    => $result['record']
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Failed to save attendance record",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function deleteAttendance(string $accessToken, int $attendanceId): array
    {
        try {
            $this->authenticate($accessToken);

            if (!$attendanceId) {
                http_response_code(400);
                return [
                    "status" => "error",
                    "message" => "attendance_id is required"
                ];
            }

            $success = $this->model->deleteAttendance($attendanceId);

            if (!$success) {
                http_response_code(404);
                return [
                    "status" => "error",
                    "message" => "Attendance record not found or could not be deleted"
                ];
            }

            return [
                "status"  => "success",
                "message" => "Attendance record deleted successfully"
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "status"  => "error",
                "message" => "Failed to delete attendance record",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function adminManualEntry(string $accessToken, array $data): array
    {
        try {
            $this->authenticate($accessToken);

            $result = $this->model->adminManualEntry($data);

            if (!$result['success']) {
                $status = ($result['code'] ?? '') === 'VISIT_ALREADY_COMPLETED' ? 409 : 400;
                http_response_code($status);
                return $result;
            }

            http_response_code(201);
            return $result;

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "success" => false,
                "code"    => "SERVER_ERROR",
                "message" => "Failed to process admin manual attendance entry",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function memberManualEntry(string $accessToken, array $data): array
    {
        try {
            $decoded = $this->authenticate($accessToken);
            $userId  = (int)($decoded->sub ?? 0);

            if (!$userId) {
                http_response_code(401);
                return [
                    "success" => false,
                    "code"    => "UNAUTHORIZED",
                    "message" => "Invalid authentication token."
                ];
            }

            $result = $this->model->memberManualEntry($userId, $data);

            if (!$result['success']) {
                http_response_code(400);
                return $result;
            }

            http_response_code(200);
            return $result;

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "success" => false,
                "code"    => "SERVER_ERROR",
                "message" => "Failed to process member manual attendance entry",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function getAttendanceLogs(string $accessToken, array $filters): array
    {
        try {
            $decoded = $this->authenticate($accessToken);
            $userRole = strtoupper($decoded->role ?? '');

            if ($userRole === 'MEMBER') {
                $filters['user_id'] = (int)($decoded->sub ?? 0);
            }

            $result = $this->model->getAttendanceLogs($filters);

            return [
                "success" => true,
                "data"    => $result
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "success" => false,
                "code"    => "SERVER_ERROR",
                "message" => "Failed to retrieve attendance logs",
                "error"   => $e->getMessage()
            ];
        }
    }

    public function getTodayAttendance(string $accessToken, ?int $targetUserId = null): array
    {
        try {
            $decoded = $this->authenticate($accessToken);
            $userIdFromToken = (int)($decoded->sub ?? 0);
            $userRole        = strtoupper($decoded->role ?? '');

            $userId = ($userRole !== 'MEMBER' && $targetUserId) ? $targetUserId : $userIdFromToken;

            if (!$userId) {
                http_response_code(400);
                return [
                    "success" => false,
                    "message" => "user_id could not be determined"
                ];
            }

            $record = $this->model->getTodayAttendance($userId);

            return [
                "success" => true,
                "data"    => $record,
                "message" => $record ? "Today's attendance retrieved successfully." : "No attendance record found for today."
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "success" => false,
                "code"    => "SERVER_ERROR",
                "message" => "Failed to retrieve today's attendance",
                "error"   => $e->getMessage()
            ];
        }
    }
}


