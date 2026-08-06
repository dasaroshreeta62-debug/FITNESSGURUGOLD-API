<?php

require_once __DIR__ . '/../repositories/FinanceModel.php';
require_once __DIR__ . '/../repositories/model.php';
require_once __DIR__ . '/../repositories/MembershipModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class FinanceWorkflow
{
    private FinanceModel $model;
    private Model $baseModel;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->model = new FinanceModel();
        $this->baseModel = new Model();
    }

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

    private function setResponseCode(int $code): void
    {
        if (php_sapi_name() !== 'cli' && !headers_sent()) {
            http_response_code($code);
        }
    }

    /**
     * GET /api/v1/invoices/{invoice_id}
     */
    public function getInvoiceDetails(string $accessToken, int $invoiceId): array
    {
        try {
            // Retrieve caller context
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'MEMBER']);
            $callerUserId = (int)$decoded->sub;
            $callerRole = str_replace(['_', '-'], '', strtoupper($decoded->role ?? ''));

            $details = $this->model->getInvoiceDetails($invoiceId);
            if (!$details) {
                throw new Exception("Invoice not found", 404);
            }

            $invoice = $details['invoice'];

            // Gatekeeper ownership rule for members
            if ($callerRole === 'MEMBER') {
                if ((int)$invoice['user_id'] !== $callerUserId) {
                    throw new Exception("Access denied. You cannot read invoices belonging to other members.", 403);
                }
            }

            // Decode invoice and line items tax_breakdown JSON
            $invoice['tax_breakdown'] = json_decode($invoice['tax_breakdown'], true) ?: new stdClass();
            
            $formattedItems = [];
            foreach ($details['items'] as $item) {
                $item['tax_breakdown'] = json_decode($item['tax_breakdown'], true) ?: new stdClass();
                $formattedItems[] = $item;
            }

            return [
                "status" => "success",
                "data"   => [
                    "invoice"      => $invoice,
                    "line_items"   => $formattedItems,
                    "transactions" => $details['payments']
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * POST /api/v1/promos/validate
     */
    public function validatePromoCode(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'MEMBER']);

            if (empty($data['code']) || empty($data['item_type']) || !isset($data['cart_amount'])) {
                throw new Exception("code, item_type, and cart_amount are required", 400);
            }

            $code = trim($data['code']);
            $itemType = strtoupper(trim($data['item_type'])); // SUBSCRIPTION or PRODUCT or PT_PACKAGE
            $referenceId = isset($data['reference_id']) ? (int)$data['reference_id'] : null;
            $cartAmount = (float)$data['cart_amount'];

            $promo = $this->model->getPromoCode($code);
            if (!$promo) {
                throw new Exception("Invalid, expired, or deactivated promotional code", 404);
            }

            // Usage limits check
            if ($promo['max_uses'] !== null && (int)$promo['times_used'] >= (int)$promo['max_uses']) {
                throw new Exception("Promotional code usage limit has been reached", 400);
            }

            // Category match validation
            $appliesOn = strtoupper($promo['applicable_on']);
            $isValid = false;

            if ($appliesOn === 'ALL') {
                $isValid = true;
            } elseif ($appliesOn === 'SUBSCRIPTIONS' && $itemType === 'SUBSCRIPTION') {
                $isValid = true;
            } elseif ($appliesOn === 'PT_ONLY' && $itemType === 'PT_PACKAGE') {
                $isValid = true;
            } elseif ($appliesOn === 'PRODUCTS' && $itemType === 'PRODUCT') {
                $isValid = true;
            } elseif ($appliesOn === 'SPECIFIC_PLAN' && $itemType === 'SUBSCRIPTION' && $referenceId !== null && (int)$promo['applicable_item_id'] === $referenceId) {
                $isValid = true;
            } elseif ($appliesOn === 'SPECIFIC_PRODUCT' && $itemType === 'PRODUCT' && $referenceId !== null && (int)$promo['applicable_item_id'] === $referenceId) {
                $isValid = true;
            }

            if (!$isValid) {
                throw new Exception("Promotional code is not applicable for this item selection", 400);
            }

            // Math calculations
            $discountVal = (float)$promo['discount_value'];
            $discountAmount = 0.00;

            if ($promo['discount_type'] === 'PERCENTAGE') {
                $discountAmount = round($cartAmount * ($discountVal / 100.0), 2);
            } else {
                $discountAmount = round($discountVal, 2);
            }

            if ($discountAmount > $cartAmount) {
                $discountAmount = $cartAmount;
            }

            $finalPayable = round($cartAmount - $discountAmount, 2);

            return [
                "status" => "success",
                "data"   => [
                    "code"            => $promo['code'],
                    "discount_type"   => $promo['discount_type'],
                    "discount_value"  => $discountVal,
                    "discount_amount" => $discountAmount,
                    "final_payable"   => $finalPayable
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * POST /api/v1/admin/finance/refund
     */
    public function refundInvoice(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);

            if (empty($data['invoice_id'])) {
                throw new Exception("invoice_id is required", 400);
            }

            $invoiceId = (int)$data['invoice_id'];
            $reason = trim($data['reason'] ?? 'Accidental double billing / Admin override');

            $this->model->beginTransaction();

            $this->model->refundInvoiceTransaction($invoiceId, $reason);

            $this->model->commit();

            return [
                "status"  => "success",
                "message" => "Invoice cancelled, payment refunded, trainer commission voided, and services deactivated successfully."
            ];

        } catch (\Throwable $e) {
            if ($this->model->inTransaction()) {
                $this->model->rollBack();
            }
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * GET /api/member/purchase-history
     */
    public function getMemberPurchaseHistory(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['MEMBER']);
            $memberUserId = (int)$decoded->sub;

            // 1. Fetch subscriptions with invoices
            $membershipModel = new MembershipModel();
            $subscriptions = $membershipModel->getAllSubscriptions(['user_id' => $memberUserId]);

            // 2. Fetch product purchases with invoices
            $productPurchases = $this->model->getMemberProductPurchases($memberUserId);

            return [
                "status" => "success",
                "data"   => [
                    "subscriptions"     => $subscriptions,
                    "product_purchases" => $productPurchases
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * GET /api/admin/dashboard-kpis
     * Retrieve system KPIs for Admin dashboard: Revenue Overview and Membership Status.
     */
    /**
     * GET /api/admin/dashboard/revenue-overview
     * Retrieve Revenue Overview KPI (filtered by this_week or this_month).
     */
    public function getRevenueOverview(string $accessToken, array $filters = []): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("Caller profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];
            $branchId = (int)$callerProfile['branch_id'];

            $period = strtolower($filters['period'] ?? $filters['filter'] ?? 'this_week');
            if (in_array($period, ['this_month', 'month'])) {
                $periodKey = 'this_month';
            } else {
                $periodKey = 'this_week';
            }

            $totalMembershipRev = 0.0;
            $totalPtRev         = 0.0;
            $totalOtherRev      = 0.0;
            $totalRevenue       = 0.0;

            $thisPeriodChart = [];
            $lastPeriodChart = [];

            if ($periodKey === 'this_month') {
                $startThisMonth = new DateTime('first day of this month');
                $startThisMonth->setTime(0, 0, 0);

                $endThisMonth = new DateTime('last day of this month');
                $endThisMonth->setTime(23, 59, 59);

                $startLastMonth = new DateTime('first day of last month');
                $startLastMonth->setTime(0, 0, 0);

                $endLastMonth = new DateTime('last day of last month');
                $endLastMonth->setTime(23, 59, 59);

                $startLastMonthStr = $startLastMonth->format('Y-m-d 00:00:00');
                $endThisMonthStr   = $endThisMonth->format('Y-m-d 23:59:59');

                $revenues = $this->model->getRevenueBetweenDates($gymId, $branchId, $startLastMonthStr, $endThisMonthStr);

                $revenueMap = [];
                foreach ($revenues as $r) {
                    $date = $r['invoice_date'];
                    $type = strtoupper($r['item_type']);
                    $val  = (float)$r['total_revenue'];

                    if (!isset($revenueMap[$date])) {
                        $revenueMap[$date] = [
                            'TOTAL'        => 0.0,
                            'SUBSCRIPTION' => 0.0,
                            'PT_PACKAGE'   => 0.0,
                            'OTHER'        => 0.0
                        ];
                    }

                    $revenueMap[$date]['TOTAL'] += $val;
                    if ($type === 'SUBSCRIPTION') {
                        $revenueMap[$date]['SUBSCRIPTION'] += $val;
                    } elseif ($type === 'PT_PACKAGE') {
                        $revenueMap[$date]['PT_PACKAGE'] += $val;
                    } else {
                        $revenueMap[$date]['OTHER'] += $val;
                    }
                }

                $thisMonthDays = (int)$endThisMonth->format('d');
                $lastMonthDays = (int)$endLastMonth->format('d');

                for ($d = 1; $d <= $thisMonthDays; $d++) {
                    $dateStr = $startThisMonth->format('Y-m-') . str_pad($d, 2, '0', STR_PAD_LEFT);
                    if (isset($revenueMap[$dateStr])) {
                        $totalMembershipRev += $revenueMap[$dateStr]['SUBSCRIPTION'];
                        $totalPtRev         += $revenueMap[$dateStr]['PT_PACKAGE'];
                        $totalOtherRev      += $revenueMap[$dateStr]['OTHER'];
                        $totalRevenue       += $revenueMap[$dateStr]['TOTAL'];
                    }
                }

                $weeks = [
                    'Week 1' => [1, 7],
                    'Week 2' => [8, 14],
                    'Week 3' => [15, 21],
                    'Week 4' => [22, 28],
                ];
                if ($thisMonthDays >= 29 || $lastMonthDays >= 29) {
                    $weeks['Week 5'] = [29, 31];
                }

                $labels = array_keys($weeks);

                foreach ($weeks as $wName => $range) {
                    $tSum = 0.0;
                    for ($d = $range[0]; $d <= min($range[1], $thisMonthDays); $d++) {
                        $dStr = $startThisMonth->format('Y-m-') . str_pad($d, 2, '0', STR_PAD_LEFT);
                        $tSum += $revenueMap[$dStr]['TOTAL'] ?? 0.0;
                    }
                    $thisPeriodChart[] = round($tSum, 2);

                    $lSum = 0.0;
                    for ($d = $range[0]; $d <= min($range[1], $lastMonthDays); $d++) {
                        $dStr = $startLastMonth->format('Y-m-') . str_pad($d, 2, '0', STR_PAD_LEFT);
                        $lSum += $revenueMap[$dStr]['TOTAL'] ?? 0.0;
                    }
                    $lastPeriodChart[] = round($lSum, 2);
                }

                $thisPeriodLabel = 'This Month';
                $lastPeriodLabel = 'Last Month';

            } else {
                $today = new DateTime();
                $dayOfWeek = (int)$today->format('N');
                if ($dayOfWeek === 6) {
                    $startThisWeek = clone $today;
                } else {
                    $startThisWeek = new DateTime('last Saturday');
                }
                $startThisWeek->setTime(0, 0, 0);

                $daysOfWeek = ['Sat', 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri'];
                $labels = $daysOfWeek;

                $thisWeekDates = [];
                $lastWeekDates = [];

                for ($i = 0; $i < 7; $i++) {
                    $dateThis = (clone $startThisWeek)->modify("+$i days");
                    $dateLast = (clone $startThisWeek)->modify("-" . (7 - $i) . " days");

                    $thisWeekDates[$daysOfWeek[$i]] = $dateThis->format('Y-m-d');
                    $lastWeekDates[$daysOfWeek[$i]] = $dateLast->format('Y-m-d');
                }

                $startLastWeekStr = (clone $startThisWeek)->modify('-7 days')->format('Y-m-d 00:00:00');
                $endThisWeekStr   = (clone $startThisWeek)->modify('+6 days')->format('Y-m-d 23:59:59');

                $revenues = $this->model->getRevenueBetweenDates($gymId, $branchId, $startLastWeekStr, $endThisWeekStr);

                $revenueMap = [];
                foreach ($revenues as $r) {
                    $date = $r['invoice_date'];
                    $type = strtoupper($r['item_type']);
                    $val  = (float)$r['total_revenue'];

                    if (!isset($revenueMap[$date])) {
                        $revenueMap[$date] = [
                            'TOTAL'        => 0.0,
                            'SUBSCRIPTION' => 0.0,
                            'PT_PACKAGE'   => 0.0,
                            'OTHER'        => 0.0
                        ];
                    }

                    $revenueMap[$date]['TOTAL'] += $val;
                    if ($type === 'SUBSCRIPTION') {
                        $revenueMap[$date]['SUBSCRIPTION'] += $val;
                    } elseif ($type === 'PT_PACKAGE') {
                        $revenueMap[$date]['PT_PACKAGE'] += $val;
                    } else {
                        $revenueMap[$date]['OTHER'] += $val;
                    }
                }

                foreach ($daysOfWeek as $day) {
                    $tDate = $thisWeekDates[$day];
                    $lDate = $lastWeekDates[$day];

                    $tWeekData = $revenueMap[$tDate] ?? ['TOTAL' => 0.0, 'SUBSCRIPTION' => 0.0, 'PT_PACKAGE' => 0.0, 'OTHER' => 0.0];
                    $lWeekData = $revenueMap[$lDate] ?? ['TOTAL' => 0.0, 'SUBSCRIPTION' => 0.0, 'PT_PACKAGE' => 0.0, 'OTHER' => 0.0];

                    $thisPeriodChart[] = round($tWeekData['TOTAL'], 2);
                    $lastPeriodChart[] = round($lWeekData['TOTAL'], 2);

                    $totalMembershipRev += $tWeekData['SUBSCRIPTION'];
                    $totalPtRev         += $tWeekData['PT_PACKAGE'];
                    $totalOtherRev      += $tWeekData['OTHER'];
                    $totalRevenue       += $tWeekData['TOTAL'];
                }

                $thisPeriodLabel = 'This Week';
                $lastPeriodLabel = 'Last Week';
            }

            return [
                "status" => "success",
                "data"   => [
                    "period"             => $periodKey,
                    "total_revenue"      => round($totalRevenue, 2),
                    "membership_revenue" => round($totalMembershipRev, 2),
                    "pt_revenue"         => round($totalPtRev, 2),
                    "other_revenue"      => round($totalOtherRev, 2),
                    "chart_data"         => [
                        "days"       => $labels,
                        "this_week"  => $thisPeriodChart,
                        "last_week"  => $lastPeriodChart,
                        "this_label" => $thisPeriodLabel,
                        "last_label" => $lastPeriodLabel
                    ]
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * GET /api/admin/dashboard/membership-status
     * Retrieve Membership Status KPI statistics.
     */
    public function getMembershipStatus(string $accessToken): array
    {
        try {
            $decoded = $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);
            $callerUserId = (int)$decoded->sub;

            $callerProfile = $this->baseModel->getUserProfileById($callerUserId);
            if (!$callerProfile) {
                throw new Exception("Caller profile not found", 404);
            }

            $gymId = (int)$callerProfile['gym_id'];
            $branchId = (int)$callerProfile['branch_id'];

            $membersData = $this->model->getMembersStatusData($gymId, $branchId);

            $activeCount   = 0;
            $expiringCount = 0;
            $expiredCount  = 0;
            $frozenCount   = 0;

            $now = new DateTime();
            $now->setTime(0,0,0);
            $expLimit = (clone $now)->modify('+7 days');

            foreach ($membersData as $m) {
                $userStatus = (int)$m['user_status'];
                $subStatus  = $m['sub_status'] !== null ? (int)$m['sub_status'] : null;
                $endDateStr = $m['end_date'];

                if ($userStatus === 2) {
                    $frozenCount++;
                } elseif ($userStatus === 0) {
                    $expiredCount++;
                } elseif (empty($endDateStr) || $subStatus !== 1) {
                    $expiredCount++;
                } else {
                    $endDate = new DateTime($endDateStr);
                    $endDate->setTime(0,0,0);

                    if ($endDate < $now) {
                        $expiredCount++;
                    } elseif ($endDate >= $now && $endDate <= $expLimit) {
                        $expiringCount++;
                    } else {
                        $activeCount++;
                    }
                }
            }

            $totalMembers = count($membersData);

            $activePct   = $totalMembers > 0 ? round(($activeCount / $totalMembers) * 100, 1) : 0.0;
            $expiringPct = $totalMembers > 0 ? round(($expiringCount / $totalMembers) * 100, 1) : 0.0;
            $expiredPct  = $totalMembers > 0 ? round(($expiredCount / $totalMembers) * 100, 1) : 0.0;
            $frozenPct   = $totalMembers > 0 ? round(($frozenCount / $totalMembers) * 100, 1) : 0.0;

            return [
                "status" => "success",
                "data"   => [
                    "total_members" => $totalMembers,
                    "active"        => ["count" => $activeCount, "percentage" => $activePct],
                    "expiring_soon" => ["count" => $expiringCount, "percentage" => $expiringPct],
                    "expired"       => ["count" => $expiredCount, "percentage" => $expiredPct],
                    "frozen"        => ["count" => $frozenCount, "percentage" => $frozenPct]
                ]
            ];

        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return [
                "status"  => "error",
                "message" => $e->getMessage()
            ];
        }
    }

    /**
     * GET /api/admin/dashboard-kpis
     * Retrieve system KPI metrics summary for Admin dashboard.
     */
    public function getDashboardKpis(string $accessToken, array $filters = []): array
    {
        $revRes = $this->getRevenueOverview($accessToken, $filters);
        if (($revRes['status'] ?? '') === 'error') {
            return $revRes;
        }

        $memRes = $this->getMembershipStatus($accessToken);
        if (($memRes['status'] ?? '') === 'error') {
            return $memRes;
        }

        $revData = $revRes['data'] ?? [];
        $memData = $memRes['data'] ?? [];

        return [
            "status" => "success",
            "data"   => [
                "total_members"        => $memData['total_members'] ?? 0,
                "active_memberships"   => $memData['active']['count'] ?? 0,
                "expiring_memberships" => $memData['expiring_soon']['count'] ?? 0,
                "expired_memberships"  => $memData['expired']['count'] ?? 0,
                "frozen_memberships"   => $memData['frozen']['count'] ?? 0,
                "total_revenue"        => $revData['total_revenue'] ?? 0.0,
                "membership_revenue"   => $revData['membership_revenue'] ?? 0.0,
                "pt_revenue"           => $revData['pt_revenue'] ?? 0.0,
                "other_revenue"        => $revData['other_revenue'] ?? 0.0
            ]
        ];
    }

    /**
     * Get Executive Profit & Loss Summary. Admin & Staff only.
     */
    public function getExecutiveSummary(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);

            $data = $this->model->getExecutiveSummary($filters);
            return [
                "status" => "success",
                "data"   => $data
            ];
        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get Operational Expenses logs. Admin & Staff only.
     */
    public function getOpexLogs(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);

            $data = $this->model->getOpexLogs($filters);
            return [
                "status" => "success",
                "data"   => $data
            ];
        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Log a new Operational Expense. Admin & Staff only.
     */
    public function logOpex(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);

            if (empty($data['title']) || empty($data['amount'])) {
                throw new Exception("Title and amount are required", 400);
            }

            $opexId = $this->model->logOpex($data);
            return [
                "status"  => "success",
                "message" => "Operating expense logged successfully",
                "opex_id" => $opexId
            ];
        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Cancel/Void an Operational Expense. Admin only.
     */
    public function cancelOpex(string $accessToken, int $opexId, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN']);

            $reason = !empty($data['cancellation_reason']) ? $data['cancellation_reason'] : 'Cancelled by Admin';
            $this->model->cancelOpex($opexId, $reason);

            return [
                "status"  => "success",
                "message" => "Operating expense cancelled successfully"
            ];
        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Get Master Financial Ledger logs. Admin & Staff only.
     */
    public function getLedgerLogs(string $accessToken, array $filters = []): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);

            $data = $this->model->getLedgerLogs($filters);
            return [
                "status" => "success",
                "data"   => $data
            ];
        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }

    /**
     * Log manual financial adjustment. Admin & Staff only.
     */
    public function logLedgerAdjustment(string $accessToken, array $data): array
    {
        try {
            $this->verifyRole($accessToken, ['ADMIN', 'SUPER-ADMIN', 'GYM_ADMIN', 'STAFF']);

            if (empty($data['amount'])) {
                throw new Exception("Amount is required", 400);
            }

            $this->model->logLedgerAdjustment($data);

            return [
                "status"  => "success",
                "message" => "Financial adjustment logged successfully"
            ];
        } catch (\Throwable $e) {
            $code = in_array($e->getCode(), [400, 401, 403, 404]) ? $e->getCode() : 500;
            $this->setResponseCode($code);
            return ["status" => "error", "message" => $e->getMessage()];
        }
    }
}

