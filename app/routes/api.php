<?php

require_once __DIR__ . '/../controllers/controller.php';
require_once __DIR__ . '/../controllers/DietPlanController.php';
require_once __DIR__ . '/../controllers/EmployeeController.php';
require_once __DIR__ . '/../controllers/PersonalTrainingController.php';
require_once __DIR__ . '/../controllers/FitnessAssessmentController.php';
require_once __DIR__ . '/../controllers/MembershipController.php';
require_once __DIR__ . '/../controllers/ShiftController.php';

function route(string $method, string $path): void
{
    // Normalize path (remove trailing slash)
    $path = rtrim($path, '/');

    // Create controller instances
    $controller = new Controller();
    $dietPlanController = new DietPlanController();
    $employeeController = new EmployeeController();
    $personalTrainingController = new PersonalTrainingController();
    $fitnessAssessmentController = new FitnessAssessmentController();
    $membershipController = new MembershipController();
    $shiftController = new ShiftController();

    switch (true) {

        // ================= AUTH ROUTES =================
        case $method === 'POST' && $path === '/api/auth/login':
            $controller->login();
            return;

        case $method === 'POST' && $path === '/api/auth/logout':
            $controller->logout();
            return;
        
        case $method === 'POST' && $path === '/api/auth/register':
            $controller->register();
            return;
        
        case $method === 'GET' && $path === '/api/users/profile':
            $controller->profile();
            return;

        case $method === 'PUT' && $path === '/api/users/update':
            $controller->updateProfile();
            return;
        
        case $method === 'GET' && $path === '/api/users/list':
            $controller->listUsers();
            return;

        case $method === 'GET' && $path === '/api/gyms':
            $controller->getGyms();
            return;

        case $method === 'POST' && $path === '/api/gyms':
            $controller->createGym();
            return;

        case $method === 'GET' && preg_match('#^/api/gyms/(\d+)$#', $path, $matches):
            $controller->getGymDetails((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/gyms/(\d+)$#', $path, $matches):
            $controller->updateGym((int)$matches[1]);
            return;

        case $method === 'GET' && $path === '/api/countryList':
            $controller->listCountry();
            return;

        case $method === 'GET' && $path === '/api/stateList':
            $controller->listState();
            return;
        
        case $method === 'GET' && $path === '/api/districtList':
            $controller->listDistrict();
            return;
        
        case $method === 'GET' && $path === '/api/gymBranchList':
            $controller->listGymBranches();
            return;
        
        case $method === 'GET' && $path === '/api/cityList':
            $controller->listCities();
            return;

        case $method === 'GET' && $path === '/api/shifts':
            $controller->getShifts();
            return;

        case $method === 'POST' && $path === '/api/members/addMember':
            $controller->addMember();
            return;
        
        case $method === 'GET' && $path === '/api/members/view':
            $controller->viewMember();
            return;
        
        case $method === 'GET' && $path === '/api/members/viewAllMembers':
            $controller->viewAllMembers();
            return;

        case $method === 'PUT' && $path === '/api/members/updateMember':
            $controller->updateMember();
            return;
        
        case $method === 'GET' && $path === '/api/membershipPlan':
            $controller->listMembershipPlan();
            return;

        case $method === 'POST' && $path === '/api/attendance/checkIn':
            $controller->addAttendance();
            return;
        case $method === 'PUT' && $path === '/api/attendance/checkOut':
            $controller->checkOutAttendance();
            return;

        case $method === 'PUT' && $path === '/api/attendance/viewAttendanceList':
            $controller->listAttendance();
            return;

        case $method === 'GET' && $path === '/api/attendance/userSessions':
            $controller->viewUserAttendanceWithSessions();
            return;

        case $method === 'POST' && $path === '/api/addContactUs':
            $controller->submitContactForm();
            return;

        case $method === 'GET' && $path === '/api/viewContactUs':
            $controller->getContactList();
            return;

        case $method === 'GET' && $path === '/api/trainer/profile':
            $controller->getTrainerProfile();
            return;

        case $method === 'GET' && $path === '/api/trainer/trainees':
            $controller->getAssignedTrainees();
            return;

        case $method === 'POST' && $path === '/api/trainer/addTrainer':
            $controller->addTrainer();
            return;
        
        case $method === 'GET' && $path === '/api/trainer/getTrainers':
            $controller->getTrainers();
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/getTrainer/(\d+)$#', $path, $matches):
            $controller->getTrainerById((int)$matches[1]);
            return;
        
        case $method === 'PUT' && preg_match('#^/api/trainer/updateTrainer/(\d+)$#', $path, $matches):
            $controller->updateTrainer((int)$matches[1]);
            return;

        //=============Employee Onboarding & Directory APIs==========
        case $method === 'POST' && $path === '/api/employees/onboard':
            $employeeController->onboardEmployee();
            return;

        case $method === 'POST' && $path === '/api/trainers/onboard':
            $employeeController->onboardTrainer();
            return;

        case $method === 'GET' && preg_match('#^/api/employees/(\d+)$#', $path, $matches):
            $employeeController->getEmployee((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/trainers/(\d+)$#', $path, $matches):
            $employeeController->getTrainer((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/employees/(\d+)$#', $path, $matches):
            $employeeController->updateEmployee((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/trainers/(\d+)$#', $path, $matches):
            $employeeController->updateTrainer((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/employees/(\d+)/documents$#', $path, $matches):
            $employeeController->updateEmployeeDocuments((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/employees/(\d+)/status$#', $path, $matches):
            $employeeController->updateEmployeeStatus((int)$matches[1]);
            return;

        case $method === 'GET' && $path === '/api/employees':
            $employeeController->listEmployees();
            return;

        case $method === 'GET' && $path === '/api/trainers':
            $employeeController->listTrainers();
            return;

        //=============Diet Plan APIs==========
        //Admin Diet Plan APIs
        case $method === 'POST' && $path === '/api/admin/diet-plans':
            $dietPlanController->createDietPlan();
            return;

        case $method === 'POST' && $path === '/api/admin/diet-plans/collective':
            $dietPlanController->createDietPlanWithMeals();
            return;

        case $method === 'GET' && $path === '/api/admin/gym-branches':
            $controller->getAdminGymBranches();
            return;

        // ================= PERSONAL TRAINING ROUTES =================
        case $method === 'GET' && $path === '/api/trainer/availability/template':
            $personalTrainingController->getWeeklyTemplate();
            return;

        case $method === 'GET' && $path === '/api/admin/pt/trainers-capacity':
            $personalTrainingController->getTrainersCapacity();
            return;

        case $method === 'GET' && $path === '/api/admin/pt/dashboard-stats':
            $personalTrainingController->getDashboardStats();
            return;

        case $method === 'GET' && $path === '/api/admin/pt/sessions':
            $personalTrainingController->getSessions();
            return;

        case $method === 'GET' && $path === '/api/admin/pt/disputes':
            $personalTrainingController->getDisputes();
            return;

        case $method === 'POST' && $path === '/api/admin/pt/manual-purchase':
            $personalTrainingController->manualPurchase();
            return;

        case $method === 'POST' && $path === '/api/admin/pt/assign-trainer':
            $personalTrainingController->assignTrainer();
            return;

        case $method === 'POST' && $path === '/api/admin/pt/generate-schedule':
            $personalTrainingController->generateSchedule();
            return;

        case $method === 'POST' && $path === '/api/trainer/availability/template':
            $personalTrainingController->setWeeklyTemplate();
            return;

        case $method === 'GET' && $path === '/api/trainer/roster':
            $personalTrainingController->getTrainerRoster();
            return;

        case $method === 'GET' && $path === '/api/member/pt/available-slots':
            $personalTrainingController->getMemberAvailableSlots();
            return;

        case $method === 'POST' && $path === '/api/member/pt/book':
            $personalTrainingController->bookSlot();
            return;

        case $method === 'POST' && $path === '/api/trainer/session/complete':
            $personalTrainingController->initiateSessionComplete();
            return;

        case $method === 'POST' && $path === '/api/pt/session/verify':
            $personalTrainingController->verifySessionComplete();
            return;

        case $method === 'POST' && $path === '/api/member/session/report-absence':
            $personalTrainingController->reportTrainerAbsence();
            return;

        case $method === 'POST' && $path === '/api/member/session/dispute':
            $personalTrainingController->disputeNoShow();
            return;

        case $method === 'POST' && $path === '/api/trainer/session/release':
            $personalTrainingController->releaseSession();
            return;

        case $method === 'POST' && $path === '/api/trainer/session/no-show':
            $personalTrainingController->flagNoShow();
            return;

        case $method === 'POST' && $path === '/api/admin/session/resolve-trainer':
            $personalTrainingController->resolveDisputeTrainer();
            return;

        case $method === 'POST' && $path === '/api/admin/session/resolve-member':
            $personalTrainingController->resolveDisputeMember();
            return;

        case $method === 'POST' && $path === '/api/admin/pt/nightly-evaluation':
            $personalTrainingController->nightlyEvaluation();
            return;

        case $method === 'POST' && $path === '/api/assessments':
            $fitnessAssessmentController->createAssessment();
            return;

        case $method === 'GET' && preg_match('#^/api/assessments/(\d+)$#', $path, $matches):
            $fitnessAssessmentController->getAssessment((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/members/(\d+)/assessments$#', $path, $matches):
            $fitnessAssessmentController->getMemberAssessments((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/members/(\d+)/assessments/latest$#', $path, $matches):
            $fitnessAssessmentController->getLatestMemberAssessment((int)$matches[1]);
            return;

        // ================= MEMBERSHIP PLANS & SUBSCRIPTIONS =================
        case $method === 'GET' && $path === '/api/membership-plans':
            $membershipController->listMembershipPlans();
            return;

        case $method === 'GET' && preg_match('#^/api/membership-plans/(\d+)$#', $path, $matches):
            $membershipController->getMembershipPlanDetails((int)$matches[1]);
            return;

        case $method === 'POST' && $path === '/api/admin/membership-plans':
            $membershipController->createMembershipPlan();
            return;

        case $method === 'PUT' && preg_match('#^/api/admin/membership-plans/(\d+)$#', $path, $matches):
            $membershipController->updateMembershipPlan((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/membership-plans/(\d+)$#', $path, $matches):
            $membershipController->deleteMembershipPlan((int)$matches[1]);
            return;

        case $method === 'POST' && preg_match('#^/api/admin/membership-plans/(\d+)/entitlements$#', $path, $matches):
            $membershipController->managePlanEntitlements((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/membership-plans/(\d+)/entitlements/([A-Z0-9_]+)$#', $path, $matches):
            $membershipController->deleteSingleEntitlement((int)$matches[1], $matches[2]);
            return;

        case $method === 'GET' && $path === '/api/admin/subscriptions':
            $membershipController->listSubscriptions();
            return;

        case $method === 'GET' && preg_match('#^/api/admin/subscriptions/(\d+)$#', $path, $matches):
            $membershipController->getSubscriptionDetails((int)$matches[1]);
            return;

        case $method === 'POST' && $path === '/api/admin/subscriptions':
            $membershipController->createSubscription();
            return;

        case $method === 'PUT' && preg_match('#^/api/admin/subscriptions/(\d+)$#', $path, $matches):
            $membershipController->updateSubscription((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/admin/subscriptions/(\d+)/cancel$#', $path, $matches):
            $membershipController->cancelSubscription((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/subscriptions/(\d+)$#', $path, $matches):
            $membershipController->cancelSubscription((int)$matches[1]);
            return;

        case $method === 'GET' && $path === '/api/member/subscriptions/active':
            $membershipController->getMyActiveSubscription();
            return;

        // ================= GYM SHIFTS & PT SLOTS =================
        case $method === 'GET' && $path === '/api/admin/shifts':
            $shiftController->listShifts();
            return;

        case $method === 'GET' && preg_match('#^/api/admin/shifts/(\d+)$#', $path, $matches):
            $shiftController->getShiftDetails((int)$matches[1]);
            return;

        case $method === 'POST' && $path === '/api/admin/shifts':
            $shiftController->createShift();
            return;

        case $method === 'PUT' && preg_match('#^/api/admin/shifts/(\d+)$#', $path, $matches):
            $shiftController->updateShift((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/shifts/(\d+)$#', $path, $matches):
            $shiftController->deleteShift((int)$matches[1]);
            return;

        case $method === 'GET' && $path === '/api/admin/pt-slots':
            $shiftController->listSlots();
            return;

        case $method === 'GET' && preg_match('#^/api/admin/pt-slots/(\d+)$#', $path, $matches):
            $shiftController->getSlotDetails((int)$matches[1]);
            return;

        case $method === 'POST' && $path === '/api/admin/pt-slots':
            $shiftController->createSlot();
            return;

        case $method === 'PUT' && preg_match('#^/api/admin/pt-slots/(\d+)$#', $path, $matches):
            $shiftController->updateSlot((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/pt-slots/(\d+)$#', $path, $matches):
            $shiftController->deleteSlot((int)$matches[1]);
            return;

        case $method === 'GET' && $path === '/api/admin/diet-plans':
            $dietPlanController->listDietPlans();
            return;

        case $method === 'GET' && preg_match('#^/api/admin/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->getDietPlanDetails((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/admin/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->updateDietPlan((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->deleteDietPlan((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/admin/diet-plans/(\d+)/activate$#', $path, $matches):
            $dietPlanController->activateDietPlan((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/admin/diet-plans/(\d+)/status$#', $path, $matches):
            $dietPlanController->changeDietPlanStatus((int)$matches[1]);
            return;

        case $method === 'POST' && preg_match('#^/api/admin/diet-plans/(\d+)/clone$#', $path, $matches):
            $dietPlanController->cloneDietPlan((int)$matches[1]);
            return;

        // Admin Meal APIs
        case $method === 'POST' && preg_match('#^/api/admin/diet-plans/(\d+)/meals$#', $path, $matches):
            $dietPlanController->createMeal((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/admin/diet-plans/(\d+)/meals$#', $path, $matches):
            $dietPlanController->listDietPlanMeals((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/admin/meals/(\d+)$#', $path, $matches):
            $dietPlanController->getMealDetails((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/admin/meals/(\d+)$#', $path, $matches):
            $dietPlanController->updateMeal((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/admin/meals/(\d+)$#', $path, $matches):
            $dietPlanController->deleteMeal((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/admin/diet-plans/(\d+)/meals/order$#', $path, $matches):
            $dietPlanController->reorderMeals((int)$matches[1]);
            return;

        // Admin Member Specific Diet Plans APIs
        case $method === 'GET' && preg_match('#^/api/admin/members/(\d+)/diet-plans$#', $path, $matches):
            $dietPlanController->getMemberDietPlans((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/admin/members/(\d+)/diet-plans/active$#', $path, $matches):
            $dietPlanController->getMemberActiveDietPlan((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/admin/members/(\d+)/diet-plans/history$#', $path, $matches):
            $dietPlanController->getMemberDietPlansHistory((int)$matches[1]);
            return;

        //Trainer Diet Plan APIs
        case $method === 'GET' && $path === '/api/trainer/members':
            $dietPlanController->listTrainerAssignedMembers();
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/members/(\d+)$#', $path, $matches):
            $dietPlanController->getTrainerAssignedMemberDetails((int)$matches[1]);
            return;

        case $method === 'POST' && preg_match('#^/api/trainer/members/(\d+)/diet-plans$#', $path, $matches):
            $dietPlanController->createDietPlanByTrainer((int)$matches[1]);
            return;

        case $method === 'POST' && preg_match('#^/api/trainer/members/(\d+)/diet-plans/collective$#', $path, $matches):
            $dietPlanController->createDietPlanWithMealsByTrainer((int)$matches[1]);
            return;

        case $method === 'GET' && $path === '/api/trainer/diet-plans':
            $dietPlanController->listTrainerDietPlans();
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->getDietPlanDetailsByTrainer((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/trainer/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->updateDietPlanByTrainer((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/trainer/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->deleteDietPlanByTrainer((int)$matches[1]);
            return;

        case $method === 'POST' && preg_match('#^/api/trainer/diet-plans/(\d+)/clone$#', $path, $matches):
            $dietPlanController->cloneDietPlanByTrainer((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/trainer/diet-plans/(\d+)/activate$#', $path, $matches):
            $dietPlanController->activateDietPlanByTrainer((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/trainer/diet-plans/(\d+)/status$#', $path, $matches):
            $dietPlanController->changeDietPlanStatusByTrainer((int)$matches[1]);
            return;

        // Trainer Meal APIs
        case $method === 'POST' && preg_match('#^/api/trainer/diet-plans/(\d+)/meals$#', $path, $matches):
            $dietPlanController->createMealByTrainer((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/diet-plans/(\d+)/meals$#', $path, $matches):
            $dietPlanController->listDietPlanMealsByTrainer((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/meals/(\d+)$#', $path, $matches):
            $dietPlanController->getMealDetailsByTrainer((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/trainer/meals/(\d+)$#', $path, $matches):
            $dietPlanController->updateMealByTrainer((int)$matches[1]);
            return;

        case $method === 'DELETE' && preg_match('#^/api/trainer/meals/(\d+)$#', $path, $matches):
            $dietPlanController->deleteMealByTrainer((int)$matches[1]);
            return;

        case $method === 'PATCH' && preg_match('#^/api/trainer/diet-plans/(\d+)/meals/order$#', $path, $matches):
            $dietPlanController->reorderMealsByTrainer((int)$matches[1]);
            return;

        // Trainer Member Specific Diet Plans APIs
        case $method === 'GET' && preg_match('#^/api/trainer/members/(\d+)/diet-plans$#', $path, $matches):
            $dietPlanController->getMemberDietPlansByTrainer((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/members/(\d+)/diet-plans/active$#', $path, $matches):
            $dietPlanController->getMemberActiveDietPlanByTrainer((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/trainer/members/(\d+)/diet-plans/history$#', $path, $matches):
            $dietPlanController->getMemberDietPlansHistoryByTrainer((int)$matches[1]);
            return;
        
        //Member Diet Plan APIs
        case $method === 'GET' && $path === '/api/member/diet-plans/active':
            $dietPlanController->getMyActiveDietPlan();
            return;

        case $method === 'GET' && $path === '/api/member/diet-plans/history':
            $dietPlanController->getMyDietPlansHistory();
            return;

        case $method === 'GET' && $path === '/api/member/diet-plans':
            $dietPlanController->getMyDietPlans();
            return;

        case $method === 'GET' && preg_match('#^/api/member/diet-plans/(\d+)$#', $path, $matches):
            $dietPlanController->getDietPlanDetailsByMember((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/member/diet-plans/(\d+)/meals$#', $path, $matches):
            $dietPlanController->getDietPlanMealsByMember((int)$matches[1]);
            return;

        case $method === 'GET' && preg_match('#^/api/member/meals/(\d+)$#', $path, $matches):
            $dietPlanController->getMealDetailsByMember((int)$matches[1]);
            return;

        // ================= DEFAULT =================
        default:
            http_response_code(404);
            echo json_encode([
                "status" => "error",
                "message" => "Route not found"
            ]);
            return;
    }
}

