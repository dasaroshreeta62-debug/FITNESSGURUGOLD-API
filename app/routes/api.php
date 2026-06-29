<?php

require_once __DIR__ . '/../controllers/controller.php';

function route(string $method, string $path): void
{
    // Normalize path (remove trailing slash)
    $path = rtrim($path, '/');

    // Create controller instance
    $controller = new Controller();

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

        case $method === 'POST' && $path === '/api/staff/addStaff':
            $controller->addStaff();
            return;
        
        case $method === 'GET' && $path === '/api/staff/getStaff':
            $controller->getStaff();
            return;

        case $method === 'GET' && preg_match('#^/api/staff/getStaff/(\d+)$#', $path, $matches):
            $controller->getStaffById((int)$matches[1]);
            return;

        case $method === 'PUT' && preg_match('#^/api/staff/updateStaff/(\d+)$#', $path, $matches):
            $controller->updateStaff((int)$matches[1]);
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

