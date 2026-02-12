<?php
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

$data = [
    "address" => [
        "name" => "Fitness Guru Gym",
        "city" => "Bhubaneswar",
        "state" => "Odisha",
        "country" => "India"
    ],
    "email" => [
        "info@fitnessguru.com",
        "support@fitnessguru.com"
    ],
    "hours" => [
        "Mon - Sat" => "5:00 AM - 10:00 PM",
        "Sunday" => "6:00 AM - 8:00 PM"
    ]
];

echo json_encode($data);