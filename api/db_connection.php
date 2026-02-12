<?php
// $host = "localhost";
// $db   = "gym_product";
// $user = "root";
// $pass = "cntx@123";

// try {
//     $conn = new PDO(
//         "mysql:host=$host;dbname=$db;charset=utf8",
//         $user,
//         $pass,
//         [
//             PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // throw errors
//             PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
//         ]
//     );
// } catch (PDOException $e) {
//     die("DB Connection failed: " . $e->getMessage());
// }

$host = "srv674.hstgr.io";
$db   = "u705414379_gym_system_db";
$user = "u705414379_gym_db_user";
$pass = "4EQZWOR^y";

try {
    $conn = new PDO(
        "mysql:host=$host;dbname=$db;charset=utf8",
        $user,
        $pass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // throw errors
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );
} catch (PDOException $e) {
    die("DB Connection failed: " . $e->getMessage());
}