<?php
// $host = "srv674.hstgr.io";
// $db   = "u705414379_gym_system_db";
// $user = "u705414379_gym_db_user";
// $pass = "4EQZWOR^y";

// try {
//     $conn = new PDO(
//         "mysql:host=$host;dbname=$db;charset=utf8",
//         $user,
//         $pass,
//         [
//             PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
//             PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
//         ]
//     );
// } catch (PDOException $e) {
//     throw new Exception("DB Connection failed: " . $e->getMessage());
// }


class Database
{
    private const DB_HOST = 'srv674.hstgr.io';
    private const DB_NAME = 'u705414379_gym_test_db';
    private const DB_USER = 'u705414379_gym_test_user';
    private const DB_PASS = '1dEKUSL;r3N$';

    private static ?PDO $conn = null;

    public static function getConnection(): PDO
    {
        if (self::$conn === null) {
            try {
                self::$conn = new PDO(
                    "mysql:host=" . self::DB_HOST .
                    ";dbname=" . self::DB_NAME .
                    ";charset=utf8mb4",
                    self::DB_USER,
                    self::DB_PASS,
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_PERSISTENT => true
                    ]
                );
            } catch (PDOException $e) {
                throw new Exception("DB Connection failed: " . $e->getMessage());
            }
        }

        return self::$conn;
    }
}

// {
//     private const DB_HOST = 'srv674.hstgr.io';
//     private const DB_NAME = 'u705414379_gym_system_db';
//     private const DB_USER = 'u705414379_gym_db_user';
//     private const DB_PASS = '4EQZWOR^y';

//     private static ?PDO $conn = null;

//     public static function getConnection(): PDO
//     {
//         if (self::$conn === null) {
//             try {
//                 self::$conn = new PDO(
//                     "mysql:host=" . self::DB_HOST .
//                     ";dbname=" . self::DB_NAME .
//                     ";charset=utf8mb4",
//                     self::DB_USER,
//                     self::DB_PASS,
//                     [
//                         PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
//                         PDO::ATTR_PERSISTENT => true
//                     ]
//                 );
//             } catch (PDOException $e) {
//                 throw new Exception("DB Connection failed: " . $e->getMessage());
//             }
//         }

//         return self::$conn;
//     }
// }

