<?php

require_once __DIR__ . '/../config/database.php';

class Model
{
    private PDO $db;

    public function __construct()
    {
        global $conn;
        $this->db = $conn;
    }

    /* ===================== USERS ===================== */

    public function getAllUsers(): array
    {
        $stmt = $this->db->query("SELECT * FROM users");
        return $stmt->fetchAll();
    }
}
