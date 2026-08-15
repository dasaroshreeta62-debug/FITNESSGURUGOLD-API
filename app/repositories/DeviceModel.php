<?php

require_once __DIR__ . '/../config/database.php';

class DeviceModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = Database::getConnection();
        $this->createTablesIfNotExists();
    }

    private function createTablesIfNotExists(): void
    {
        $sqlDevices = "
        CREATE TABLE IF NOT EXISTS `biometric_devices` (
          `device_id` int(11) NOT NULL AUTO_INCREMENT,
          `sn` varchar(50) NOT NULL,
          `device_name` varchar(100) DEFAULT NULL,
          `device_type` varchar(50) DEFAULT 'acc',
          `ip_address` varchar(45) DEFAULT NULL,
          `mac_address` varchar(50) DEFAULT NULL,
          `firmware_ver` varchar(50) DEFAULT NULL,
          `push_version` varchar(50) DEFAULT NULL,
          `registry_code` varchar(100) DEFAULT NULL,
          `status` enum('ONLINE','OFFLINE','UNREGISTERED') DEFAULT 'UNREGISTERED',
          `last_heartbeat` datetime DEFAULT NULL,
          `created_at` datetime DEFAULT current_timestamp(),
          `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
          PRIMARY KEY (`device_id`),
          UNIQUE KEY `unique_sn` (`sn`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
        ";

        $sqlCommands = "
        CREATE TABLE IF NOT EXISTS `device_commands` (
          `command_id` int(11) NOT NULL AUTO_INCREMENT,
          `sn` varchar(50) NOT NULL,
          `command_detail` text NOT NULL,
          `status` enum('PENDING','SENT','EXECUTED','FAILED') DEFAULT 'PENDING',
          `return_code` int(11) DEFAULT NULL,
          `created_at` datetime DEFAULT current_timestamp(),
          `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
          PRIMARY KEY (`command_id`),
          KEY `idx_sn_status` (`sn`, `status`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
        ";

        try {
            $this->db->exec($sqlDevices);
            $this->db->exec($sqlCommands);
        } catch (\PDOException $e) {
            // Fails silently if restricted
        }
    }

    public function getDeviceBySn(string $sn): ?array
    {
        $stmt = $this->db->prepare("SELECT * FROM biometric_devices WHERE sn = :sn LIMIT 1");
        $stmt->execute(['sn' => $sn]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public function registerDevice(string $sn, array $data = []): array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');
        $registryCode = 'REG_' . time() . rand(1000, 9999);

        $deviceName  = $data['device_name']  ?? $data['~DeviceName'] ?? 'ZKTeco Terminal';
        $deviceType  = $data['device_type']  ?? $data['DeviceType']  ?? 'acc';
        $ipAddress   = $data['ip_address']   ?? $data['IPAddress']   ?? null;
        $macAddress  = $data['mac_address']  ?? $data['MAC']         ?? null;
        $firmwareVer = $data['firmware_ver'] ?? $data['FirmVer']     ?? null;
        $pushVersion = $data['push_version'] ?? $data['PushVersion'] ?? '3.1.2';

        $stmt = $this->db->prepare("
            INSERT INTO biometric_devices (
                sn, device_name, device_type, ip_address, mac_address, firmware_ver, push_version, registry_code, status, last_heartbeat, created_at, updated_at
            ) VALUES (
                :sn, :device_name, :device_type, :ip_address, :mac_address, :firmware_ver, :push_version, :registry_code, 'ONLINE', :last_heartbeat, :created_at, :updated_at
            )
            ON DUPLICATE KEY UPDATE
                device_name = VALUES(device_name),
                device_type = VALUES(device_type),
                ip_address = COALESCE(VALUES(ip_address), ip_address),
                mac_address = COALESCE(VALUES(mac_address), mac_address),
                firmware_ver = COALESCE(VALUES(firmware_ver), firmware_ver),
                push_version = COALESCE(VALUES(push_version), push_version),
                registry_code = COALESCE(VALUES(registry_code), registry_code),
                status = 'ONLINE',
                last_heartbeat = VALUES(last_heartbeat),
                updated_at = VALUES(updated_at)
        ");

        $stmt->execute([
            'sn'             => $sn,
            'device_name'    => $deviceName,
            'device_type'    => $deviceType,
            'ip_address'     => $ipAddress,
            'mac_address'    => $macAddress,
            'firmware_ver'   => $firmwareVer,
            'push_version'   => $pushVersion,
            'registry_code'  => $registryCode,
            'last_heartbeat' => $now,
            'created_at'     => $now,
            'updated_at'     => $now
        ]);

        return $this->getDeviceBySn($sn) ?? ['registry_code' => $registryCode];
    }

    public function updateHeartbeat(string $sn): void
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');
        $stmt = $this->db->prepare("
            UPDATE biometric_devices 
            SET last_heartbeat = :now, status = 'ONLINE', updated_at = :now 
            WHERE sn = :sn
        ");
        $stmt->execute(['now' => $now, 'sn' => $sn]);
    }

    public function queueUserSyncCommand(string $sn, array $userData): int
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');

        $pin       = $userData['pin'] ?? '';
        $cardNo    = $userData['card_no'] ?? '0';
        $password  = $userData['password'] ?? '';
        $name      = $userData['name'] ?? '';
        $privilege = isset($userData['privilege']) ? (int)$userData['privilege'] : 0;

        // Command detail format for ZKTeco PUSH v3.1.2:
        // DATA UPDATE user Pin=1042\tCardNo=12345678\tPassword=\tGroup=1\tStartTime=0\tEndTime=0\tName=JohnDoe\tPrivilege=0
        $commandDetail = "DATA UPDATE user Pin={$pin}\tCardNo={$cardNo}\tPassword={$password}\tGroup=1\tStartTime=0\tEndTime=0\tName={$name}\tPrivilege={$privilege}";

        $stmt = $this->db->prepare("
            INSERT INTO device_commands (sn, command_detail, status, created_at, updated_at)
            VALUES (:sn, :command_detail, 'PENDING', :created_at, :updated_at)
        ");
        $stmt->execute([
            'sn'             => $sn,
            'command_detail' => $commandDetail,
            'created_at'     => $now,
            'updated_at'     => $now
        ]);

        return (int)$this->db->lastInsertId();
    }

    public function getNextPendingCommand(string $sn): ?array
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');

        $stmt = $this->db->prepare("
            SELECT * FROM device_commands 
            WHERE sn = :sn AND status = 'PENDING' 
            ORDER BY command_id ASC 
            LIMIT 1
        ");
        $stmt->execute(['sn' => $sn]);
        $command = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($command) {
            $updateStmt = $this->db->prepare("
                UPDATE device_commands 
                SET status = 'SENT', updated_at = :now 
                WHERE command_id = :command_id
            ");
            $updateStmt->execute(['now' => $now, 'command_id' => $command['command_id']]);
        }

        return $command ?: null;
    }

    public function updateCommandResult(int $commandId, int $returnCode): bool
    {
        date_default_timezone_set('Asia/Kolkata');
        $now = date('Y-m-d H:i:s');
        $status = ($returnCode === 0) ? 'EXECUTED' : 'FAILED';

        $stmt = $this->db->prepare("
            UPDATE device_commands 
            SET status = :status, return_code = :return_code, updated_at = :now 
            WHERE command_id = :command_id
        ");
        return $stmt->execute([
            'status'      => $status,
            'return_code' => $returnCode,
            'now'         => $now,
            'command_id'  => $commandId
        ]);
    }
}
