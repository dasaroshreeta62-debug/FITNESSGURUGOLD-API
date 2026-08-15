<?php

require_once __DIR__ . '/../repositories/DeviceModel.php';
require_once __DIR__ . '/../repositories/AttendanceModel.php';
require_once __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class DeviceWorkflow
{
    private DeviceModel $deviceModel;
    private AttendanceModel $attendanceModel;
    private const JWT_SECRET = '12b5a9899ecf1ce62e6af2dfbf8caecadf7bdcaa6e8bc92aeaf94871d9a100d1';

    public function __construct()
    {
        $this->deviceModel     = new DeviceModel();
        $this->attendanceModel = new AttendanceModel();
    }

    private function authenticate(string $token): object
    {
        return JWT::decode($token, new Key(self::JWT_SECRET, 'HS256'));
    }

    public function handleHandshake(string $sn, ?string $options = null): string
    {
        if (empty($sn)) {
            return "OK";
        }

        $device = $this->deviceModel->getDeviceBySn($sn);

        if (!$device) {
            // Unregistered terminal handshake response
            return "OK";
        }

        $this->deviceModel->updateHeartbeat($sn);

        $regCode = $device['registry_code'] ?: ('REG_' . time());

        // Protocol v3.1.2 Registered Handshake Response
        return "registry=ok\n" .
               "RegistryCode={$regCode}\n" .
               "ServerVersion=3.1.2\n" .
               "ServerName=GymManagementServer\n" .
               "PushProtVer=3.1.2\n" .
               "ErrorDelay=60\n" .
               "RequestDelay=5\n" .
               "TransTimes=00:00;12:00\n" .
               "TransInterval=1\n" .
               "TransTables=User Transaction\n" .
               "Realtime=1\n" .
               "SessionID=" . md5($sn . time()) . "\n" .
               "TimeoutSec=10\n";
    }

    public function registerDevice(string $sn, string $rawBody): string
    {
        if (empty($sn)) {
            return "RegistryCode=REG_FAILED";
        }

        $params = [];
        // Raw body can be comma-separated or newline-separated key-value pairs (e.g. DeviceType=acc,~DeviceName=F09...)
        $cleanBody = str_replace(["\r\n", "\n", "\r"], ',', $rawBody);
        $pairs = explode(',', $cleanBody);
        foreach ($pairs as $pair) {
            if (strpos($pair, '=') !== false) {
                list($k, $v) = explode('=', trim($pair), 2);
                $params[trim($k)] = trim($v);
            }
        }

        $device = $this->deviceModel->registerDevice($sn, $params);
        $regCode = $device['registry_code'] ?? ('REG_' . time());

        return "RegistryCode={$regCode}\n";
    }

    public function downloadConfig(string $sn): string
    {
        if (!empty($sn)) {
            $this->deviceModel->updateHeartbeat($sn);
        }

        return "ServerVersion=3.1.2\n" .
               "ServerName=GymManagementServer\n" .
               "PushVersion=3.1.2\n" .
               "ErrorDelay=60\n" .
               "RequestDelay=2\n" .
               "TransInterval=1\n" .
               "TransTables=User Transaction\n" .
               "Realtime=1\n" .
               "SessionID=" . md5($sn . time()) . "\n" .
               "TimeoutSec=10\n";
    }

    public function ping(string $sn): string
    {
        if (!empty($sn)) {
            $this->deviceModel->updateHeartbeat($sn);
        }
        return "OK";
    }

    public function ingestRealtimePunches(string $sn, string $rawBody): string
    {
        if (!empty($sn)) {
            $this->deviceModel->updateHeartbeat($sn);
        }

        if (empty($rawBody)) {
            return "OK";
        }

        // Split body by lines
        $lines = preg_split('/\r\n|\r|\n/', trim($rawBody));
        foreach ($lines as $line) {
            if (empty(trim($line))) continue;

            $punchData = [];
            // Tab-separated or space-separated key-values: time=2026-08-16 08:30:15\tpin=1042\tcardno=0...
            $pairs = explode("\t", $line);
            foreach ($pairs as $pair) {
                if (strpos($pair, '=') !== false) {
                    list($k, $v) = explode('=', trim($pair), 2);
                    $punchData[trim($k)] = trim($v);
                }
            }

            if (!empty($punchData['pin']) || !empty($punchData['cardno'])) {
                $this->attendanceModel->processRealtimePunch($sn, $punchData);
            }
        }

        return "OK";
    }

    public function pollCommands(string $sn): string
    {
        if (empty($sn)) {
            return "OK";
        }

        $this->deviceModel->updateHeartbeat($sn);

        $command = $this->deviceModel->getNextPendingCommand($sn);

        if (!$command) {
            return "OK";
        }

        // ZKTeco command polling format: C:${CmdID}:${CmdDetail}
        return "C:" . $command['command_id'] . ":" . $command['command_detail'] . "\n";
    }

    public function commandCallback(string $sn, string $rawBody): string
    {
        if (!empty($sn)) {
            $this->deviceModel->updateHeartbeat($sn);
        }

        $params = [];
        parse_str($rawBody, $params);

        if (empty($params['ID']) && strpos($rawBody, 'ID=') !== false) {
            // Alternative parsing if rawBody uses tab/lines
            $cleanBody = str_replace(["\r\n", "\n", "\r", "\t"], '&', $rawBody);
            parse_str($cleanBody, $params);
        }

        $cmdId      = isset($params['ID']) ? (int)$params['ID'] : 0;
        $returnCode = isset($params['Return']) ? (int)$params['Return'] : 0;

        if ($cmdId > 0) {
            $this->deviceModel->updateCommandResult($cmdId, $returnCode);
        }

        return "OK";
    }

    public function queueUserSync(string $accessToken, string $sn, array $userData): array
    {
        try {
            $decoded = $this->authenticate($accessToken);

            if (empty($sn)) {
                http_response_code(400);
                return [
                    "success" => false,
                    "message" => "Device serial number (sn) is required."
                ];
            }

            if (empty($userData['pin'])) {
                http_response_code(400);
                return [
                    "success" => false,
                    "message" => "pin is required for user sync."
                ];
            }

            $commandId = $this->deviceModel->queueUserSyncCommand($sn, $userData);

            http_response_code(202);
            return [
                "success"    => true,
                "message"    => "User sync command queued for terminal delivery.",
                "command_id" => $commandId
            ];

        } catch (\Throwable $e) {
            http_response_code(500);
            return [
                "success" => false,
                "message" => "Failed to queue user sync command",
                "error"   => $e->getMessage()
            ];
        }
    }
}
