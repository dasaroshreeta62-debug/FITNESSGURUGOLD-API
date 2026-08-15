<?php

require_once __DIR__ . '/../services/DeviceWorkflow.php';

class DeviceController
{
    private DeviceWorkflow $workflow;

    public function __construct()
    {
        $this->workflow = new DeviceWorkflow();
    }

    private function getSN(): string
    {
        return $_GET['SN'] ?? $_GET['sn'] ?? '';
    }

    private function getBearerToken(): string|false
    {
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (empty($authHeader)) {
            http_response_code(401);
            echo json_encode([
                "success" => false,
                "message" => "Authorization token missing"
            ]);
            return false;
        }

        return str_replace('Bearer ', '', $authHeader);
    }

    private function getRequestInput(): array
    {
        $input = json_decode(file_get_contents("php://input"), true);
        if (empty($input)) {
            $input = $_POST;
        }
        if (empty($input)) {
            parse_str(file_get_contents("php://input"), $input);
        }
        return is_array($input) ? $input : [];
    }

    public function handshake(): void
    {
        header("Content-Type: text/plain");
        $sn = $this->getSN();
        $options = $_GET['options'] ?? null;
        echo $this->workflow->handleHandshake($sn, $options);
    }

    public function registry(): void
    {
        header("Content-Type: text/plain");
        $sn = $this->getSN();
        $rawBody = file_get_contents("php://input");
        echo $this->workflow->registerDevice($sn, $rawBody);
    }

    public function pushConfig(): void
    {
        header("Content-Type: text/plain");
        $sn = $this->getSN();
        echo $this->workflow->downloadConfig($sn);
    }

    public function ping(): void
    {
        header("Content-Type: text/plain");
        $sn = $this->getSN();
        echo $this->workflow->ping($sn);
    }

    public function cdata(): void
    {
        header("Content-Type: text/plain");
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $sn = $this->getSN();
            $rawBody = file_get_contents("php://input");
            echo $this->workflow->ingestRealtimePunches($sn, $rawBody);
        } else {
            $this->handshake();
        }
    }

    public function getrequest(): void
    {
        header("Content-Type: text/plain");
        $sn = $this->getSN();
        echo $this->workflow->pollCommands($sn);
    }

    public function devicecmd(): void
    {
        header("Content-Type: text/plain");
        $sn = $this->getSN();
        $rawBody = file_get_contents("php://input");
        echo $this->workflow->commandCallback($sn, $rawBody);
    }

    public function syncUser(string $sn = ''): void
    {
        $token = $this->getBearerToken();
        if ($token === false) return;

        if (empty($sn) && !empty($_GET['sn'])) {
            $sn = $_GET['sn'];
        }

        $input = $this->getRequestInput();
        $response = $this->workflow->queueUserSync($token, $sn, $input);
        echo json_encode($response);
    }
}
