<?php

class Logger
{
    private static string $logDir         = __DIR__ . '/../../logs';
    private static string $apiLogFile     = __DIR__ . '/../../logs/api_calls.log';
    private static string $errorLogFile   = __DIR__ . '/../../logs/error_logs.log';
    private static string $weekMarkerFile = __DIR__ . '/../../logs/.last_week';

    private static function ensureLogDir(): void
    {
        if (!file_exists(self::$logDir)) {
            @mkdir(self::$logDir, 0777, true);
        }
    }

    private static function checkAndRotateWeekly(): void
    {
        self::ensureLogDir();
        date_default_timezone_set('Asia/Kolkata');
        $currentWeek = date('o-W'); // ISO-8601 year and week number e.g. 2026-W35
        $lastWeek    = file_exists(self::$weekMarkerFile) ? trim((string)file_get_contents(self::$weekMarkerFile)) : '';

        if ($lastWeek !== $currentWeek || !file_exists(self::$apiLogFile)) {
            $header = sprintf(
                "================================================================================\n" .
                " FITNESSGURUGOLD API CALL LOGS - WEEK [%s]\n" .
                " Reset Timestamp : %s\n" .
                " Note             : This file automatically resets/overwrites on a weekly basis.\n" .
                "================================================================================\n\n",
                $currentWeek,
                date('Y-m-d H:i:s')
            );
            file_put_contents(self::$apiLogFile, $header);
            file_put_contents(self::$weekMarkerFile, $currentWeek);
        }
    }

    public static function error(Throwable $e): void
    {
        self::ensureLogDir();
        date_default_timezone_set('Asia/Kolkata');
        $message = sprintf(
            "[%s] %s in %s:%d\nStack trace:\n%s\n\n",
            date('Y-m-d H:i:s'),
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            $e->getTraceAsString()
        );

        error_log($message, 3, self::$errorLogFile);
    }

    public static function logApiCall(
        string $method,
        string $uri,
        int $statusCode,
        float $durationMs,
        array|string $queryParams = [],
        mixed $payload = null,
        mixed $response = null
    ): void {
        try {
            self::checkAndRotateWeekly();
            date_default_timezone_set('Asia/Kolkata');
            $timestamp   = date('Y-m-d H:i:s');
            $currentWeek = date('o-W');

            $ip        = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

            // Format query params
            $queryParamsStr = !empty($queryParams) ? json_encode($queryParams, JSON_UNESCAPED_SLASHES) : 'None';

            // Format payload & sanitize sensitive fields
            $formattedPayload  = self::formatAndSanitize($payload);
            $formattedResponse = self::formatResponseSnippet($response);

            $entry = sprintf(
                "--------------------------------------------------------------------------------\n" .
                "[%s] [WEEK %s] %s %s\n" .
                "Status Code : %d\n" .
                "Duration    : %.2f ms\n" .
                "Client IP   : %s\n" .
                "User-Agent  : %s\n" .
                "Query Params: %s\n" .
                "Payload     : %s\n" .
                "Response    : %s\n" .
                "--------------------------------------------------------------------------------\n\n",
                $timestamp,
                $currentWeek,
                strtoupper($method),
                $uri,
                $statusCode,
                $durationMs,
                $ip,
                $userAgent,
                $queryParamsStr,
                $formattedPayload,
                $formattedResponse
            );

            file_put_contents(self::$apiLogFile, $entry, FILE_APPEND | LOCK_EX);
        } catch (\Throwable $e) {
            // Fail safely without breaking API response
            self::error($e);
        }
    }

    private static function formatAndSanitize(mixed $data): string
    {
        if (empty($data)) {
            return 'None';
        }

        if (is_array($data)) {
            $sanitized = self::sanitizeArray($data);
            return json_encode($sanitized, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        if (is_string($data)) {
            $trimmed = trim($data);
            if (empty($trimmed)) return 'None';
            if (strpos($trimmed, 'password=') !== false || strpos($trimmed, 'Password=') !== false) {
                return (string)preg_replace('/(password|Password)=[^&\t\n\r]*/i', '$1=***MASKED***', $trimmed);
            }
            return strlen($trimmed) > 500 ? substr($trimmed, 0, 500) . '... [Truncated]' : $trimmed;
        }

        return (string)$data;
    }

    private static function sanitizeArray(array $arr): array
    {
        $sensitiveKeys = ['password', 'pass', 'token', 'access_token', 'refresh_token', 'authorization', 'secret'];
        foreach ($arr as $key => $val) {
            if (in_array(strtolower((string)$key), $sensitiveKeys, true)) {
                $arr[$key] = '***MASKED***';
            } elseif (is_array($val)) {
                $arr[$key] = self::sanitizeArray($val);
            }
        }
        return $arr;
    }

    private static function formatResponseSnippet(mixed $response): string
    {
        if (empty($response) && $response !== '0' && $response !== 0) {
            return 'Empty';
        }
        if (is_array($response)) {
            $json = json_encode($response, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            return strlen($json) > 300 ? substr($json, 0, 300) . '... [Truncated]' : $json;
        }
        $str = (string)$response;
        $cleanStr = str_replace(["\r\n", "\n", "\r"], ' ', trim($str));
        return strlen($cleanStr) > 300 ? substr($cleanStr, 0, 300) . '... [Truncated]' : $cleanStr;
    }
}

