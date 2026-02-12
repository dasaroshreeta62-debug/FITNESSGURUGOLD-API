<?php

class Logger
{
    private static string $file = __DIR__ . '/../../logs/error_logs.log';

    public static function error(Throwable $e): void
    {
        $message = sprintf(
            "[%s] %s in %s:%d\nStack trace:\n%s\n\n",
            date('Y-m-d H:i:s'),
            $e->getMessage(),
            $e->getFile(),
            $e->getLine(),
            $e->getTraceAsString()
        );

        error_log($message, 3, self::$file);
    }
}
