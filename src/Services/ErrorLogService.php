<?php

namespace PeterAlaxin\LaravelSecurity\Services;

use Illuminate\Support\Facades\Log;
use PeterAlaxin\LaravelSecurity\Models\ErrorLog;
use Throwable;

class ErrorLogService
{
    /**
     * Log exception to database
     */
    public function logException(Throwable $exception): ?ErrorLog
    {
        if (!config('security.error_logging.enabled', true)) {
            return null;
        }

        // Skip certain exceptions
        if ($this->shouldIgnore($exception)) {
            return null;
        }

        try {
            // Get user context
            /** @var int|null $userId */
            $userId = auth()->id();

            // Log to database
            return ErrorLog::logException($exception, $userId);
        } catch (Throwable $e) {
            // Don't let error logging cause more errors
            Log::error('ErrorLogService failed', [
                'original_exception' => $exception->getMessage(),
                'logging_exception' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * Check if exception should be ignored
     */
    private function shouldIgnore(Throwable $exception): bool
    {
        $ignoredExceptions = config('security.error_logging.ignored_exceptions', [
            \Illuminate\Auth\AuthenticationException::class,
            \Illuminate\Session\TokenMismatchException::class,
            \Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class,
            \Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException::class,
            \Illuminate\Database\Eloquent\ModelNotFoundException::class,
            \Illuminate\Validation\ValidationException::class,
        ]);

        // Ignore Livewire checksum verification failures (stale page after deployment)
        $ignoredMessages = config('security.error_logging.ignored_messages', ['Checksum']);

        foreach ($ignoredMessages as $message) {
            if (str_contains($exception->getMessage(), $message)) {
                return true;
            }
        }

        foreach ($ignoredExceptions as $ignored) {
            if ($exception instanceof $ignored) {
                return true;
            }
        }

        return false;
    }
}
