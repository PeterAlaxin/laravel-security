<?php

namespace PeterAlaxin\LaravelSecurity\Exceptions;

use Illuminate\Http\Request;
use PeterAlaxin\LaravelSecurity\Services\ErrorLogService;
use PeterAlaxin\LaravelSecurity\Services\IpBlockerService;
use Throwable;

/**
 * Trait for handling security-related exceptions in your application's exception handler.
 *
 * Usage in bootstrap/app.php:
 *
 * use PeterAlaxin\LaravelSecurity\Exceptions\HandlesSecurityExceptions;
 *
 * ->withExceptions(function (Exceptions $exceptions) {
 *     $exceptions->render(function (Throwable $e, Request $request) {
 *         return (new class { use HandlesSecurityExceptions; })->handleSecurityException($e, $request);
 *     });
 * })
 */
trait HandlesSecurityExceptions
{
    /**
     * Handle security-related exceptions.
     *
     * @return \Illuminate\Http\Response|\Illuminate\Http\JsonResponse|null
     */
    public function handleSecurityException(Throwable $e, Request $request)
    {
        // Handle Livewire property manipulation attempts
        if ($this->isLivewirePropertyViolation($e)) {
            $this->blockAttacker($request, 'Livewire property manipulation attempt');

            return response()->json(['message' => 'Forbidden'], 403);
        }

        // Log exception to database
        $this->logException($e);

        return null;
    }

    /**
     * Check if exception is a Livewire property lock violation.
     */
    protected function isLivewirePropertyViolation(Throwable $e): bool
    {
        // Check by class name to avoid requiring Livewire as a dependency
        $className = get_class($e);

        return str_contains($className, 'CannotUpdateLockedPropertyException');
    }

    /**
     * Block the attacker's IP address.
     */
    protected function blockAttacker(Request $request, string $reason): void
    {
        if (!config('security.ip_blocking.enabled', true)) {
            return;
        }

        $ip = $request->ip();

        if ($ip === null) {
            return;
        }

        try {
            /** @var IpBlockerService $ipBlocker */
            $ipBlocker = app(IpBlockerService::class);
            $ipBlocker->queueForBlocking($ip, $reason);
        } catch (Throwable $e) {
            // Don't let blocking failure cause more issues
            report($e);
        }
    }

    /**
     * Log exception to database.
     */
    protected function logException(Throwable $e): void
    {
        if (!config('security.error_logging.enabled', true)) {
            return;
        }

        try {
            /** @var ErrorLogService $errorLogService */
            $errorLogService = app(ErrorLogService::class);
            $errorLogService->logException($e);
        } catch (Throwable $logException) {
            // Don't let logging failure cause more issues
            report($logException);
        }
    }
}
