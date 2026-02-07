<?php

namespace PeterAlaxin\LaravelSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Throwable;

class ErrorLog extends Model
{
    protected $fillable = [
        'hash',
        'exception_class',
        'message',
        'code',
        'file',
        'line',
        'trace',
        'url',
        'method',
        'ip',
        'user_agent',
        'request_data',
        'user_id',
        'occurrences',
        'last_occurrence',
        'resolved',
        'resolved_at',
        'notes',
    ];

    protected $casts = [
        'request_data' => 'array',
        'resolved' => 'boolean',
        'last_occurrence' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    /**
     * User who triggered the error
     */
    public function user(): BelongsTo
    {
        $userModel = config('security.user_model', 'App\\Models\\User');

        return $this->belongsTo($userModel);
    }

    /**
     * Generate hash for deduplication
     */
    public static function generateHash(Throwable $exception): string
    {
        return hash('sha256', $exception->getFile() . ':' . $exception->getLine() . ':' . get_class($exception));
    }

    /**
     * Create or update error log entry
     */
    public static function logException(Throwable $exception, ?int $userId = null): self
    {
        $hash = self::generateHash($exception);
        $request = request();

        // Filter sensitive data from request
        $requestData = self::filterSensitiveData($request->all());

        $existing = self::where('hash', $hash)
            ->where('resolved', false)
            ->first();

        if ($existing) {
            $existing->update([
                'occurrences' => $existing->occurrences + 1,
                'last_occurrence' => now(),
                'user_id' => $userId ?? $existing->user_id,
            ]);

            return $existing;
        }

        return self::create([
            'hash' => $hash,
            'exception_class' => get_class($exception),
            'message' => $exception->getMessage(),
            'code' => $exception->getCode(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'request_data' => $requestData,
            'user_id' => $userId,
            'last_occurrence' => now(),
        ]);
    }

    /**
     * Filter sensitive data from request
     */
    private static function filterSensitiveData(array $data): array
    {
        $sensitiveKeys = config('security.error_logging.sensitive_fields', [
            'password',
            'password_confirmation',
            'current_password',
            'new_password',
            'token',
            'api_key',
            'secret',
            'credit_card',
            'card_number',
            'cvv',
            'authorization',
        ]);

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = self::filterSensitiveData($value);
            } elseif (in_array(strtolower($key), $sensitiveKeys)) {
                $data[$key] = '***FILTERED***';
            }
        }

        return $data;
    }

    /**
     * Mark as resolved
     */
    public function markResolved(?string $notes = null): void
    {
        $this->update([
            'resolved' => true,
            'resolved_at' => now(),
            'notes' => $notes,
        ]);
    }

    /**
     * Reopen error
     */
    public function reopen(): void
    {
        $this->update([
            'resolved' => false,
            'resolved_at' => null,
        ]);
    }

    /**
     * Get short exception class name
     */
    public function getShortClassAttribute(): string
    {
        $parts = explode('\\', $this->exception_class);

        return end($parts);
    }

    /**
     * Scope for unresolved errors
     */
    public function scopeUnresolved($query)
    {
        return $query->where('resolved', false);
    }

    /**
     * Scope for recent errors (last 24 hours)
     */
    public function scopeRecent($query)
    {
        return $query->where('created_at', '>=', now()->subDay());
    }
}
