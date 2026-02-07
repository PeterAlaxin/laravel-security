<?php

namespace PeterAlaxin\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use PeterAlaxin\LaravelSecurity\Services\IpBlockerService;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware to detect and block PHP Object Injection / Deserialization attacks
 * and Livewire property type manipulation attempts.
 *
 * This middleware inspects request bodies for patterns commonly used in
 * PHP deserialization exploits (gadget chains) targeting Laravel/Livewire,
 * as well as type confusion attacks on Livewire component properties.
 */
class BlockSerializationAttacks
{
    public function __construct(
        private IpBlockerService $ipBlocker
    ) {
    }

    /**
     * Default patterns that indicate serialized PHP object injection attempts.
     *
     * @var array<string>
     */
    private array $defaultPatterns = [
        // Serialized PHP object pattern (O:number:"classname")
        '/O:\d+:"[^"]+"/i',

        // Common Laravel gadget chain classes
        '/Illuminate\\\\Broadcasting\\\\BroadcastEvent/i',
        '/Illuminate\\\\Broadcasting\\\\PendingBroadcast/i',
        '/Illuminate\\\\Validation\\\\Validator/i',
        '/Laravel\\\\SerializableClosure/i',
        '/GuzzleHttp\\\\Psr7\\\\FnStream/i',
        '/Monolog\\\\Handler\\\\SyslogUdpHandler/i',
        '/Symfony\\\\Component\\\\Process\\\\Process/i',

        // Dangerous PHP functions that might be called via gadget chains
        '/"system"/i',
        '/"exec"/i',
        '/"passthru"/i',
        '/"shell_exec"/i',
        '/"popen"/i',
        '/"proc_open"/i',
        '/"eval"/i',
        '/"assert"/i',

        // Magic method exploitation
        '/__toString.*phpversion/i',
        '/__destruct/i',
        '/__wakeup/i',
        '/dispatchNextJobInChain/i',
    ];

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (!config('security.attack_detection.block_serialization_attacks', true)) {
            return $next($request);
        }

        // Only check POST/PUT/PATCH requests with body content
        if (!in_array($request->method(), ['POST', 'PUT', 'PATCH'])) {
            return $next($request);
        }

        $content = $request->getContent();

        if (empty($content)) {
            return $next($request);
        }

        // Check for Livewire property type manipulation
        if (config('security.attack_detection.block_livewire_manipulation', true)) {
            if ($this->isLivewireTypeManipulation($request)) {
                $this->logAttackAttempt($request, 'Livewire property type manipulation');

                return response()->json([
                    'message' => 'Request blocked.',
                ], 403);
            }
        }

        // Check for suspicious patterns
        $patterns = $this->getSuspiciousPatterns();

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                $this->logAttackAttempt($request, $pattern);

                return response()->json([
                    'message' => 'Request blocked.',
                ], 403);
            }
        }

        return $next($request);
    }

    /**
     * Get suspicious patterns from config or use defaults.
     */
    private function getSuspiciousPatterns(): array
    {
        return config('security.attack_detection.suspicious_patterns', $this->defaultPatterns);
    }

    /**
     * Detect Livewire update requests where empty arrays are sent
     * for properties that should be scalar values (type confusion attack).
     *
     * Note: Livewire legitimately sends populated arrays for form objects,
     * so we only flag empty arrays which are a clear attack indicator.
     */
    private function isLivewireTypeManipulation(Request $request): bool
    {
        if (!str_contains($request->path(), 'livewire') || !str_contains($request->path(), 'update')) {
            return false;
        }

        $components = $request->input('components', []);

        foreach ($components as $component) {
            $updates = $component['updates'] ?? [];

            foreach ($updates as $value) {
                if ($value === []) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Log the attack attempt and queue IP for blocking.
     */
    private function logAttackAttempt(Request $request, string $matchedPattern): void
    {
        $ip = $request->ip();
        $logChannel = config('security.attack_detection.log_channel', 'daily');

        Log::channel($logChannel)->warning('Potential PHP Object Injection attack blocked', [
            'ip' => $ip,
            'user_agent' => $request->userAgent(),
            'url' => $request->fullUrl(),
            'method' => $request->method(),
            'matched_pattern' => $matchedPattern,
            'content_preview' => substr($request->getContent(), 0, 500),
        ]);

        // Queue IP for firewall blocking
        if ($ip !== null) {
            $this->ipBlocker->queueForBlocking(
                $ip,
                'PHP Object Injection attempt: ' . $matchedPattern,
            );
        }
    }
}
