<?php

namespace PeterAlaxin\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use PeterAlaxin\LaravelSecurity\Models\BlockedIp;
use Symfony\Component\HttpFoundation\Response;

class BlockByIp
{
    private const CACHE_KEY = 'security_blocked_ips_list';

    public function handle(Request $request, Closure $next): Response
    {
        if (!config('security.ip_blocking.enabled', true)) {
            return $next($request);
        }

        // Skip IP blocking for authenticated users
        if (auth()->check()) {
            return $next($request);
        }

        $ip = $request->ip();

        if ($ip === null) {
            return $next($request);
        }

        $cacheTtl = config('security.ip_blocking.cache_ttl', 3600);

        $blockedIps = Cache::remember(
            self::CACHE_KEY,
            $cacheTtl,
            fn () => BlockedIp::pluck('ip')->flip()->toArray(),
        );

        if (isset($blockedIps[$ip])) {
            BlockedIp::where('ip', $ip)->increment('attempts');

            return response()->json(['message' => 'Request blocked.'], 403);
        }

        return $next($request);
    }

    public static function clearCache(): void
    {
        Cache::forget(self::CACHE_KEY);
    }
}
