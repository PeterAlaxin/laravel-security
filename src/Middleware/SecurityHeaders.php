<?php

namespace PeterAlaxin\LaravelSecurity\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    /**
     * Handle an incoming request.
     *
     * @param \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response) $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (!config('security.headers.enabled', true)) {
            return $response;
        }

        // Content Security Policy
        if (config('security.headers.csp.enabled', true)) {
            $csp = $this->buildCsp();
            $response->headers->set('Content-Security-Policy', $csp);
        }

        // Prevent MIME type sniffing
        $response->headers->set(
            'X-Content-Type-Options',
            config('security.headers.x_content_type_options', 'nosniff')
        );

        // Clickjacking protection
        $response->headers->set(
            'X-Frame-Options',
            config('security.headers.x_frame_options', 'SAMEORIGIN')
        );

        // Referrer Policy
        $response->headers->set(
            'Referrer-Policy',
            config('security.headers.referrer_policy', 'strict-origin-when-cross-origin')
        );

        // HTTP Strict Transport Security (HSTS) - only in production
        if (config('security.headers.hsts.enabled', true) && app()->environment('production')) {
            $maxAge = config('security.headers.hsts.max_age', 31536000);
            $response->headers->set('Strict-Transport-Security', "max-age={$maxAge}; includeSubDomains");
        }

        // Permissions Policy (formerly Feature-Policy)
        $permissionsPolicy = config('security.headers.permissions_policy', 'geolocation=(self), camera=(), microphone=()');
        $response->headers->set('Permissions-Policy', $permissionsPolicy);

        return $response;
    }

    /**
     * Build the Content Security Policy header value.
     */
    private function buildCsp(): string
    {
        $configDirectives = config('security.headers.csp.directives', []);

        // If config has directives, use them
        if (!empty($configDirectives)) {
            return $this->buildCspFromConfig($configDirectives);
        }

        // Default CSP
        return $this->buildDefaultCsp();
    }

    /**
     * Build CSP from configuration array.
     */
    private function buildCspFromConfig(array $configDirectives): string
    {
        $directives = [];

        foreach ($configDirectives as $directive => $values) {
            if (is_array($values)) {
                $directives[] = $directive . ' ' . implode(' ', $values);
            } else {
                $directives[] = $directive . ' ' . $values;
            }
        }

        return implode('; ', $directives);
    }

    /**
     * Build default Content Security Policy.
     */
    private function buildDefaultCsp(): string
    {
        $allowedDomains = config('security.headers.csp.allowed_domains', []);

        $scriptSrc = array_merge(
            ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            $allowedDomains
        );

        $styleSrc = array_merge(
            ["'self'", "'unsafe-inline'"],
            $allowedDomains
        );

        $directives = [
            'default-src \'self\'',
            'script-src ' . implode(' ', $scriptSrc),
            'style-src ' . implode(' ', $styleSrc),
            'img-src \'self\' data: blob: https: http:',
            'font-src \'self\' data:',
            'connect-src \'self\' wss:',
            'frame-src \'self\'',
            'media-src \'self\' blob:',
            'object-src \'none\'',
            'base-uri \'self\'',
            'form-action \'self\'',
            'frame-ancestors \'self\'',
        ];

        // Upgrade insecure requests in production
        if (app()->environment('production')) {
            $directives[] = 'upgrade-insecure-requests';
        }

        return implode('; ', $directives);
    }
}
