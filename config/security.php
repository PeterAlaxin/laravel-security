<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Auto-register Middleware
    |--------------------------------------------------------------------------
    |
    | When enabled, the package will automatically register its middleware
    | globally. Set to false if you prefer to register middleware manually
    | in your application's bootstrap or route files.
    |
    */

    'auto_register_middleware' => env('SECURITY_AUTO_MIDDLEWARE', false),

    /*
    |--------------------------------------------------------------------------
    | IP Blocking Configuration
    |--------------------------------------------------------------------------
    |
    | Configure IP blocking behavior. When enabled, blocked IPs are stored
    | in the database and checked on each request.
    |
    */

    'ip_blocking' => [
        'enabled' => env('SECURITY_IP_BLOCKING_ENABLED', true),
        'cache_ttl' => env('SECURITY_IP_CACHE_TTL', 3600),
        'whitelist' => array_filter(explode(',', env('SECURITY_IP_WHITELIST', ''))),

        'ufw_integration' => [
            'enabled' => env('SECURITY_UFW_ENABLED', false),
            'queue_path' => env('SECURITY_UFW_QUEUE_PATH', storage_path('logs')),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Attack Detection Configuration
    |--------------------------------------------------------------------------
    |
    | Configure detection of PHP Object Injection, deserialization attacks,
    | and Livewire property manipulation attempts.
    |
    */

    'attack_detection' => [
        'block_serialization_attacks' => env('SECURITY_BLOCK_SERIALIZATION', true),
        'block_livewire_manipulation' => env('SECURITY_BLOCK_LIVEWIRE_MANIPULATION', true),
        'log_channel' => env('SECURITY_LOG_CHANNEL', 'daily'),

        // Override default patterns (leave empty to use defaults)
        'suspicious_patterns' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Headers Configuration
    |--------------------------------------------------------------------------
    |
    | Configure HTTP security headers including Content-Security-Policy,
    | HSTS, X-Frame-Options, and more.
    |
    */

    'headers' => [
        'enabled' => env('SECURITY_HEADERS_ENABLED', true),

        'csp' => [
            'enabled' => env('SECURITY_CSP_ENABLED', true),
            // Custom CSP directives (leave empty for defaults)
            'directives' => [],
            // Additional domains to allow in default CSP
            'allowed_domains' => array_filter(explode(',', env('SECURITY_CSP_DOMAINS', ''))),
        ],

        'hsts' => [
            'enabled' => env('SECURITY_HSTS_ENABLED', true),
            'max_age' => env('SECURITY_HSTS_MAX_AGE', 31536000),
        ],

        'x_frame_options' => env('SECURITY_X_FRAME_OPTIONS', 'SAMEORIGIN'),
        'x_content_type_options' => env('SECURITY_X_CONTENT_TYPE_OPTIONS', 'nosniff'),
        'referrer_policy' => env('SECURITY_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        'permissions_policy' => env('SECURITY_PERMISSIONS_POLICY', 'geolocation=(self), camera=(), microphone=()'),
    ],

    /*
    |--------------------------------------------------------------------------
    | CSRF Configuration
    |--------------------------------------------------------------------------
    |
    | Configure CSRF middleware behavior.
    |
    */

    'csrf' => [
        'redirect_route' => env('SECURITY_CSRF_REDIRECT_ROUTE', 'login'),
        'error_message' => env('SECURITY_CSRF_ERROR_MESSAGE', 'Session expired. Please log in again.'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Error Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Configure error logging to database. Errors are deduplicated by
    | file, line, and exception class.
    |
    */

    'error_logging' => [
        'enabled' => env('SECURITY_ERROR_LOGGING_ENABLED', true),

        'sensitive_fields' => [
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
        ],

        'ignored_exceptions' => [
            \Illuminate\Auth\AuthenticationException::class,
            \Illuminate\Session\TokenMismatchException::class,
            \Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class,
            \Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException::class,
            \Illuminate\Database\Eloquent\ModelNotFoundException::class,
            \Illuminate\Validation\ValidationException::class,
        ],

        'ignored_messages' => [
            'Checksum',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | HTML Sanitizer Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the HTML sanitizer for preventing XSS attacks in user content.
    |
    */

    'html_sanitizer' => [
        'allowed_elements' => [
            'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'strike',
            'h1', 'h2', 'h3', 'ul', 'ol', 'li', 'a', 'span', 'blockquote',
        ],

        'allowed_attributes' => [
            'a' => ['href', 'target', 'rel'],
            'span' => ['style'],
        ],

        'allowed_schemes' => ['http', 'https', 'mailto'],

        'force_link_security' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | User Model Configuration
    |--------------------------------------------------------------------------
    |
    | The user model used for relationships in error logs.
    |
    */

    'user_model' => env('SECURITY_USER_MODEL', 'App\\Models\\User'),

];
