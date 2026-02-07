# Laravel Security

Comprehensive security package for Laravel applications providing IP blocking, attack detection, error logging, and security headers.

## Features

- **IP Blocking** - Block malicious IPs at middleware level with optional UFW firewall integration
- **Attack Detection** - Detect and block PHP Object Injection, deserialization attacks, and Livewire property manipulation
- **Security Headers** - Automatically add CSP, HSTS, X-Frame-Options, and other security headers
- **Error Logging** - Log exceptions to database with deduplication and sensitive data filtering
- **HTML Sanitizer** - Sanitize user HTML input to prevent XSS attacks
- **CSRF Enhancement** - Enhanced CSRF handling with session expiry redirects

## Requirements

- PHP 8.2+
- Laravel 11.x or 12.x

## Installation

```bash
composer require peteralaxin/laravel-security
```

Publish the configuration and migrations:

```bash
php artisan vendor:publish --tag=security
```

Or publish separately:

```bash
php artisan vendor:publish --tag=security-config
php artisan vendor:publish --tag=security-migrations
```

Run migrations:

```bash
php artisan migrate
```

## Configuration

After publishing, edit `config/security.php` to customize the package behavior.

### Environment Variables

```env
# IP Blocking
SECURITY_IP_BLOCKING_ENABLED=true
SECURITY_IP_CACHE_TTL=3600
SECURITY_IP_WHITELIST=192.168.1.1,10.0.0.1

# UFW Integration (optional)
SECURITY_UFW_ENABLED=false
SECURITY_UFW_QUEUE_PATH=/var/www/security

# Attack Detection
SECURITY_BLOCK_SERIALIZATION=true
SECURITY_BLOCK_LIVEWIRE_MANIPULATION=true
SECURITY_LOG_CHANNEL=daily

# Security Headers
SECURITY_HEADERS_ENABLED=true
SECURITY_CSP_ENABLED=true
SECURITY_HSTS_ENABLED=true

# Error Logging
SECURITY_ERROR_LOGGING_ENABLED=true
```

## Usage

### Middleware

The package registers three middleware aliases:

- `security.block-ip` - Block requests from blacklisted IPs
- `security.block-attacks` - Detect and block serialization attacks
- `security.headers` - Add security headers to responses

#### Manual Registration

In `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->prepend(\PeterAlaxin\LaravelSecurity\Middleware\BlockByIp::class);
    $middleware->append(\PeterAlaxin\LaravelSecurity\Middleware\BlockSerializationAttacks::class);
    $middleware->append(\PeterAlaxin\LaravelSecurity\Middleware\SecurityHeaders::class);
})
```

#### Route-based Registration

```php
Route::middleware(['security.block-ip', 'security.headers'])->group(function () {
    // Your routes
});
```

#### Auto-registration

Set `SECURITY_AUTO_MIDDLEWARE=true` in `.env` to automatically register all middleware globally.

### Exception Handling

Add security exception handling to `bootstrap/app.php`:

```php
use PeterAlaxin\LaravelSecurity\Exceptions\HandlesSecurityExceptions;
use PeterAlaxin\LaravelSecurity\Services\ErrorLogService;
use PeterAlaxin\LaravelSecurity\Services\IpBlockerService;

->withExceptions(function (Exceptions $exceptions) {
    $exceptions->report(function (Throwable $e) {
        app(ErrorLogService::class)->logException($e);
    });

    // Block Livewire property manipulation attempts
    $exceptions->render(function (\Livewire\Exceptions\CannotUpdateLockedPropertyException $e, $request) {
        app(IpBlockerService::class)->queueForBlocking(
            $request->ip(),
            'Livewire property manipulation attempt'
        );
        return response()->json(['message' => 'Forbidden'], 403);
    });
})
```

### HTML Sanitizer

```php
use PeterAlaxin\LaravelSecurity\Helpers\HtmlSanitizer;

// Sanitize HTML (allows safe tags)
$clean = HtmlSanitizer::sanitize($userInput);

// Strip all HTML
$plainText = HtmlSanitizer::stripAll($userInput);
```

### IP Blocker Service

```php
use PeterAlaxin\LaravelSecurity\Services\IpBlockerService;

$ipBlocker = app(IpBlockerService::class);

// Queue an IP for blocking
$ipBlocker->queueForBlocking('1.2.3.4', 'Suspicious activity');

// Mark IP as blocked (after UFW rule added)
$ipBlocker->markAsBlocked('1.2.3.4');
```

### Artisan Commands

```bash
# Mark an IP as blocked in the database
php artisan security:mark-ip-blocked 1.2.3.4
```

## UFW Integration

For server-level IP blocking with UFW firewall:

1. Enable UFW integration in config:
   ```env
   SECURITY_UFW_ENABLED=true
   SECURITY_UFW_QUEUE_PATH=/var/www/security
   ```

2. Create a cron job running as root to process the queue:
   ```bash
   * * * * * /path/to/block-ips.sh
   ```

3. Example `block-ips.sh`:
   ```bash
   #!/bin/bash
   QUEUE_FILE="/var/www/security/ips_to_block.txt"
   BLOCKED_FILE="/var/www/security/blocked_ips.txt"

   if [ -f "$QUEUE_FILE" ]; then
       while IFS='|' read -r ip timestamp reason; do
           ufw deny from "$ip" to any
           echo "$ip" >> "$BLOCKED_FILE"
           php /path/to/artisan security:mark-ip-blocked "$ip"
       done < "$QUEUE_FILE"
       > "$QUEUE_FILE"
   fi
   ```

## Models

The package provides two Eloquent models:

### BlockedIp

```php
use PeterAlaxin\LaravelSecurity\Models\BlockedIp;

// Get all blocked IPs
BlockedIp::blocked()->get();

// Get queued IPs (not yet blocked at firewall)
BlockedIp::queued()->get();
```

### ErrorLog

```php
use PeterAlaxin\LaravelSecurity\Models\ErrorLog;

// Get unresolved errors
ErrorLog::unresolved()->get();

// Get recent errors (last 24 hours)
ErrorLog::recent()->get();

// Mark as resolved
$error->markResolved('Fixed in commit abc123');

// Reopen
$error->reopen();
```

## License

MIT License. See [LICENSE](LICENSE) for details.
