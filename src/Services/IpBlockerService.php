<?php

namespace PeterAlaxin\LaravelSecurity\Services;

use Illuminate\Support\Facades\Log;
use PeterAlaxin\LaravelSecurity\Middleware\BlockByIp;
use PeterAlaxin\LaravelSecurity\Models\BlockedIp;

/**
 * Service for managing IP addresses that should be blocked at firewall level.
 *
 * Writes malicious IPs to a file that is processed by a cron job running as root
 * to add them to ufw firewall rules.
 */
class IpBlockerService
{
    /**
     * File where IPs to be blocked are written.
     */
    private string $blockFile;

    /**
     * File containing already blocked IPs (to avoid duplicates).
     */
    private string $blockedFile;

    /**
     * IP addresses that should never be blocked (whitelisted).
     *
     * @var array<string>
     */
    private array $whitelistedIps;

    public function __construct()
    {
        $basePath = config('security.ip_blocking.ufw_integration.queue_path', storage_path('logs'));
        $this->blockFile = rtrim($basePath, '/') . '/ips_to_block.txt';
        $this->blockedFile = rtrim($basePath, '/') . '/blocked_ips.txt';
        $this->whitelistedIps = config('security.ip_blocking.whitelist', []);
    }

    /**
     * Add an IP address to the block queue.
     */
    public function queueForBlocking(string $ip, string $reason): bool
    {
        if (!config('security.ip_blocking.enabled', true)) {
            return false;
        }

        // Validate IP address
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            Log::warning('IpBlockerService: Invalid IP address', ['ip' => $ip]);

            return false;
        }

        // Skip private/local IPs
        if ($this->isPrivateIp($ip)) {
            Log::info('IpBlockerService: Skipping private IP', ['ip' => $ip]);

            return false;
        }

        // Skip whitelisted IPs
        if ($this->isWhitelisted($ip)) {
            Log::info('IpBlockerService: Skipping whitelisted IP', ['ip' => $ip]);

            return false;
        }

        // Check if already in database (queued or blocked)
        if (BlockedIp::where('ip', $ip)->exists()) {
            Log::info('IpBlockerService: IP already in database', ['ip' => $ip]);

            return false;
        }

        // Check if already blocked (file fallback)
        if ($this->isAlreadyBlocked($ip)) {
            Log::info('IpBlockerService: IP already blocked', ['ip' => $ip]);

            return false;
        }

        // Check if already in queue (file fallback)
        if ($this->isInQueue($ip)) {
            Log::info('IpBlockerService: IP already in queue', ['ip' => $ip]);

            return false;
        }

        // Store in database for middleware-level blocking
        BlockedIp::firstOrCreate(
            ['ip' => $ip],
            [
                'reason' => str_replace(['|', "\n", "\r"], ' ', $reason),
                'queued_at' => now(),
            ],
        );

        BlockByIp::clearCache();

        // Write to block file if UFW integration is enabled
        if (config('security.ip_blocking.ufw_integration.enabled', false)) {
            $this->writeToBlockFile($ip, $reason);
        }

        Log::warning('IpBlockerService: IP queued for blocking', [
            'ip' => $ip,
            'reason' => $reason,
        ]);

        return true;
    }

    /**
     * Write IP to block file for UFW integration.
     */
    private function writeToBlockFile(string $ip, string $reason): bool
    {
        $entry = sprintf(
            "%s|%s|%s\n",
            $ip,
            now()->toIso8601String(),
            str_replace(['|', "\n", "\r"], ' ', $reason),
        );

        $result = file_put_contents($this->blockFile, $entry, FILE_APPEND | LOCK_EX);

        if ($result === false) {
            Log::error('IpBlockerService: Failed to write to block file', ['ip' => $ip]);

            return false;
        }

        return true;
    }

    /**
     * Mark an IP as blocked in the database (called after ufw rule is added).
     */
    public function markAsBlocked(string $ip): bool
    {
        $blockedIp = BlockedIp::where('ip', $ip)->first();

        if (!$blockedIp) {
            Log::warning('IpBlockerService: IP not found in database for marking as blocked', ['ip' => $ip]);

            return false;
        }

        $blockedIp->update(['blocked_at' => now()]);

        return true;
    }

    /**
     * Check if an IP is a private/local address.
     */
    private function isPrivateIp(string $ip): bool
    {
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        );
    }

    /**
     * Check if an IP is whitelisted.
     */
    private function isWhitelisted(string $ip): bool
    {
        return in_array($ip, $this->whitelistedIps, true);
    }

    /**
     * Check if an IP is already in the blocked list.
     */
    private function isAlreadyBlocked(string $ip): bool
    {
        if (!file_exists($this->blockedFile)) {
            return false;
        }

        $blocked = file_get_contents($this->blockedFile);

        return $blocked !== false && str_contains($blocked, $ip);
    }

    /**
     * Check if an IP is already in the queue.
     */
    private function isInQueue(string $ip): bool
    {
        if (!file_exists($this->blockFile)) {
            return false;
        }

        $queue = file_get_contents($this->blockFile);

        return $queue !== false && str_contains($queue, $ip . '|');
    }
}
