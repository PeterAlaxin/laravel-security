<?php

namespace PeterAlaxin\LaravelSecurity\Console\Commands;

use Illuminate\Console\Command;
use PeterAlaxin\LaravelSecurity\Services\IpBlockerService;

class MarkIpBlockedCommand extends Command
{
    protected $signature = 'security:mark-ip-blocked {ip}';

    protected $description = 'Mark an IP address as blocked in the database (called after ufw rule is added)';

    public function handle(IpBlockerService $ipBlocker): int
    {
        $ip = $this->argument('ip');

        if ($ipBlocker->markAsBlocked($ip)) {
            $this->info("IP {$ip} marked as blocked.");

            return self::SUCCESS;
        }

        $this->error("IP {$ip} not found in database.");

        return self::FAILURE;
    }
}
