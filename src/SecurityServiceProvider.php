<?php

namespace PeterAlaxin\LaravelSecurity;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;
use PeterAlaxin\LaravelSecurity\Console\Commands\MarkIpBlockedCommand;
use PeterAlaxin\LaravelSecurity\Middleware\BlockByIp;
use PeterAlaxin\LaravelSecurity\Middleware\BlockSerializationAttacks;
use PeterAlaxin\LaravelSecurity\Middleware\SecurityHeaders;
use PeterAlaxin\LaravelSecurity\Services\ErrorLogService;
use PeterAlaxin\LaravelSecurity\Services\IpBlockerService;

class SecurityServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/security.php', 'security');

        $this->app->singleton(IpBlockerService::class);
        $this->app->singleton(ErrorLogService::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerCommands();
        $this->registerMiddleware();
    }

    /**
     * Register the package's publishable resources.
     */
    protected function registerPublishing(): void
    {
        if ($this->app->runningInConsole()) {
            // Config
            $this->publishes([
                __DIR__ . '/../config/security.php' => config_path('security.php'),
            ], 'security-config');

            // Migrations
            $this->publishes([
                __DIR__ . '/../database/migrations/create_blocked_ips_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time()) . '_create_blocked_ips_table.php'),
                __DIR__ . '/../database/migrations/create_error_logs_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time() + 1) . '_create_error_logs_table.php'),
            ], 'security-migrations');

            // All
            $this->publishes([
                __DIR__ . '/../config/security.php' => config_path('security.php'),
                __DIR__ . '/../database/migrations/create_blocked_ips_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time()) . '_create_blocked_ips_table.php'),
                __DIR__ . '/../database/migrations/create_error_logs_table.php.stub' => database_path('migrations/' . date('Y_m_d_His', time() + 1) . '_create_error_logs_table.php'),
            ], 'security');
        }
    }

    /**
     * Register the package's artisan commands.
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                MarkIpBlockedCommand::class,
            ]);
        }
    }

    /**
     * Register middleware aliases.
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app['router'];

        // Register middleware aliases
        $router->aliasMiddleware('security.block-ip', BlockByIp::class);
        $router->aliasMiddleware('security.headers', SecurityHeaders::class);
        $router->aliasMiddleware('security.block-attacks', BlockSerializationAttacks::class);

        // Auto-register global middleware if configured
        if (config('security.auto_register_middleware', false)) {
            /** @var Kernel $kernel */
            $kernel = $this->app->make(Kernel::class);

            if (config('security.ip_blocking.enabled', true)) {
                $kernel->prependMiddleware(BlockByIp::class);
            }

            if (config('security.attack_detection.block_serialization_attacks', true)) {
                $kernel->pushMiddleware(BlockSerializationAttacks::class);
            }

            if (config('security.headers.enabled', true)) {
                $kernel->pushMiddleware(SecurityHeaders::class);
            }
        }
    }
}
