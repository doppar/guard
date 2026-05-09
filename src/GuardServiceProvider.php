<?php

namespace Doppar\Authorizer;

use Phaseolies\Providers\GhostableProvider;
use Phaseolies\Providers\ServiceProvider;
use Doppar\Authorizer\Authorizer;

class GuardServiceProvider extends ServiceProvider implements GhostableProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->app->singleton('authorizer.guard', Authorizer::class);

        app('authorizer.guard')->resolveUserUsing(fn() => auth()->user());
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot(): void
    {
        //
    }

    /**
     * Get the services that should ghost-load this provider.
     *
     * @return array<int, string>
     */
    public function ghosts(): array
    {
        return [
            'authorizer.guard',
        ];
    }
}
