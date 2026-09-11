<?php

namespace Doppar\Authorizer;

use Phaseolies\Launchers\GhostableLauncher;
use Phaseolies\Launchers\ServiceLauncher;
use Doppar\Authorizer\Authorizer;

class GuardLauncher extends ServiceLauncher implements GhostableLauncher
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
    public function launch(): void
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
