<?php

namespace Doppar\Authorizer;

use Phaseolies\Providers\ServiceProvider;
use Doppar\Authorizer\Authorizer;

class GuardServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->app->singleton('authorizer.guard', Authorizer::class);
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
}
