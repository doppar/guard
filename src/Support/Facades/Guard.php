<?php

namespace Doppar\Authorizer\Support\Facades;

use Phaseolies\Facade\BaseFacade;

class Guard extends BaseFacade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'authorizer.guard';
    }
}
