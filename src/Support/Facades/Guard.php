<?php

namespace Doppar\Authorizer\Support\Facades;

/**
 * @method static \Doppar\Authorizer\Authorizer policy($class, $policy): void
 * @method static \Doppar\Authorizer\Authorizer define($ability, callable $callback): void
 * @method static \Doppar\Authorizer\Authorizer allows($ability, ...$arguments): bool
 * @method static \Doppar\Authorizer\Authorizer denies($ability, ...$arguments): bool
 * @method static \Doppar\Authorizer\Authorizer temporary($ability, callable $callback): self
 * @method static \Doppar\Authorizer\Authorizer inherit($parentAbility, $childAbilities): self
 * @method static \Doppar\Authorizer\Authorizer group($groupName, array $abilities): self
 * @method static \Doppar\Authorizer\Authorizer before(callable $callback): self
 * @method static \Doppar\Authorizer\Authorizer after(callable $callback): self
 * @method static \Doppar\Authorizer\Authorizer inGroup($groupName, $ability): bool
 * @method static \Doppar\Authorizer\Authorizer getChildren($ability): array
 * @method static \Doppar\Authorizer\Authorizer check($ability, array $arguments = []): bool
 * @method static \Doppar\Authorizer\Authorizer resolveUserUsing(callable $userResolver): self
 * @method static \Doppar\Authorizer\Authorizer resolveUser(): mixed
 * @method static \Doppar\Authorizer\Authorizer policies(): array
 * @method static \Doppar\Authorizer\Authorizer abilities(): array
 * @method static \Doppar\Authorizer\Authorizer clear(): self
 * @method static \Doppar\Authorizer\Authorizer any(array $abilities, array $arguments = []): bool
 * @method static \Doppar\Authorizer\Authorizer all(array $abilities, array $arguments = []): bool
 * @method static \Doppar\Authorizer\Authorizer hasAbility($ability): bool
 * @method static \Doppar\Authorizer\Authorizer getAllAbilities(): array
 * @see \Doppar\Authorizer\Authorizer
 */

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
