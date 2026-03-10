<?php

namespace Doppar\Authorizer\Support\Facades;

/**
 * @method static \Doppar\Authorizer\Authorizer authorize($class, $authorizer): void
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
 * @method static \Doppar\Authorizer\Authorizer getParents($ability): array
 * @method static \Doppar\Authorizer\Authorizer check($ability, array $arguments = [], array $visited = []): bool
 * @method static \Doppar\Authorizer\Authorizer resolveUserUsing(callable $userResolver): self
 * @method static \Doppar\Authorizer\Authorizer resolveUser(): mixed
 * @method static \Doppar\Authorizer\Authorizer policies(): array
 * @method static \Doppar\Authorizer\Authorizer abilities(): array
 * @method static \Doppar\Authorizer\Authorizer clear(): self
 * @method static \Doppar\Authorizer\Authorizer any(array $abilities, array $arguments = []): bool
 * @method static \Doppar\Authorizer\Authorizer all(array $abilities, array $arguments = []): bool
 * @method static \Doppar\Authorizer\Authorizer hasAbility($ability): bool
 * @method static \Doppar\Authorizer\Authorizer getAllAbilities(): array
 * @method static \Doppar\Authorizer\Authorizer alias(string $alias, string $ability): self
 * @method static \Doppar\Authorizer\Authorizer aliases(): array
 * @method static \Doppar\Authorizer\Authorizer resolveAlias(string $ability): string
 * @method static \Doppar\Authorizer\Authorizer wildcard(string $pattern, callable $callback): self
 * @method static \Doppar\Authorizer\Authorizer matchWildcard(string $ability): ?string
 * @method static \Doppar\Authorizer\Authorizer condition(string $ability, callable $condition): self
 * @method static \Doppar\Authorizer\Authorizer conditions(): array
 * @method static \Doppar\Authorizer\Authorizer roles(array $map, string $property = 'role'): self
 * @method static \Doppar\Authorizer\Authorizer roleMap(): array
 * @method static \Doppar\Authorizer\Authorizer roleProperty(): string
 * @method static \Doppar\Authorizer\Authorizer lazy(string $ability, callable $callback): self
 * @method static \Doppar\Authorizer\Authorizer lazyAbilities(): array
 * @method static \Doppar\Authorizer\Authorizer vote(string $ability, array $voters, string $strategy = 'majority'): self
 * @method static \Doppar\Authorizer\Authorizer votingAbilities(): array
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
