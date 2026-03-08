<?php

namespace Doppar\Authorizer;

class Authorizer
{
    /**
     * @var array The registered policies
     */
    protected $policies = [];

    /**
     * @var array The registered abilities (gates)
     */
    protected $abilities = [];

    /**
     * @var callable The callback to resolve the current user
     */
    protected $userResolver;

    /**
     * @var array Temporary abilities that expire after first check
     */
    protected $temporaryAbilities = [];

    /**
     * @var array Ability hierarchies (parent -> child relationships)
     */
    protected $abilityHierarchies = [];

    /**
     * @var array Ability groups
     */
    protected $abilityGroups = [];

    /**
     * @var array Global before callbacks
     */
    protected $beforeCallbacks = [];

    /**
     * @var array Global after callbacks
     */
    protected $afterCallbacks = [];

    /**
     * @var array Ability aliases
     */
    protected $abilityAliases = [];

    /**
     * @var array Conditional ability callbacks
     */
    protected $conditionalAbilities = [];

    /**
     * Register a authorizer for a given class.
     *
     * @param string $class
     * @param string $authorizer
     * @return void
     */
    public function authorize($class, $authorizer): void
    {
        $this->policies[$class] = $authorizer;
    }

    /**
     * Register an ability with the Guard.
     *
     * @param string $ability
     * @param callable $callback
     * @return void
     */
    public function define($ability, callable $callback): void
    {
        $this->abilities[$ability] = $callback;
    }

    /**
     * Register an alias that maps to an existing ability name.
     *
     * Example:
     *   Guard::alias('edit', 'update-post');
     *   Guard::allows('edit', $post);
     *
     * @param string $alias
     * @param string $ability
     * @return $this
     */
    public function alias(string $alias, string $ability): self
    {
        $this->abilityAliases[$alias] = $ability;

        return $this;
    }

    /**
     * Register a wildcard ability pattern.
     *
     * Supported pattern styles:
     *   'post.*'          matches post.create, post.edit, post.delete, …
     *   '*.create'        matches post.create, comment.create, …
     *   'admin.*.*'       matches admin.users.delete, admin.settings.edit, …
     *   '*'               matches every ability
     *
     * Example:
     *   Guard::wildcard('post.*', fn($user) => $user->isEditor);
     *   Guard::allows('post.delete');
     *
     * @param string $pattern
     * @param callable $callback
     * @return $this
     */
    public function wildcard(string $pattern, callable $callback): self
    {
        $this->abilities[$pattern] = $callback;

        return $this;
    }

    /**
     * Register a conditional ability that is only active when a runtime condition passes.
     *
     * Example — weekend-only access:
     *   Guard::condition('weekend-export', fn() => now()->isWeekend());
     *   Guard::define('weekend-export', fn($user) => $user->isPremium);
     *
     * Example — feature-flag gated ability:
     *   Guard::condition('beta-dashboard', fn() => config('features.beta'));
     *   Guard::define('beta-dashboard', fn($user) => true);
     *
     * @param string $ability
     * @param callable $condition
     * @return $this
     */
    public function condition(string $ability, callable $condition): self
    {
        $this->conditionalAbilities[$ability] = $condition;

        return $this;
    }

    /**
     * Determine if the given ability should be granted for the current user.
     *
     * @param string $ability
     * @param mixed ...$arguments
     * @return bool
     */
    public function allows($ability, ...$arguments): bool
    {
        return $this->check($ability, $arguments);
    }

    /**
     * Determine if the given ability should be denied for the current user.
     *
     * @param string $ability
     * @param mixed ...$arguments
     * @return bool
     */
    public function denies($ability, ...$arguments): bool
    {
        return !$this->allows($ability, ...$arguments);
    }

    /**
     * Register a temporary ability that expires after first check.
     *
     * @param string $ability
     * @param callable $callback
     * @return $this
     */
    public function temporary($ability, callable $callback): self
    {
        $this->temporaryAbilities[$ability] = $callback;

        return $this;
    }

    /**
     * Define a parent-child relationship between abilities.
     *
     * @param string $parentAbility
     * @param string|array $childAbilities
     * @return $this
     */
    public function inherit($parentAbility, $childAbilities): self
    {
        if (!is_array($childAbilities)) {
            $childAbilities = [$childAbilities];
        }

        foreach ($childAbilities as $childAbility) {
            $this->abilityHierarchies[$parentAbility][] = $childAbility;
        }

        return $this;
    }

    /**
     * Group multiple abilities together.
     *
     * @param string $groupName
     * @param array $abilities
     * @return $this
     */
    public function group($groupName, array $abilities): self
    {
        $this->abilityGroups[$groupName] = $abilities;

        return $this;
    }

    /**
     * Register a global before callback.
     *
     * @param callable $callback
     * @return $this
     */
    public function before(callable $callback): self
    {
        $this->beforeCallbacks[] = $callback;

        return $this;
    }

    /**
     * Register a global after callback.
     *
     * @param callable $callback
     * @return $this
     */
    public function after(callable $callback): self
    {
        $this->afterCallbacks[] = $callback;

        return $this;
    }

    /**
     * Check if ability belongs to a group.
     *
     * @param string $groupName
     * @param string $ability
     * @return bool
     */
    public function inGroup($groupName, $ability): bool
    {
        return isset($this->abilityGroups[$groupName]) &&
            in_array($ability, $this->abilityGroups[$groupName]);
    }

    /**
     * Get all child abilities for a parent ability.
     *
     * @param string $ability
     * @return array
     */
    public function getChildren($ability): array
    {
        return $this->abilityHierarchies[$ability] ?? [];
    }

    /**
     * Resolve an ability name through the alias chain.
     *
     * @param string $ability
     * @return string
     */
    public function resolveAlias(string $ability): string
    {
        $visited = [];

        while (isset($this->abilityAliases[$ability])) {
            if (in_array($ability, $visited, true)) {
                // Circular alias chain — break out and return current
                break;
            }
            $visited[] = $ability;
            $ability   = $this->abilityAliases[$ability];
        }

        return $ability;
    }

    /**
     * Find the first wildcard pattern in $this->abilities that matches
     * the given ability name and return the pattern key, or null if none match.
     *
     * @param string $ability
     * @return string|null
     */
    public function matchWildcard(string $ability): ?string
    {
        foreach (array_keys($this->abilities) as $pattern) {
            if (strpos($pattern, '*') === false) {
                continue; // not a wildcard pattern
            }

            if ($this->wildcardPatternMatches($pattern, $ability)) {
                return $pattern;
            }
        }

        return null;
    }

    /**
     * Test whether a wildcard pattern matches a concrete ability name.
     *
     * @param string $pattern
     * @param string $ability
     * @return bool
     */
    protected function wildcardPatternMatches(string $pattern, string $ability): bool
    {
        if ($pattern === '*') {
            return true;
        }

        // Convert the pattern into a regex:
        // escape dots, then replace * with [^.]+ (non-dot chars)
        $regex = '/^' . str_replace('\*', '[^.]+', preg_quote($pattern, '/')) . '$/';

        return (bool) preg_match($regex, $ability);
    }

    /**
     * Return the registered aliases map.
     *
     * @return array<string, string>
     */
    public function aliases(): array
    {
        return $this->abilityAliases;
    }

    /**
     * Return the registered conditional ability callbacks.
     *
     * @return array<string, callable>
     */
    public function conditions(): array
    {
        return $this->conditionalAbilities;
    }

    /**
     * Enhanced check method with all features.
     *
     * @param string $ability
     * @param array  $arguments
     * @param array  $visited
     * @return bool
     */
    public function check($ability, array $arguments = [], array $visited = []): bool
    {
        // Resolve alias
        $ability = $this->resolveAlias($ability);

        if (in_array($ability, $visited)) {
            return false;
        }
        $visited[] = $ability;

        $user = $this->resolveUser();

        // Global before callbacks
        foreach ($this->beforeCallbacks as $callback) {
            $callbackArgs = array_merge([$user, $ability], $arguments);
            $result       = call_user_func_array($callback, $callbackArgs);
            if ($result !== null) {
                foreach ($this->afterCallbacks as $afterCallback) {
                    $afterArgs = array_merge([$user, $ability, $result], $arguments);
                    call_user_func_array($afterCallback, $afterArgs);
                }
                return (bool) $result;
            }
        }

        // Conditional guard — if a condition is registered and fails, deny immediately
        if (isset($this->conditionalAbilities[$ability])) {
            if (!call_user_func($this->conditionalAbilities[$ability])) {
                $result = false;
                foreach ($this->afterCallbacks as $afterCallback) {
                    $afterArgs = array_merge([$user, $ability, $result], $arguments);
                    call_user_func_array($afterCallback, $afterArgs);
                }
                return $result;
            }
        }

        // Temporary abilities
        if (isset($this->temporaryAbilities[$ability])) {
            $callback = $this->temporaryAbilities[$ability];
            unset($this->temporaryAbilities[$ability]);
            $result = $this->callAuthCallback($user, $callback, $arguments);

            foreach ($this->afterCallbacks as $afterCallback) {
                $afterArgs = array_merge([$user, $ability, $result], $arguments);
                call_user_func_array($afterCallback, $afterArgs);
            }

            return $result;
        }

        // Directly defined ability
        if (isset($this->abilities[$ability])) {
            $result = $this->callAuthCallback($user, $this->abilities[$ability], $arguments);

            foreach ($this->afterCallbacks as $afterCallback) {
                $afterArgs = array_merge([$user, $ability, $result], $arguments);
                call_user_func_array($afterCallback, $afterArgs);
            }

            return $result;
        }

        // Wildcard ability match
        $wildcardPattern = $this->matchWildcard($ability);
        if ($wildcardPattern !== null) {
            $result = $this->callAuthCallback($user, $this->abilities[$wildcardPattern], $arguments);

            foreach ($this->afterCallbacks as $afterCallback) {
                $afterArgs = array_merge([$user, $ability, $result], $arguments);
                call_user_func_array($afterCallback, $afterArgs);
            }

            return $result;
        }

        // Hierarchy: parent -> children
        if (isset($this->abilityHierarchies[$ability])) {
            foreach ($this->abilityHierarchies[$ability] as $childAbility) {
                if ($this->check($childAbility, $arguments, $visited)) {
                    return true;
                }
            }
        }

        // Hierarchy: child -> parents
        $parentAbilities = $this->getParents($ability);
        foreach ($parentAbilities as $parentAbility) {
            if ($this->check($parentAbility, $arguments, $visited)) {
                return true;
            }
        }

        // Policy-based authorization
        if (!empty($arguments)) {
            $result = $this->authorizeViaPolicy($ability, $user, $arguments);

            foreach ($this->afterCallbacks as $callback) {
                $this->callAuthCallback($user, $callback, [$ability, $result] + $arguments);
            }

            return $result;
        }

        // After callbacks — denied
        foreach ($this->afterCallbacks as $callback) {
            $this->callAuthCallback($user, $callback, [$ability, false] + $arguments);
        }

        return false;
    }

    public function getParents($ability): array
    {
        $parents = [];
        foreach ($this->abilityHierarchies as $parent => $children) {
            if (in_array($ability, $children)) {
                $parents[] = $parent;
            }
        }

        return $parents;
    }

    /**
     * Attempt authorization via policy methods.
     *
     * @param string $ability
     * @param mixed $user
     * @param array $arguments
     * @return bool
     */
    protected function authorizeViaPolicy($ability, $user, array $arguments): bool
    {
        $model  = $arguments[0];
        $policy = $this->getPolicyFor($model);

        if (!$policy) {
            return false;
        }

        if (is_string($policy)) {
            $policy = new $policy;
        }

        if (method_exists($policy, $ability)) {
            return $this->callPolicyMethod($policy, $ability, $user, $arguments);
        }

        return false;
    }

    /**
     * Call an authorization callback.
     *
     * @param mixed $user
     * @param callable $callback
     * @param array $arguments
     * @return bool
     */
    protected function callAuthCallback($user, callable $callback, array $arguments = []): bool
    {
        if ($user === null) {
            $reflection = new \ReflectionFunction($callback);
            $parameters = $reflection->getParameters();

            if (!empty($parameters) && $parameters[0]->getName() === 'user') {
                return false;
            }
        }

        array_unshift($arguments, $user);

        return call_user_func_array($callback, $arguments) === true;
    }

    /**
     * Call a policy method.
     *
     * @param mixed $policy
     * @param string $method
     * @param mixed $user
     * @param array $arguments
     * @return bool
     */
    protected function callPolicyMethod($policy, $method, $user, array $arguments): bool
    {
        $result = call_user_func_array(
            [$policy, $method],
            array_merge([$user], $arguments)
        );

        return $result === true;
    }

    /**
     * Get a policy instance for a given class.
     *
     * @param mixed $class
     * @return mixed
     */
    protected function getPolicyFor($class): ?object
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        if (!is_string($class)) {
            return null;
        }

        if (isset($this->policies[$class])) {
            $policy = $this->policies[$class];
            return is_string($policy) ? new $policy : $policy;
        }

        foreach ($this->policies as $policyClass => $policy) {
            if (is_a($class, $policyClass, true)) {
                return is_string($policy) ? new $policy : $policy;
            }
        }

        return null;
    }

    /**
     * Set the callback to be used to resolve the current user.
     *
     * @param callable $userResolver
     * @return $this
     */
    public function resolveUserUsing(callable $userResolver): self
    {
        $this->userResolver = $userResolver;

        return $this;
    }

    /**
     * Resolve the current user.
     *
     * @return mixed
     */
    public function resolveUser(): mixed
    {
        if (is_callable($this->userResolver)) {
            return call_user_func($this->userResolver);
        }

        return null;
    }

    /**
     * Get all registered policies.
     *
     * @return array
     */
    public function policies(): array
    {
        return $this->policies;
    }

    /**
     * Get all registered abilities.
     *
     * @return array
     */
    public function abilities(): array
    {
        return $this->abilities;
    }

    /**
     * Clear all policies and abilities.
     *
     * @return $this
     */
    public function clear(): self
    {
        $this->policies              = [];
        $this->abilities             = [];
        $this->abilityAliases        = [];
        $this->conditionalAbilities  = [];

        return $this;
    }

    /**
     * Check if a user has any of the given abilities.
     *
     * @param array $abilities
     * @param array $arguments
     * @return bool
     */
    public function any(array $abilities, array $arguments = []): bool
    {
        foreach ($abilities as $ability) {
            if ($this->check($ability, $arguments)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a user has all of the given abilities.
     *
     * @param array $abilities
     * @param array $arguments
     * @return bool
     */
    public function all(array $abilities, array $arguments = []): bool
    {
        foreach ($abilities as $ability) {
            if (!$this->check($ability, $arguments)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if ability exists (defined, temporary, in hierarchy, or a wildcard pattern).
     *
     * @param string $ability
     * @return bool
     */
    public function hasAbility($ability): bool
    {
        if (isset($this->abilities[$ability]) || isset($this->temporaryAbilities[$ability])) {
            return true;
        }

        if (isset($this->abilityHierarchies[$ability])) {
            return true;
        }

        foreach ($this->abilityHierarchies as $children) {
            if (in_array($ability, $children)) {
                return true;
            }
        }

        // Check alias resolution
        if (isset($this->abilityAliases[$ability])) {
            return true;
        }

        // Check wildcard match
        if ($this->matchWildcard($ability) !== null) {
            return true;
        }

        return false;
    }

    /**
     * Get all abilities including temporary ones and hierarchy parents.
     *
     * @return array
     */
    public function getAllAbilities(): array
    {
        return array_unique(array_merge(
            array_keys($this->abilities),
            array_keys($this->temporaryAbilities),
            array_keys($this->abilityHierarchies)
        ));
    }
}
