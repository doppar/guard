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
     * Register a policy for a given class.
     *
     * @param string $class
     * @param string $policy
     * @return void
     */
    public function policy($class, $policy): void
    {
        $this->policies[$class] = $policy;
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
     * Enhanced check method with all new features.
     *
     * @param string $ability
     * @param array $arguments
     * @return bool
     */
    public function check($ability, array $arguments = []): bool
    {
        $user = $this->resolveUser();

        // Run global before callbacks
        foreach ($this->beforeCallbacks as $callback) {
            $callbackArgs = array_merge([$user, $ability], $arguments);
            $result = call_user_func_array($callback, $callbackArgs);
            if ($result !== null) {
                // Run after callbacks even if before callback returns a result
                foreach ($this->afterCallbacks as $afterCallback) {
                    $afterArgs = array_merge([$user, $ability, $result], $arguments);
                    call_user_func_array($afterCallback, $afterArgs);
                }
                return (bool)$result;
            }
        }

        // Check temporary abilities first
        if (isset($this->temporaryAbilities[$ability])) {
            $callback = $this->temporaryAbilities[$ability];
            unset($this->temporaryAbilities[$ability]);
            $result = $this->callAuthCallback($user, $callback, $arguments);

            // Run after callbacks
            foreach ($this->afterCallbacks as $afterCallback) {
                $afterArgs = array_merge([$user, $ability, $result], $arguments);
                call_user_func_array($afterCallback, $afterArgs);
            }

            return $result;
        }

        // Check for directly defined abilities
        if (isset($this->abilities[$ability])) {
            $result = $this->callAuthCallback($user, $this->abilities[$ability], $arguments);

            // Run after callbacks
            foreach ($this->afterCallbacks as $afterCallback) {
                $afterArgs = array_merge([$user, $ability, $result], $arguments);
                call_user_func_array($afterCallback, $afterArgs);
            }

            return $result;
        }

        // Check if ability is a child in any hierarchy
        foreach ($this->abilityHierarchies as $parentAbility => $childAbilities) {
            if (in_array($ability, $childAbilities)) {
                // If the parent ability is allowed, then the child is allowed
                if ($this->check($parentAbility, $arguments)) {
                    return true;
                }
            }
        }

        // Check for policy-based authorization
        if (!empty($arguments)) {
            $result = $this->authorizeViaPolicy($ability, $user, $arguments);

            // Run global after callbacks
            foreach ($this->afterCallbacks as $callback) {
                $this->callAuthCallback($user, $callback, [$ability, $result] + $arguments);
            }

            return $result;
        }

        // Run global after callbacks
        foreach ($this->afterCallbacks as $callback) {
            $this->callAuthCallback($user, $callback, [$ability, false] + $arguments);
        }

        return false;
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
        $model = $arguments[0];
        $policy = $this->getPolicyFor($model);

        if ($policy && method_exists($policy, $ability)) {
            return $this->callPolicyMethod(
                $policy,
                $ability,
                $user,
                $arguments
            );
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
        // If no user is provided
        // the callback expects a user parameter, return false
        if ($user === null) {
            $reflection = new \ReflectionFunction($callback);
            $parameters = $reflection->getParameters();

            // If the first parameter is a user parameter, 
            // return false for null users
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
    protected function getPolicyFor($class): mixed
    {
        if (is_object($class)) {
            $class = get_class($class);
        }

        if (isset($this->policies[$class])) {
            return new $this->policies[$class];
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
        $this->policies = [];
        $this->abilities = [];

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
     * Check if ability exists (defined, temporary, or in hierarchy).
     *
     * @param string $ability
     * @return bool
     */
    public function hasAbility($ability): bool
    {
        return isset($this->abilities[$ability]) ||
            isset($this->temporaryAbilities[$ability]) ||
            isset($this->abilityHierarchies[$ability]);
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
