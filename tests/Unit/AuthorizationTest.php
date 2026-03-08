<?php

namespace Doppar\Authorizer\Tests\Unit;

use Doppar\Authorizer\Authorizer;
use PHPUnit\Framework\TestCase;

class AuthorizationTest extends TestCase
{
    private Authorizer $authorizer;

    protected function setUp(): void
    {
        $this->authorizer = new Authorizer();
    }

    // =====================================================
    // TEST ABILITY DEFINITION AND BASIC CHECKS
    // =====================================================

    public function testDefineAndAllowsAbility(): void
    {
        $this->authorizer->define('edit-settings', function ($user) {
            return $user->isAdmin;
        });

        $adminUser = new class {
            public $isAdmin = true;
        };

        $this->authorizer->resolveUserUsing(fn() => $adminUser);
        $this->assertTrue($this->authorizer->allows('edit-settings'));
    }

    public function testDefineAndDeniesAbility(): void
    {
        $this->authorizer->define('edit-settings', function ($user) {
            return $user->isAdmin;
        });

        $regularUser = new class {
            public $isAdmin = false;
        };

        $this->authorizer->resolveUserUsing(fn() => $regularUser);
        $this->assertFalse($this->authorizer->allows('edit-settings'));
        $this->assertTrue($this->authorizer->denies('edit-settings'));
    }

    public function testDeniesIsInverseOfAllows(): void
    {
        $this->authorizer->define('view-reports', fn($user) => $user->canViewReports);

        $user = new class {
            public $canViewReports = true;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->assertTrue($this->authorizer->allows('view-reports'));
        $this->assertFalse($this->authorizer->denies('view-reports'));
    }

    public function testUndefinedAbilityReturnsFalse(): void
    {
        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('nonexistent-ability'));
        $this->assertTrue($this->authorizer->denies('nonexistent-ability'));
    }

    public function testNullUserReturnsFalseForUserParamAbility(): void
    {
        $this->authorizer->define('edit-settings', function ($user) {
            return $user->isAdmin;
        });

        $this->authorizer->resolveUserUsing(fn() => null);
        $this->assertFalse($this->authorizer->allows('edit-settings'));
    }

    public function testMultipleAbilitiesCanBeDefined(): void
    {
        $this->authorizer->define('create-post', fn($user) => $user->role === 'editor');
        $this->authorizer->define('delete-post', fn($user) => $user->role === 'admin');
        $this->authorizer->define('view-post', fn($user) => true);

        $editor = new class {
            public $role = 'editor';
        };

        $this->authorizer->resolveUserUsing(fn() => $editor);
        $this->assertTrue($this->authorizer->allows('create-post'));
        $this->assertFalse($this->authorizer->allows('delete-post'));
        $this->assertTrue($this->authorizer->allows('view-post'));
    }

    // =====================================================
    // TEST ABILITY WITH ARGUMENTS
    // =====================================================

    public function testAllowsWithModelArgument(): void
    {
        $this->authorizer->define('update-post', function ($user, $post) {
            return (int) $user->id === (int) $post->user_id;
        });

        $user = new class {
            public $id = 1;
        };
        $post = new class {
            public $user_id = 1;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->assertTrue($this->authorizer->allows('update-post', $post));
    }

    public function testDeniesWithMismatchedModelArgument(): void
    {
        $this->authorizer->define('update-post', function ($user, $post) {
            return (int) $user->id === (int) $post->user_id;
        });

        $user = new class {
            public $id = 2;
        };
        $post = new class {
            public $user_id = 1;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->assertFalse($this->authorizer->allows('update-post', $post));
    }

    public function testAllowsWithMultipleArguments(): void
    {
        $this->authorizer->define('transfer-funds', function ($user, $account, $amount) {
            return $user->id === $account->owner_id && $amount <= $account->balance;
        });

        $user = new class {
            public $id = 1;
        };
        $account = new class {
            public $owner_id = 1;
            public $balance = 500;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->assertTrue($this->authorizer->allows('transfer-funds', $account, 200));
        $this->assertFalse($this->authorizer->allows('transfer-funds', $account, 600));
    }

    // =====================================================
    // TEST POLICY REGISTRATION AND AUTHORIZATION
    // =====================================================

    public function testPolicyRegistration(): void
    {
        $policy = new class {
            public function edit($user, $model)
            {
                return true;
            }
        };

        $model = new class {};

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->assertSame([get_class($model) => get_class($policy)], $this->authorizer->policies());
    }

    public function testPolicyAuthorizationAllows(): void
    {
        $policy = new class {
            public function update($user, $model)
            {
                return $user->id === $model->owner_id;
            }
        };

        $model = new class {
            public $owner_id = 1;
        };
        $user  = new class {
            public $id = 1;
        };

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('update', $model));
    }

    public function testPolicyAuthorizationDenies(): void
    {
        $policy = new class {
            public function update($user, $model)
            {
                return $user->id === $model->owner_id;
            }
        };

        $model     = new class {
            public $owner_id = 1;
        };
        $otherUser = new class {
            public $id = 2;
        };

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->authorizer->resolveUserUsing(fn() => $otherUser);

        $this->assertFalse($this->authorizer->allows('update', $model));
    }

    public function testPolicyWithUndefinedMethodReturnsFalse(): void
    {
        $policy = new class {
            public function view($user, $model)
            {
                return true;
            }
        };

        $model = new class {};
        $user  = new class {};

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->authorizer->resolveUserUsing(fn() => $user);

        // 'delete' is not defined on the policy
        $this->assertFalse($this->authorizer->allows('delete', $model));
    }

    public function testMultiplePoliciesCanBeRegistered(): void
    {
        $postPolicy    = new class {
            public function edit($u, $m)
            {
                return true;
            }
        };
        $commentPolicy = new class {
            public function edit($u, $m)
            {
                return false;
            }
        };

        $post    = new class {};
        $comment = new class {};
        $user    = new class {};

        $this->authorizer->authorize(get_class($post), get_class($postPolicy));
        $this->authorizer->authorize(get_class($comment), get_class($commentPolicy));
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('edit', $post));
        $this->assertFalse($this->authorizer->allows('edit', $comment));
    }

    public function testPoliciesForParentClassAreApplied(): void
    {
        $policy = new class {
            public function view($user, $model)
            {
                return true;
            }
        };

        // Concrete model class
        $model = new class {};
        $user  = new class {};

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('view', $model));
    }

    // =====================================================
    // TEST TEMPORARY ABILITIES
    // =====================================================

    public function testTemporaryAbilityPassesOnFirstCheck(): void
    {
        $this->authorizer->temporary('one-time-access', fn() => true);

        $this->assertTrue($this->authorizer->allows('one-time-access'));
    }

    public function testTemporaryAbilityFailsOnSubsequentChecks(): void
    {
        $this->authorizer->temporary('one-time-access', fn() => true);

        $this->assertTrue($this->authorizer->allows('one-time-access'));
        $this->assertFalse($this->authorizer->allows('one-time-access'));
        $this->assertFalse($this->authorizer->allows('one-time-access'));
    }

    public function testTemporaryAbilityIsRemovedAfterFirstCheck(): void
    {
        $this->authorizer->temporary('temp-ability', fn() => true);

        $this->assertTrue($this->authorizer->hasAbility('temp-ability'));
        $this->authorizer->allows('temp-ability'); // consumes it
        $this->assertFalse($this->authorizer->hasAbility('temp-ability'));
    }

    public function testTemporaryAbilityCallbackIsCalledExactlyOnce(): void
    {
        $callCount = 0;

        $this->authorizer->temporary('counted-ability', function () use (&$callCount) {
            $callCount++;
            return true;
        });

        $this->authorizer->allows('counted-ability');
        $this->authorizer->allows('counted-ability');
        $this->authorizer->allows('counted-ability');

        $this->assertEquals(1, $callCount);
    }

    public function testTemporaryAbilityThatReturnsFalse(): void
    {
        $this->authorizer->temporary('denied-temp', fn() => false);

        $this->assertFalse($this->authorizer->allows('denied-temp'));
        // It's consumed even if it returned false
        $this->assertFalse($this->authorizer->hasAbility('denied-temp'));
    }

    public function testTemporaryAbilityWithUserContext(): void
    {
        $user = new class {
            public $isVerified = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->authorizer->temporary('email-verification', fn($user) => $user->isVerified);

        $this->assertTrue($this->authorizer->allows('email-verification'));
    }

    // =====================================================
    // TEST ABILITY INHERITANCE / HIERARCHY
    // =====================================================

    public function testInheritanceAllowsChildAbilities(): void
    {
        $this->authorizer->define('manage-users',    fn($user) => $user->isAdmin);
        $this->authorizer->define('manage-settings', fn($user) => $user->isAdmin);
        $this->authorizer->inherit('admin', ['manage-users', 'manage-settings']);

        $admin = new class {
            public $isAdmin = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $admin);

        $this->assertTrue($this->authorizer->allows('manage-users'));
        $this->assertTrue($this->authorizer->allows('manage-settings'));
    }

    public function testInheritanceParentGrantsAccessIfAnyChildPasses(): void
    {
        $this->authorizer->define('manage-users',    fn($user) => $user->isAdmin);
        $this->authorizer->define('manage-settings', fn($user) => $user->isAdmin);
        $this->authorizer->inherit('admin', ['manage-users', 'manage-settings']);

        $admin = new class {
            public $isAdmin = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $admin);

        $this->assertTrue($this->authorizer->allows('admin'));
    }

    public function testInheritanceParentDeniedIfAllChildrenFail(): void
    {
        $this->authorizer->define('manage-users',    fn($user) => false);
        $this->authorizer->define('manage-settings', fn($user) => false);
        $this->authorizer->inherit('admin', ['manage-users', 'manage-settings']);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('admin'));
    }

    public function testGetChildrenReturnsRegisteredChildren(): void
    {
        $this->authorizer->inherit('admin', ['manage-users', 'manage-settings']);

        $children = $this->authorizer->getChildren('admin');

        $this->assertSame(['manage-users', 'manage-settings'], $children);
    }

    public function testGetChildrenReturnsEmptyForUnknownAbility(): void
    {
        $this->assertSame([], $this->authorizer->getChildren('nonexistent'));
    }

    public function testInheritanceSingleChildAbility(): void
    {
        $this->authorizer->define('view-dashboard', fn($user) => $user->active);
        $this->authorizer->inherit('dashboard-access', 'view-dashboard'); // string, not array

        $user = new class {
            public $active = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('dashboard-access'));
    }

    public function testInheritanceDoesNotCauseInfiniteLoop(): void
    {
        // Circular-ish definition — should not loop forever
        $this->authorizer->inherit('a', ['b']);
        $this->authorizer->inherit('b', ['a']);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // Should return false without throwing
        $this->assertFalse($this->authorizer->allows('a'));
    }

    public function testGetParentsReturnsCorrectParents(): void
    {
        $this->authorizer->inherit('admin',    ['manage-users']);
        $this->authorizer->inherit('superuser', ['manage-users']);

        $parents = $this->authorizer->getParents('manage-users');

        $this->assertContains('admin',     $parents);
        $this->assertContains('superuser', $parents);
    }

    // =====================================================
    // TEST ABILITY GROUPING
    // =====================================================

    public function testGroupRegistersAbilities(): void
    {
        $this->authorizer->group('content-management', ['create-post', 'edit-post', 'delete-post']);

        $this->assertTrue($this->authorizer->inGroup('content-management', 'edit-post'));
        $this->assertTrue($this->authorizer->inGroup('content-management', 'create-post'));
        $this->assertTrue($this->authorizer->inGroup('content-management', 'delete-post'));
    }

    public function testGroupReturnsFalseForAbilityNotInGroup(): void
    {
        $this->authorizer->group('content-management', ['create-post', 'edit-post']);

        $this->assertFalse($this->authorizer->inGroup('content-management', 'manage-users'));
    }

    public function testGroupReturnsFalseForNonexistentGroup(): void
    {
        $this->assertFalse($this->authorizer->inGroup('nonexistent-group', 'some-ability'));
    }

    public function testMultipleGroupsCanBeRegistered(): void
    {
        $this->authorizer->group('content', ['create-post', 'edit-post']);
        $this->authorizer->group('users',   ['create-user', 'delete-user']);

        $this->assertTrue($this->authorizer->inGroup('content', 'create-post'));
        $this->assertTrue($this->authorizer->inGroup('users',   'create-user'));
        $this->assertFalse($this->authorizer->inGroup('content', 'create-user'));
        $this->assertFalse($this->authorizer->inGroup('users',   'create-post'));
    }

    public function testGroupAbilitiesAreSeparate(): void
    {
        $this->authorizer->group('group-a', ['ability-1', 'ability-2']);
        $this->authorizer->group('group-b', ['ability-3', 'ability-4']);

        $this->assertFalse($this->authorizer->inGroup('group-a', 'ability-3'));
        $this->assertFalse($this->authorizer->inGroup('group-b', 'ability-1'));
    }

    // =====================================================
    // TEST GLOBAL BEFORE CALLBACKS
    // =====================================================

    public function testBeforeCallbackCanGrantAccess(): void
    {
        $this->authorizer->define('some-ability', fn($user) => false); // normally denied

        $this->authorizer->before(function ($user, $ability) {
            return true; // override: always allow
        });

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('some-ability'));
    }

    public function testBeforeCallbackCanDenyAccess(): void
    {
        $this->authorizer->define('some-ability', fn($user) => true); // normally allowed

        $this->authorizer->before(function ($user, $ability) {
            return false; // override: always deny
        });

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('some-ability'));
    }

    public function testBeforeCallbackReturningNullContinuesNormalChecks(): void
    {
        $this->authorizer->define('some-ability', fn($user) => true);

        $this->authorizer->before(function ($user, $ability) {
            return null; // do not short-circuit
        });

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('some-ability'));
    }

    public function testBeforeCallbackReceivesCorrectArguments(): void
    {
        $receivedUser    = null;
        $receivedAbility = null;

        $user = new class {
            public $id = 42;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->authorizer->before(function ($u, $ability) use (&$receivedUser, &$receivedAbility) {
            $receivedUser    = $u;
            $receivedAbility = $ability;
            return null;
        });

        $this->authorizer->define('test-ability', fn() => true);
        $this->authorizer->allows('test-ability');

        $this->assertSame($user, $receivedUser);
        $this->assertEquals('test-ability', $receivedAbility);
    }

    public function testSuperAdminPatternViaBefore(): void
    {
        $this->authorizer->define('admin-only', fn($user) => false);

        $this->authorizer->before(function ($user, $ability) {
            if ($user->isSuperAdmin) {
                return true;
            }
            return null;
        });

        $superAdmin  = new class {
            public $isSuperAdmin = true;
        };
        $regularUser = new class {
            public $isSuperAdmin = false;
        };

        $this->authorizer->resolveUserUsing(fn() => $superAdmin);
        $this->assertTrue($this->authorizer->allows('admin-only'));

        $this->authorizer->resolveUserUsing(fn() => $regularUser);
        $this->assertFalse($this->authorizer->allows('admin-only'));
    }

    public function testMultipleBeforeCallbacksAreRunInOrder(): void
    {
        $order = [];

        $this->authorizer->before(function ($user, $ability) use (&$order) {
            $order[] = 'first';
            return null;
        });

        $this->authorizer->before(function ($user, $ability) use (&$order) {
            $order[] = 'second';
            return null;
        });

        $this->authorizer->define('test', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('test');

        $this->assertEquals(['first', 'second'], $order);
    }

    public function testFirstBeforeCallbackReturningBoolShortCircuits(): void
    {
        $secondCalled = false;

        $this->authorizer->before(fn($user, $ability) => true); // short-circuit

        $this->authorizer->before(function ($user, $ability) use (&$secondCalled) {
            $secondCalled = true;
            return null;
        });

        $this->authorizer->define('test', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('test');

        $this->assertFalse($secondCalled);
    }

    // =====================================================
    // TEST GLOBAL AFTER CALLBACKS
    // =====================================================

    public function testAfterCallbackIsCalledAfterCheck(): void
    {
        $afterCalled = false;

        $this->authorizer->after(function ($user, $ability, $result) use (&$afterCalled) {
            $afterCalled = true;
        });

        $this->authorizer->define('test', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('test');

        $this->assertTrue($afterCalled);
    }

    public function testAfterCallbackReceivesCorrectResult(): void
    {
        $capturedResult = null;

        $this->authorizer->after(function ($user, $ability, $result) use (&$capturedResult) {
            $capturedResult = $result;
        });

        $this->authorizer->define('allowed-action', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('allowed-action');

        $this->assertTrue($capturedResult);
    }

    public function testAfterCallbackReceivesFalseResultWhenDenied(): void
    {
        $capturedResult = null;

        $this->authorizer->after(function ($user, $ability, $result) use (&$capturedResult) {
            $capturedResult = $result;
        });

        $this->authorizer->define('denied-action', fn() => false);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('denied-action');

        $this->assertFalse($capturedResult);
    }

    public function testAfterCallbackIsCalledEvenWhenBeforeShortCircuits(): void
    {
        $afterCalled = false;

        $this->authorizer->before(fn($user, $ability) => true); // short-circuit

        $this->authorizer->after(function ($user, $ability, $result) use (&$afterCalled) {
            $afterCalled = true;
        });

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('bypass');

        $this->assertTrue($afterCalled);
    }

    public function testAfterCallbackIsCalledForTemporaryAbilities(): void
    {
        $afterCalled = false;

        $this->authorizer->after(function ($user, $ability, $result) use (&$afterCalled) {
            $afterCalled = true;
        });

        $this->authorizer->temporary('temp', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('temp');

        $this->assertTrue($afterCalled);
    }

    public function testMultipleAfterCallbacksAllRun(): void
    {
        $log = [];

        $this->authorizer->after(function ($user, $ability, $result) use (&$log) {
            $log[] = 'after-1';
        });
        $this->authorizer->after(function ($user, $ability, $result) use (&$log) {
            $log[] = 'after-2';
        });

        $this->authorizer->define('test', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('test');

        $this->assertContains('after-1', $log);
        $this->assertContains('after-2', $log);
    }

    // =====================================================
    // TEST BULK CHECKS: any() AND all()
    // =====================================================

    public function testAnyReturnsTrueIfAtLeastOneAbilityPasses(): void
    {
        $this->authorizer->define('ability-1', fn() => true);
        $this->authorizer->define('ability-2', fn() => false);
        $this->authorizer->define('ability-3', fn() => false);

        $this->assertTrue($this->authorizer->any(['ability-1', 'ability-2', 'ability-3']));
    }

    public function testAnyReturnsFalseIfNoAbilityPasses(): void
    {
        $this->authorizer->define('ability-1', fn() => false);
        $this->authorizer->define('ability-2', fn() => false);

        $this->assertFalse($this->authorizer->any(['ability-1', 'ability-2']));
    }

    public function testAnyReturnsFalseForEmptyArray(): void
    {
        $this->assertFalse($this->authorizer->any([]));
    }

    public function testAllReturnsTrueIfAllAbilitiesPass(): void
    {
        $this->authorizer->define('ability-1', fn() => true);
        $this->authorizer->define('ability-2', fn() => true);
        $this->authorizer->define('ability-3', fn() => true);

        $this->assertTrue($this->authorizer->all(['ability-1', 'ability-2', 'ability-3']));
    }

    public function testAllReturnsFalseIfAnyAbilityFails(): void
    {
        $this->authorizer->define('ability-1', fn() => true);
        $this->authorizer->define('ability-2', fn() => false);
        $this->authorizer->define('ability-3', fn() => true);

        $this->assertFalse($this->authorizer->all(['ability-1', 'ability-2', 'ability-3']));
    }

    public function testAllReturnsTrueForEmptyArray(): void
    {
        $this->assertTrue($this->authorizer->all([]));
    }

    public function testAnyWithMixedDefinedAndUndefinedAbilities(): void
    {
        $this->authorizer->define('defined-true', fn() => true);

        $this->assertTrue($this->authorizer->any(['undefined-ability', 'defined-true']));
        $this->assertFalse($this->authorizer->any(['undefined-ability', 'another-undefined']));
    }

    public function testAnyChecksWithArguments(): void
    {
        $this->authorizer->define('edit-post', function ($user, $post) {
            return $user->id === $post->user_id;
        });
        $this->authorizer->define('view-post', fn() => true);

        $user = new class {
            public $id = 99;
        };
        $post = new class {
            public $user_id = 1;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        // edit-post fails but view-post passes
        $this->assertTrue($this->authorizer->any(['edit-post', 'view-post'], [$post]));
    }

    // =====================================================
    // TEST hasAbility AND getAllAbilities
    // =====================================================

    public function testHasAbilityReturnsTrueForDefinedAbility(): void
    {
        $this->authorizer->define('defined-ability', fn() => true);
        $this->assertTrue($this->authorizer->hasAbility('defined-ability'));
    }

    public function testHasAbilityReturnsTrueForTemporaryAbility(): void
    {
        $this->authorizer->temporary('temp-ability', fn() => true);
        $this->assertTrue($this->authorizer->hasAbility('temp-ability'));
    }

    public function testHasAbilityReturnsTrueForParentInHierarchy(): void
    {
        $this->authorizer->inherit('parent-ability', ['child-ability']);
        $this->assertTrue($this->authorizer->hasAbility('parent-ability'));
    }

    public function testHasAbilityReturnsFalseForUnregisteredAbility(): void
    {
        $this->assertFalse($this->authorizer->hasAbility('nonexistent'));
    }

    public function testGetAllAbilitiesIncludesAllTypes(): void
    {
        $this->authorizer->define('defined-ability', fn() => true);
        $this->authorizer->temporary('temp-ability', fn() => true);
        $this->authorizer->inherit('parent-ability', ['child-ability']);

        $all = $this->authorizer->getAllAbilities();

        $this->assertContains('defined-ability', $all);
        $this->assertContains('temp-ability',    $all);
        $this->assertContains('parent-ability',  $all);
    }

    public function testGetAllAbilitiesReturnsUniqueValues(): void
    {
        $this->authorizer->define('shared', fn() => true);
        $this->authorizer->inherit('shared', ['child']); // same name in both places

        $all = $this->authorizer->getAllAbilities();
        $this->assertEquals(count($all), count(array_unique($all)));
    }

    // =====================================================
    // TEST USER RESOLUTION
    // =====================================================

    public function testResolveUserUsingRegistersCallback(): void
    {
        $user = new class {
            public $id = 7;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertSame($user, $this->authorizer->resolveUser());
    }

    public function testResolveUserReturnsNullWithNoResolver(): void
    {
        // No resolver registered
        $this->assertNull($this->authorizer->resolveUser());
    }

    public function testResolveUserCallsCallbackEachTime(): void
    {
        $callCount = 0;

        $this->authorizer->resolveUserUsing(function () use (&$callCount) {
            $callCount++;
            return new class {};
        });

        $this->authorizer->resolveUser();
        $this->authorizer->resolveUser();

        $this->assertEquals(2, $callCount);
    }

    // =====================================================
    // TEST abilities() AND policies() ACCESSORS
    // =====================================================

    public function testAbilitiesReturnsRegisteredAbilities(): void
    {
        $this->authorizer->define('ability-a', fn() => true);
        $this->authorizer->define('ability-b', fn() => false);

        $abilities = $this->authorizer->abilities();

        $this->assertArrayHasKey('ability-a', $abilities);
        $this->assertArrayHasKey('ability-b', $abilities);
    }

    public function testPoliciesReturnsRegisteredPolicies(): void
    {
        $policy = new class {};
        $model  = new class {};

        $this->authorizer->authorize(get_class($model), get_class($policy));

        $policies = $this->authorizer->policies();

        $this->assertArrayHasKey(get_class($model), $policies);
        $this->assertEquals(get_class($policy), $policies[get_class($model)]);
    }

    // =====================================================
    // TEST clear()
    // =====================================================

    public function testClearRemovesAbilities(): void
    {
        $this->authorizer->define('test-ability', fn() => true);
        $this->assertNotEmpty($this->authorizer->abilities());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->abilities());
    }

    public function testClearRemovesPolicies(): void
    {
        $policy = new class {};
        $model  = new class {};

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->assertNotEmpty($this->authorizer->policies());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->policies());
    }

    public function testClearReturnsSelf(): void
    {
        $result = $this->authorizer->clear();
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testAfterClearAbilitiesCanBeRedefined(): void
    {
        $this->authorizer->define('test', fn() => true);
        $this->authorizer->clear();
        $this->authorizer->define('test', fn() => false);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('test'));
    }

    // =====================================================
    // TEST METHOD CHAINING
    // =====================================================

    public function testTemporaryReturnsSelf(): void
    {
        $result = $this->authorizer->temporary('t', fn() => true);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testInheritReturnsSelf(): void
    {
        $result = $this->authorizer->inherit('parent', ['child']);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testGroupReturnsSelf(): void
    {
        $result = $this->authorizer->group('g', ['a', 'b']);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testBeforeReturnsSelf(): void
    {
        $result = $this->authorizer->before(fn() => null);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testAfterReturnsSelf(): void
    {
        $result = $this->authorizer->after(fn() => null);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testResolveUserUsingReturnsSelf(): void
    {
        $result = $this->authorizer->resolveUserUsing(fn() => null);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    // =====================================================
    // TEST COMPLEX COMBINED SCENARIOS
    // =====================================================

    public function testSuperAdminBypassesEverything(): void
    {
        $this->authorizer->define('edit-post',   fn($user) => false);
        $this->authorizer->define('delete-user', fn($user) => false);

        $this->authorizer->before(function ($user, $ability) {
            if (isset($user->superAdmin) && $user->superAdmin) {
                return true;
            }
            return null;
        });

        $superAdmin = new class {
            public $superAdmin = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $superAdmin);

        $this->assertTrue($this->authorizer->allows('edit-post'));
        $this->assertTrue($this->authorizer->allows('delete-user'));
        $this->assertTrue($this->authorizer->any(['edit-post', 'delete-user']));
        $this->assertTrue($this->authorizer->all(['edit-post', 'delete-user']));
    }

    public function testHierarchyWithPolicyCombined(): void
    {
        $policy = new class {
            public function view($user, $model)
            {
                return $user->id === $model->owner_id;
            }
        };

        $model = new class {
            public $owner_id = 5;
        };
        $user  = new class {
            public $id = 5;
            public $isAdmin = true;
        };

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->authorizer->define('admin-view', fn($user) => $user->isAdmin);
        $this->authorizer->inherit('full-access', ['admin-view']);

        $this->authorizer->resolveUserUsing(fn() => $user);

        // Policy-based check
        $this->assertTrue($this->authorizer->allows('view', $model));
        // Hierarchy-based check
        $this->assertTrue($this->authorizer->allows('full-access'));
    }

    public function testLoggingViaAfterCallbackAcrossMultipleChecks(): void
    {
        $log = [];

        $this->authorizer->after(function ($user, $ability, $result) use (&$log) {
            $log[] = ['ability' => $ability, 'result' => $result];
        });

        $this->authorizer->define('action-1', fn() => true);
        $this->authorizer->define('action-2', fn() => false);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->authorizer->allows('action-1');
        $this->authorizer->allows('action-2');

        $this->assertCount(2, $log);
        $this->assertEquals('action-1', $log[0]['ability']);
        $this->assertTrue($log[0]['result']);
        $this->assertEquals('action-2', $log[1]['ability']);
        $this->assertFalse($log[1]['result']);
    }

    public function testAbilityOverrideReplacesCallback(): void
    {
        $this->authorizer->define('mutable', fn() => false);
        // Redefine the same ability
        $this->authorizer->define('mutable', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('mutable'));
    }

    public function testCheckDirectlyOnAuthorizer(): void
    {
        $this->authorizer->define('direct-check', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->check('direct-check'));
    }

    public function testCheckWithArgumentsPassedAsArray(): void
    {
        $this->authorizer->define('match-id', function ($user, $resource) {
            return $user->id === $resource->id;
        });

        $user     = new class {
            public $id = 3;
        };
        $resource = new class {
            public $id = 3;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->check('match-id', [$resource]));
    }
}
