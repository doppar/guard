<?php

namespace Doppar\Authorizer\Tests\Unit;

use Doppar\Authorizer\Authorizer;
use PHPUnit\Framework\TestCase;

/**
 * Tests for three new Guard features:
 *  - Role Inference
 *  - Lazy Abilities
 *  - Ability Voting
 */
class RoleLazyVoteTest extends TestCase
{
    private Authorizer $authorizer;

    protected function setUp(): void
    {
        $this->authorizer = new Authorizer();
    }

    // =========================================================================
    // ROLE INFERENCE
    // =========================================================================

    public function testRoleGrantsExactAbility(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.create', 'post.edit'],
        ]);

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertTrue($this->authorizer->allows('post.edit'));
    }

    public function testRoleDeniesAbilityNotInList(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.create', 'post.edit'],
        ]);

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertFalse($this->authorizer->allows('post.delete'));
        $this->assertFalse($this->authorizer->allows('manage-users'));
    }

    public function testRoleWithWildcardPattern(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.*'],
        ]);

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertTrue($this->authorizer->allows('post.edit'));
        $this->assertTrue($this->authorizer->allows('post.delete'));
        $this->assertTrue($this->authorizer->allows('post.publish'));
    }

    public function testRoleWildcardDoesNotMatchOtherResources(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.*'],
        ]);

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertFalse($this->authorizer->allows('comment.create'));
        $this->assertFalse($this->authorizer->allows('user.delete'));
    }

    public function testMultipleRolesAreIndependent(): void
    {
        $this->authorizer->roles([
            'admin'  => ['manage-users', 'manage-settings'],
            'editor' => ['post.create', 'post.edit'],
            'viewer' => ['post.view'],
        ]);

        $admin  = new class {
            public $role = 'admin';
        };
        $editor = new class {
            public $role = 'editor';
        };
        $viewer = new class {
            public $role = 'viewer';
        };

        $this->authorizer->resolveUserUsing(fn() => $admin);
        $this->assertTrue($this->authorizer->allows('manage-users'));
        $this->assertFalse($this->authorizer->allows('post.create'));

        $this->authorizer->resolveUserUsing(fn() => $editor);
        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertFalse($this->authorizer->allows('manage-users'));

        $this->authorizer->resolveUserUsing(fn() => $viewer);
        $this->assertTrue($this->authorizer->allows('post.view'));
        $this->assertFalse($this->authorizer->allows('post.edit'));
    }

    public function testUnregisteredRoleReturnsFalse(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.create'],
        ]);

        $unknown = new class {
            public $role = 'unknown-role';
        };
        $this->authorizer->resolveUserUsing(fn() => $unknown);

        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    public function testUserWithNoRolePropertyReturnsFalse(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.create'],
        ]);

        $user = new class {}; // no 'role' property
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    public function testNullUserReturnsFalseForRoleCheck(): void
    {
        $this->authorizer->roles([
            'editor' => ['post.create'],
        ]);

        $this->authorizer->resolveUserUsing(fn() => null);

        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    public function testCustomRoleProperty(): void
    {
        $this->authorizer->roles([
            'superuser' => ['manage-everything'],
        ], property: 'access_level');

        $user = new class {
            public $access_level = 'superuser';
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('manage-everything'));
    }

    public function testRolePropertyAccessorReturnsConfiguredValue(): void
    {
        $this->authorizer->roles([], property: 'permission_level');
        $this->assertEquals('permission_level', $this->authorizer->roleProperty());
    }

    public function testRoleMapAccessorReturnsFullMap(): void
    {
        $this->authorizer->roles([
            'admin'  => ['manage-users'],
            'editor' => ['post.create'],
        ]);

        $map = $this->authorizer->roleMap();

        $this->assertArrayHasKey('admin',  $map);
        $this->assertArrayHasKey('editor', $map);
        $this->assertEquals(['manage-users'], $map['admin']);
    }

    public function testRoleReturnsSelf(): void
    {
        $result = $this->authorizer->roles(['admin' => ['manage-users']]);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testDefinedAbilityTakesPrecedenceOverRole(): void
    {
        // explicit define denies
        $this->authorizer->define('post.create', fn($user) => false);

        // role would grant
        $this->authorizer->roles(['editor' => ['post.create']]);

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        // defined ability is checked before role inference
        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    public function testBeforeCallbackOverridesRole(): void
    {
        $this->authorizer->roles(['editor' => ['post.create']]);
        $this->authorizer->before(fn($user, $ability) => false); // deny everything

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    public function testRoleWorksWithAnyBulkCheck(): void
    {
        $this->authorizer->roles(['editor' => ['post.create', 'post.edit']]);

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->any(['post.create', 'manage-users']));
        $this->assertFalse($this->authorizer->all(['post.create', 'manage-users']));
    }

    public function testRoleWorksWithAlias(): void
    {
        $this->authorizer->roles(['editor' => ['post.create']]);
        $this->authorizer->alias('write', 'post.create');

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('write'));
    }

    public function testClearRemovesRoles(): void
    {
        $this->authorizer->roles(['editor' => ['post.create']]);
        $this->assertNotEmpty($this->authorizer->roleMap());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->roleMap());
    }

    public function testRoleWithGlobalWildcardGrantsAll(): void
    {
        $this->authorizer->roles(['superadmin' => ['*']]);

        $superadmin = new class {
            public $role = 'superadmin';
        };
        $this->authorizer->resolveUserUsing(fn() => $superadmin);

        $this->assertTrue($this->authorizer->allows('anything'));
        $this->assertTrue($this->authorizer->allows('post.delete'));
        $this->assertTrue($this->authorizer->allows('manage-users'));
    }

    // =========================================================================
    // LAZY ABILITIES
    // =========================================================================

    public function testLazyAbilityIsEvaluatedOnFirstCheck(): void
    {
        $evaluated = false;

        $this->authorizer->lazy('heavy-check', function () use (&$evaluated) {
            $evaluated = true;
            return true;
        });

        $this->assertFalse($evaluated, 'Callback must not run before first check');

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->authorizer->allows('heavy-check');

        $this->assertTrue($evaluated, 'Callback must run on first check');
    }

    public function testLazyAbilityCallbackIsNotCalledIfNeverChecked(): void
    {
        $called = false;

        $this->authorizer->lazy('never-checked', function () use (&$called) {
            $called = true;
            return true;
        });

        // Deliberately never calling allows('never-checked')

        $this->assertFalse($called);
    }

    public function testLazyAbilityGrantsAccess(): void
    {
        $this->authorizer->lazy('lazy-allow', fn($user) => $user->isPremium);

        $premium = new class {
            public $isPremium = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $premium);

        $this->assertTrue($this->authorizer->allows('lazy-allow'));
    }

    public function testLazyAbilityDeniesAccess(): void
    {
        $this->authorizer->lazy('lazy-deny', fn($user) => $user->isPremium);

        $free = new class {
            public $isPremium = false;
        };
        $this->authorizer->resolveUserUsing(fn() => $free);

        $this->assertFalse($this->authorizer->allows('lazy-deny'));
    }

    public function testLazyAbilityIsPromotedAfterFirstCheck(): void
    {
        $this->authorizer->lazy('promoted', fn() => true);

        $this->assertArrayHasKey('promoted', $this->authorizer->lazyAbilities());

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('promoted');

        // After promotion, lazy registry is cleared for this ability
        $this->assertArrayNotHasKey('promoted', $this->authorizer->lazyAbilities());
        // But it is now in standard abilities
        $this->assertArrayHasKey('promoted', $this->authorizer->abilities());
    }

    public function testLazyAbilityIsNotCalledBeforeFirstCheck(): void
    {
        $callCount = 0;

        $this->authorizer->lazy('counted', function () use (&$callCount) {
            $callCount++;
            return true;
        });

        // Zero calls before any allows() — this is the entire point of lazy
        $this->assertEquals(0, $callCount);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->authorizer->allows('counted');
        $this->assertEquals(1, $callCount); // called on first check

        $this->authorizer->allows('counted');
        $this->assertEquals(2, $callCount); // promoted to normal ability, runs each check

        $this->authorizer->allows('counted');
        $this->assertEquals(3, $callCount);
    }

    public function testLazyAbilityWithArguments(): void
    {
        $this->authorizer->lazy('lazy-update', function ($user, $post) {
            return (int) $user->id === (int) $post->owner_id;
        });

        $user = new class {
            public $id = 5;
        };
        $post = new class {
            public $owner_id = 5;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('lazy-update', $post));
    }

    public function testLazyAbilityReturnsSelf(): void
    {
        $result = $this->authorizer->lazy('test', fn() => true);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testHasAbilityReturnsTrueForLazyAbility(): void
    {
        $this->authorizer->lazy('pending-ability', fn() => true);
        $this->assertTrue($this->authorizer->hasAbility('pending-ability'));
    }

    public function testGetAllAbilitiesIncludesLazyAbilities(): void
    {
        $this->authorizer->lazy('lazy-one', fn() => true);
        $this->authorizer->lazy('lazy-two', fn() => true);

        $all = $this->authorizer->getAllAbilities();

        $this->assertContains('lazy-one', $all);
        $this->assertContains('lazy-two', $all);
    }

    public function testClearRemovesLazyAbilities(): void
    {
        $this->authorizer->lazy('to-be-cleared', fn() => true);
        $this->assertNotEmpty($this->authorizer->lazyAbilities());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->lazyAbilities());
    }

    public function testLazyAbilityWorksWithBeforeCallback(): void
    {
        $this->authorizer->lazy('lazy-gated', fn() => true);
        $this->authorizer->before(fn($user, $ability) => false);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('lazy-gated'));
    }

    public function testLazyAbilityWorksWithConditional(): void
    {
        $featureOn = true;

        $this->authorizer->condition('lazy-feature', function () use (&$featureOn) {
            return $featureOn;
        });
        $this->authorizer->lazy('lazy-feature', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('lazy-feature'));

        $featureOn = false;
        $this->assertFalse($this->authorizer->allows('lazy-feature'));
    }

    // =========================================================================
    // ABILITY VOTING
    // =========================================================================

    public function testMajorityStrategyGrantsWhenMoreGrantsThanDenies(): void
    {
        $this->authorizer->vote('publish-post', [
            fn($user) => true,   // grant
            fn($user) => true,   // grant
            fn($user) => false,  // deny
        ]);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('publish-post'));
    }

    public function testMajorityStrategyDeniesWhenMoreDeniesThanGrants(): void
    {
        $this->authorizer->vote('publish-post', [
            fn($user) => true,   // grant
            fn($user) => false,  // deny
            fn($user) => false,  // deny
        ]);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('publish-post'));
    }

    public function testMajorityStrategyDeniesOnTie(): void
    {
        $this->authorizer->vote('publish-post', [
            fn($user) => true,
            fn($user) => false,
        ]);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('publish-post'));
    }

    public function testMajorityStrategyIgnoresAbstentions(): void
    {
        $this->authorizer->vote('publish-post', [
            fn($user) => true,   // grant
            fn($user) => null,   // abstain
            fn($user) => null,   // abstain
        ]);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('publish-post'));
    }

    public function testMajorityStrategyDeniesWhenAllAbstain(): void
    {
        $this->authorizer->vote('publish-post', [
            fn($user) => null,
            fn($user) => null,
        ]);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // 0 grants, 0 denies — not > deny, so false
        $this->assertFalse($this->authorizer->allows('publish-post'));
    }

    public function testUnanimousStrategyGrantsWhenAllVotersGrant(): void
    {
        $this->authorizer->vote('deploy-production', [
            fn($user) => $user->hasRole,
            fn($user) => $user->hasMfa,
            fn($user) => $user->isActive,
        ], strategy: 'unanimous');

        $user = new class {
            public $hasRole  = true;
            public $hasMfa   = true;
            public $isActive = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('deploy-production'));
    }

    public function testUnanimousStrategyDeniesWhenOneDenies(): void
    {
        $this->authorizer->vote('deploy-production', [
            fn($user) => true,
            fn($user) => true,
            fn($user) => false, // single deny blocks everything
        ], strategy: 'unanimous');

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('deploy-production'));
    }

    public function testUnanimousStrategyIgnoresAbstentions(): void
    {
        $this->authorizer->vote('deploy-production', [
            fn($user) => true,
            fn($user) => null,  // abstain — ignored
            fn($user) => true,
        ], strategy: 'unanimous');

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('deploy-production'));
    }

    public function testUnanimousStrategyDeniesWhenAllAbstain(): void
    {
        $this->authorizer->vote('deploy-production', [
            fn($user) => null,
            fn($user) => null,
        ], strategy: 'unanimous');

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // grant === 0 — unanimous requires at least one grant
        $this->assertFalse($this->authorizer->allows('deploy-production'));
    }

    public function testVoteWithModelArguments(): void
    {
        $this->authorizer->vote('approve-post', [
            fn($user, $post) => $user->isReviewer,
            fn($user, $post) => $post->isSubmitted,
            fn($user, $post) => !$post->isBanned,
        ]);

        $user = new class {
            public $isReviewer = true;
        };
        $post = new class {
            public $isSubmitted = true;
            public $isBanned = false;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('approve-post', $post));
    }

    public function testVoteWithModelArgumentsMajorityDenies(): void
    {
        $this->authorizer->vote('approve-post', [
            fn($user, $post) => true,
            fn($user, $post) => $post->isSubmitted,
            fn($user, $post) => !$post->isBanned,
        ]);

        $user = new class {};
        $post = new class {
            public $isSubmitted = false;
            public $isBanned = true;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        // 1 grant, 2 denies
        $this->assertFalse($this->authorizer->allows('approve-post', $post));
    }

    public function testVoteThrowsOnInvalidStrategy(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->authorizer->vote('bad-ability', [fn() => true], strategy: 'invalid');
    }

    public function testVoteReturnsSelf(): void
    {
        $result = $this->authorizer->vote('test-vote', [fn() => true]);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testVotingAbilitiesAccessor(): void
    {
        $this->authorizer->vote('vote-a', [fn() => true]);
        $this->authorizer->vote('vote-b', [fn() => false], strategy: 'unanimous');

        $voting = $this->authorizer->votingAbilities();

        $this->assertArrayHasKey('vote-a', $voting);
        $this->assertArrayHasKey('vote-b', $voting);
        $this->assertEquals('majority',  $voting['vote-a']['strategy']);
        $this->assertEquals('unanimous', $voting['vote-b']['strategy']);
    }

    public function testHasAbilityReturnsTrueForVotingAbility(): void
    {
        $this->authorizer->vote('voted-ability', [fn() => true]);
        $this->assertTrue($this->authorizer->hasAbility('voted-ability'));
    }

    public function testGetAllAbilitiesIncludesVotingAbilities(): void
    {
        $this->authorizer->vote('vote-one', [fn() => true]);
        $this->authorizer->vote('vote-two', [fn() => false]);

        $all = $this->authorizer->getAllAbilities();

        $this->assertContains('vote-one', $all);
        $this->assertContains('vote-two', $all);
    }

    public function testClearRemovesVotingAbilities(): void
    {
        $this->authorizer->vote('to-clear', [fn() => true]);
        $this->assertNotEmpty($this->authorizer->votingAbilities());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->votingAbilities());
    }

    public function testBeforeCallbackOverridesVote(): void
    {
        // Vote would grant (all true)
        $this->authorizer->vote('voted', [fn() => true, fn() => true]);

        // Before denies everything
        $this->authorizer->before(fn($user, $ability) => false);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('voted'));
    }

    public function testAfterCallbackFiresForVotingAbility(): void
    {
        $afterCalled    = false;
        $capturedResult = null;

        $this->authorizer->vote('audited-vote', [fn() => true, fn() => true]);
        $this->authorizer->after(function ($user, $ability, $result) use (&$afterCalled, &$capturedResult) {
            $afterCalled    = true;
            $capturedResult = $result;
        });

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);
        $this->authorizer->allows('audited-vote');

        $this->assertTrue($afterCalled);
        $this->assertTrue($capturedResult);
    }

    public function testVotingWithSingleVoterMajority(): void
    {
        $this->authorizer->vote('solo-grant', [fn() => true]);
        $this->authorizer->vote('solo-deny',  [fn() => false]);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('solo-grant'));
        $this->assertFalse($this->authorizer->allows('solo-deny'));
    }

    // =========================================================================
    // COMBINED SCENARIOS
    // =========================================================================

    public function testRoleAndLazyAbilityIndependentlyEvaluated(): void
    {
        $lazyCalled = false;

        $this->authorizer->roles(['editor' => ['post.create']]);
        $this->authorizer->lazy('compliance-check', function () use (&$lazyCalled) {
            $lazyCalled = true;
            return true;
        });

        $editor = new class {
            public $role = 'editor';
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertFalse($lazyCalled); // lazy was never checked

        $this->assertTrue($this->authorizer->allows('compliance-check'));
        $this->assertTrue($lazyCalled);
    }

    public function testVotingAndRoleWorkTogether(): void
    {
        // Vote requires review + not banned
        $this->authorizer->vote('approve-post', [
            fn($user, $post) => $user->isReviewer,
            fn($user, $post) => !$post->isBanned,
        ], strategy: 'unanimous');

        // Role grants simple abilities
        $this->authorizer->roles(['reviewer' => ['view-queue']]);

        $user = new class {
            public $role = 'reviewer';
            public $isReviewer = true;
        };
        $post = new class {
            public $isBanned = false;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('approve-post', $post));
        $this->assertTrue($this->authorizer->allows('view-queue'));
    }

    public function testAllThreeFeaturesInSingleRequest(): void
    {
        $lazyCalled = false;

        // Role covers simple content abilities
        $this->authorizer->roles(['editor' => ['post.create', 'post.edit']]);

        // Lazy covers an expensive external check
        $this->authorizer->lazy('compliance-check', function ($user) use (&$lazyCalled) {
            $lazyCalled = true;
            return $user->isCompliant;
        });

        // Vote controls a sensitive multi-factor action
        $this->authorizer->vote('publish-to-homepage', [
            fn($user)       => $user->isEditor,
            fn($user, $post) => $post->isApproved,
        ], strategy: 'unanimous');

        $user = new class {
            public $role        = 'editor';
            public $isCompliant = true;
            public $isEditor    = true;
        };
        $post = new class {
            public $isApproved = true;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        // Role check — no lazy call
        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertFalse($lazyCalled);

        // Lazy check — now evaluated
        $this->assertTrue($this->authorizer->allows('compliance-check'));
        $this->assertTrue($lazyCalled);

        // Vote check
        $this->assertTrue($this->authorizer->allows('publish-to-homepage', $post));
    }
}
