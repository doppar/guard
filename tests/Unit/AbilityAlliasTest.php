<?php

namespace Doppar\Authorizer\Tests\Unit;

use Doppar\Authorizer\Authorizer;
use PHPUnit\Framework\TestCase;

/**
 * Tests for three new Guard features:
 *  - Ability Aliases
 *  - Wildcard Abilities
 *  - Conditional Abilities
 */
class AbilityAlliasTest extends TestCase
{
    private Authorizer $authorizer;

    protected function setUp(): void
    {
        $this->authorizer = new Authorizer();
    }

    // =====================================================
    // ABILITY ALIASES
    // =====================================================

    public function testAliasResolvesToTargetAbility(): void
    {
        $this->authorizer->define('update-post', fn($user) => $user->isEditor);
        $this->authorizer->alias('edit', 'update-post');

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('edit'));
    }

    public function testAliasDeniesWhenTargetDenies(): void
    {
        $this->authorizer->define('update-post', fn($user) => $user->isEditor);
        $this->authorizer->alias('edit', 'update-post');

        $viewer = new class {
            public $isEditor = false;
        };
        $this->authorizer->resolveUserUsing(fn() => $viewer);

        $this->assertFalse($this->authorizer->allows('edit'));
        $this->assertTrue($this->authorizer->denies('edit'));
    }

    public function testAliasPassesArgumentsToTargetAbility(): void
    {
        $this->authorizer->define('update-post', function ($user, $post) {
            return (int) $user->id === (int) $post->user_id;
        });
        $this->authorizer->alias('edit', 'update-post');

        $user = new class {
            public $id = 1;
        };
        $post = new class {
            public $user_id = 1;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('edit', $post));
    }

    public function testAliasChaining(): void
    {
        // 'modify' -> 'edit' -> 'update-post'
        $this->authorizer->define('update-post', fn($user) => $user->isEditor);
        $this->authorizer->alias('edit',   'update-post');
        $this->authorizer->alias('modify', 'edit');

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('modify'));
    }

    public function testCircularAliasDoesNotInfiniteLoop(): void
    {
        $this->authorizer->alias('a', 'b');
        $this->authorizer->alias('b', 'a');

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // Should return false without hanging
        $this->assertFalse($this->authorizer->allows('a'));
    }

    public function testAliasToUndefinedAbilityReturnsFalse(): void
    {
        $this->authorizer->alias('shortcut', 'nonexistent-ability');

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('shortcut'));
    }

    public function testAliasReturnsSelf(): void
    {
        $result = $this->authorizer->alias('a', 'b');
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testAliasesAccessor(): void
    {
        $this->authorizer->alias('edit',   'update-post');
        $this->authorizer->alias('remove', 'delete-post');

        $aliases = $this->authorizer->aliases();

        $this->assertArrayHasKey('edit',   $aliases);
        $this->assertArrayHasKey('remove', $aliases);
        $this->assertEquals('update-post', $aliases['edit']);
        $this->assertEquals('delete-post', $aliases['remove']);
    }

    public function testResolveAliasReturnsOriginalForNonAlias(): void
    {
        $resolved = $this->authorizer->resolveAlias('update-post');
        $this->assertEquals('update-post', $resolved);
    }

    public function testResolveAliasFollowsChain(): void
    {
        $this->authorizer->alias('a', 'b');
        $this->authorizer->alias('b', 'c');
        $this->authorizer->alias('c', 'real-ability');

        $this->assertEquals('real-ability', $this->authorizer->resolveAlias('a'));
    }

    public function testAliasWorksWithPolicyAuthorization(): void
    {
        $policy = new class {
            public function update($user, $model)
            {
                return $user->id === $model->owner_id;
            }
        };

        $model = new class {
            public $owner_id = 7;
        };
        $user  = new class {
            public $id = 7;
        };

        $this->authorizer->authorize(get_class($model), get_class($policy));
        $this->authorizer->alias('save', 'update');

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('save', $model));
    }

    public function testAliasWorksInsideAnyCheck(): void
    {
        $this->authorizer->define('update-post', fn($user) => $user->isEditor);
        $this->authorizer->alias('edit', 'update-post');

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->any(['edit', 'nonexistent']));
    }

    public function testHasAbilityReturnsTrueForAlias(): void
    {
        $this->authorizer->define('update-post', fn() => true);
        $this->authorizer->alias('edit', 'update-post');

        $this->assertTrue($this->authorizer->hasAbility('edit'));
    }

    public function testClearRemovesAliases(): void
    {
        $this->authorizer->alias('edit', 'update-post');
        $this->assertNotEmpty($this->authorizer->aliases());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->aliases());
    }

    // =====================================================
    // WILDCARD ABILITIES
    // =====================================================

    public function testWildcardPrefixPatternMatchesAllSuffixes(): void
    {
        $this->authorizer->wildcard('post.*', fn($user) => $user->isEditor);

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertTrue($this->authorizer->allows('post.edit'));
        $this->assertTrue($this->authorizer->allows('post.delete'));
        $this->assertTrue($this->authorizer->allows('post.publish'));
    }

    public function testWildcardPrefixPatternDoesNotMatchOtherPrefixes(): void
    {
        $this->authorizer->wildcard('post.*', fn($user) => $user->isEditor);

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertFalse($this->authorizer->allows('comment.create'));
        $this->assertFalse($this->authorizer->allows('user.delete'));
    }

    public function testWildcardSuffixPatternMatchesAllPrefixes(): void
    {
        $this->authorizer->wildcard('*.create', fn($user) => $user->canCreate);

        $user = new class {
            public $canCreate = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertTrue($this->authorizer->allows('comment.create'));
        $this->assertTrue($this->authorizer->allows('tag.create'));
    }

    public function testWildcardSuffixPatternDoesNotMatchOtherSuffixes(): void
    {
        $this->authorizer->wildcard('*.create', fn($user) => $user->canCreate);

        $user = new class {
            public $canCreate = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('post.delete'));
        $this->assertFalse($this->authorizer->allows('post.edit'));
    }

    public function testGlobalWildcardMatchesEverything(): void
    {
        $this->authorizer->wildcard('*', fn($user) => $user->isAdmin);

        $admin = new class {
            public $isAdmin = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $admin);

        $this->assertTrue($this->authorizer->allows('anything'));
        $this->assertTrue($this->authorizer->allows('post.create'));
        $this->assertTrue($this->authorizer->allows('some.deeply.nested.ability'));
    }

    public function testWildcardDeniesWhenCallbackReturnsFalse(): void
    {
        $this->authorizer->wildcard('post.*', fn($user) => false);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    public function testExactAbilityTakesPrecedenceOverWildcard(): void
    {
        // Exact ability explicitly denies
        $this->authorizer->define('post.delete', fn($user) => false);
        // Wildcard would allow
        $this->authorizer->wildcard('post.*', fn($user) => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // Exact match is checked before wildcard
        $this->assertFalse($this->authorizer->allows('post.delete'));
        // Other abilities fall through to wildcard
        $this->assertTrue($this->authorizer->allows('post.create'));
    }

    public function testWildcardWithMultipleSegments(): void
    {
        $this->authorizer->wildcard('admin.*.*', fn($user) => $user->isAdmin);

        $admin = new class {
            public $isAdmin = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $admin);

        $this->assertTrue($this->authorizer->allows('admin.users.delete'));
        $this->assertTrue($this->authorizer->allows('admin.settings.edit'));
        $this->assertFalse($this->authorizer->allows('admin.single'));  // only one segment after admin
    }

    public function testWildcardPassesArgumentsToCallback(): void
    {
        $this->authorizer->wildcard('post.*', function ($user, $post) {
            return (int) $user->id === (int) $post->owner_id;
        });

        $user    = new class {
            public $id = 3;
        };
        $post    = new class {
            public $owner_id = 3;
        };
        $notPost = new class {
            public $owner_id = 99;
        };

        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('post.edit', $post));
        $this->assertFalse($this->authorizer->allows('post.edit', $notPost));
    }

    public function testMultipleWildcardsFirstMatchWins(): void
    {
        $this->authorizer->wildcard('post.*', fn($user) => false); // registered first — denies
        $this->authorizer->wildcard('*.edit', fn($user) => true);  // registered second — allows

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // 'post.edit' matches 'post.*' first — it should deny
        $this->assertFalse($this->authorizer->allows('post.edit'));
    }

    public function testWildcardReturnsSelf(): void
    {
        $result = $this->authorizer->wildcard('post.*', fn() => true);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testMatchWildcardReturnsPatternKey(): void
    {
        $this->authorizer->wildcard('post.*', fn() => true);

        $this->assertEquals('post.*', $this->authorizer->matchWildcard('post.create'));
        $this->assertEquals('post.*', $this->authorizer->matchWildcard('post.delete'));
        $this->assertNull($this->authorizer->matchWildcard('comment.create'));
    }

    public function testMatchWildcardReturnsNullForNoMatch(): void
    {
        $this->authorizer->wildcard('post.*', fn() => true);

        $this->assertNull($this->authorizer->matchWildcard('user.update'));
    }

    public function testHasAbilityReturnsTrueForWildcardMatch(): void
    {
        $this->authorizer->wildcard('post.*', fn() => true);

        $this->assertTrue($this->authorizer->hasAbility('post.create'));
        $this->assertTrue($this->authorizer->hasAbility('post.delete'));
        $this->assertFalse($this->authorizer->hasAbility('comment.create'));
    }

    public function testWildcardWorksWithAliases(): void
    {
        $this->authorizer->wildcard('post.*', fn($user) => $user->isEditor);
        $this->authorizer->alias('write-post', 'post.create');

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        // alias resolves to 'post.create', wildcard matches 'post.*'
        $this->assertTrue($this->authorizer->allows('write-post'));
    }

    public function testWildcardWorksWithBeforeCallback(): void
    {
        $this->authorizer->wildcard('post.*', fn($user) => true);

        $this->authorizer->before(fn($user, $ability) => false); // deny everything

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('post.create'));
    }

    // =====================================================
    // CONDITIONAL ABILITIES
    // =====================================================

    public function testConditionalAbilityAllowsWhenConditionPasses(): void
    {
        $this->authorizer->condition('weekend-export', fn() => true); // condition passes
        $this->authorizer->define('weekend-export', fn($user) => $user->isPremium);

        $premium = new class {
            public $isPremium = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $premium);

        $this->assertTrue($this->authorizer->allows('weekend-export'));
    }

    public function testConditionalAbilityDeniesWhenConditionFails(): void
    {
        $this->authorizer->condition('weekend-export', fn() => false); // condition fails
        $this->authorizer->define('weekend-export', fn($user) => $user->isPremium);

        $premium = new class {
            public $isPremium = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $premium);

        // Even though user is premium, condition blocks access
        $this->assertFalse($this->authorizer->allows('weekend-export'));
    }

    public function testConditionalAbilityDeniesEvenIfUserWouldBeAllowed(): void
    {
        $featureEnabled = false;

        $this->authorizer->condition('beta-feature', function () use (&$featureEnabled) {
            return $featureEnabled;
        });
        $this->authorizer->define('beta-feature', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('beta-feature'));

        // Enable the feature flag
        $featureEnabled = true;

        $this->assertTrue($this->authorizer->allows('beta-feature'));
    }

    public function testConditionalAbilityWithTimeBoundLogic(): void
    {
        $now = new \DateTimeImmutable();

        // Simulate "only during business hours" (we control the clock via closure)
        $isBusinessHours = true;

        $this->authorizer->condition('schedule-meeting', function () use (&$isBusinessHours) {
            return $isBusinessHours;
        });
        $this->authorizer->define('schedule-meeting', fn($user) => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('schedule-meeting'));

        $isBusinessHours = false;
        $this->assertFalse($this->authorizer->allows('schedule-meeting'));
    }

    public function testConditionalAbilityWithoutAbilityDefinedReturnsFalse(): void
    {
        // Condition passes but no ability defined
        $this->authorizer->condition('ghost-ability', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('ghost-ability'));
    }

    public function testAbilityWithoutConditionIsUnrestricted(): void
    {
        $this->authorizer->define('normal-ability', fn($user) => true);
        // No condition registered — should pass normally

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('normal-ability'));
    }

    public function testMultipleConditionsAreIndependent(): void
    {
        $this->authorizer->condition('feature-a', fn() => true);
        $this->authorizer->condition('feature-b', fn() => false);

        $this->authorizer->define('feature-a', fn() => true);
        $this->authorizer->define('feature-b', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('feature-a'));
        $this->assertFalse($this->authorizer->allows('feature-b'));
    }

    public function testConditionalAbilityReturnsSelf(): void
    {
        $result = $this->authorizer->condition('my-ability', fn() => true);
        $this->assertInstanceOf(Authorizer::class, $result);
    }

    public function testConditionsAccessor(): void
    {
        $condA = fn() => true;
        $condB = fn() => false;

        $this->authorizer->condition('ability-a', $condA);
        $this->authorizer->condition('ability-b', $condB);

        $conditions = $this->authorizer->conditions();

        $this->assertArrayHasKey('ability-a', $conditions);
        $this->assertArrayHasKey('ability-b', $conditions);
    }

    public function testConditionalAbilityFiresAfterCallbackOnDeny(): void
    {
        $afterCalled    = false;
        $capturedResult = null;

        $this->authorizer->condition('locked-ability', fn() => false);
        $this->authorizer->define('locked-ability', fn() => true);

        $this->authorizer->after(function ($user, $ability, $result) use (&$afterCalled, &$capturedResult) {
            $afterCalled    = true;
            $capturedResult = $result;
        });

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('locked-ability'));
        $this->assertTrue($afterCalled);
        $this->assertFalse($capturedResult);
    }

    public function testConditionalAbilityBeforeCallbackCanStillOverride(): void
    {
        // Condition blocks the ability
        $this->authorizer->condition('restricted', fn() => false);
        $this->authorizer->define('restricted', fn() => true);

        // But a before callback (e.g. super-admin) can still override
        $this->authorizer->before(fn($user, $ability) => $user->isSuperAdmin ? true : null);

        $superAdmin = new class {
            public $isSuperAdmin = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $superAdmin);

        // before runs before the condition check, so super-admin bypasses it
        $this->assertTrue($this->authorizer->allows('restricted'));
    }

    public function testConditionalAbilityWorksWithAlias(): void
    {
        $this->authorizer->condition('export-data', fn() => true);
        $this->authorizer->define('export-data', fn($user) => $user->canExport);
        $this->authorizer->alias('export', 'export-data');

        $user = new class {
            public $canExport = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertTrue($this->authorizer->allows('export'));
    }

    public function testConditionalAbilityBlockedViaAliasWhenConditionFails(): void
    {
        $this->authorizer->condition('export-data', fn() => false);
        $this->authorizer->define('export-data', fn($user) => $user->canExport);
        $this->authorizer->alias('export', 'export-data');

        $user = new class {
            public $canExport = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $user);

        $this->assertFalse($this->authorizer->allows('export'));
    }

    public function testClearRemovesConditions(): void
    {
        $this->authorizer->condition('my-ability', fn() => true);
        $this->assertNotEmpty($this->authorizer->conditions());

        $this->authorizer->clear();

        $this->assertEmpty($this->authorizer->conditions());
    }

    // =====================================================
    // COMBINED SCENARIOS
    // =====================================================

    public function testAllThreeFeaturesWorkTogether(): void
    {
        // Wildcard pattern covers all post abilities
        $this->authorizer->wildcard('post.*', fn($user) => $user->isEditor);

        // Alias 'write' -> 'post.create'
        $this->authorizer->alias('write', 'post.create');

        // Condition: feature is enabled
        $featureOn = true;
        $this->authorizer->condition('post.create', function () use (&$featureOn) {
            return $featureOn;
        });

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        // 'write' -> resolves alias -> 'post.create'
        // condition passes -> wildcard 'post.*' -> user is editor -> true
        $this->assertTrue($this->authorizer->allows('write'));

        // Turn off feature flag
        $featureOn = false;
        $this->assertFalse($this->authorizer->allows('write'));
    }

    public function testWildcardAndAliasWithInheritance(): void
    {
        $this->authorizer->wildcard('content.*', fn($user) => $user->isEditor);
        $this->authorizer->alias('write', 'content.create');
        $this->authorizer->inherit('editor-access', ['content.create', 'content.edit']);

        $editor = new class {
            public $isEditor = true;
        };
        $this->authorizer->resolveUserUsing(fn() => $editor);

        $this->assertTrue($this->authorizer->allows('write'));          // alias -> wildcard
        $this->assertTrue($this->authorizer->allows('editor-access')); // hierarchy -> wildcard
    }

    public function testConditionalWithAnyBulkCheck(): void
    {
        $this->authorizer->condition('premium-export', fn() => false); // blocked
        $this->authorizer->define('premium-export', fn() => true);
        $this->authorizer->define('basic-export', fn() => true);

        $user = new class {};
        $this->authorizer->resolveUserUsing(fn() => $user);

        // premium-export blocked by condition, but basic-export passes
        $this->assertTrue($this->authorizer->any(['premium-export', 'basic-export']));

        // all() fails because premium-export is blocked
        $this->assertFalse($this->authorizer->all(['premium-export', 'basic-export']));
    }
}
