// Register policies and abilities (typically in a service provider)
Guard::define('edit-settings', function ($user) {
    return $user->isAdmin();
});

Guard::policy(Post::class, PostPolicy::class);

// In your controllers or other classes
if (Guard::allows('edit-settings')) {
    // User can edit settings
}

if (Guard::denies('update-post', $post)) {
    abort(403);
}

// Using the new any/all methods
if (Guard::any(['edit-post', 'admin-post'], [$post])) {
    // User can either edit post or is an admin
}

##  Temporary Abilities (One-Time Checks)
```php
// Define a temporary ability that only works once
Guard::temporary('one-time-access', function($user) {
    return true; // Grant access just this once
});

// First check will work
if (Guard::allows('one-time-access')) {
    // This will execute
}

// Second check will fail
if (Guard::denies('one-time-access')) {
    // This will now execute
}
```

## Ability Inheritance (Hierarchy)
```php
// Set up ability hierarchy
Guard::inherit('admin', ['manage-users', 'manage-settings']);

// Define child abilities
Guard::define('manage-users', fn($user) => $user->isAdmin());
Guard::define('manage-settings', fn($user) => $user->isAdmin());

// Check parent ability
if (Guard::allows('admin')) {
    // This will pass if either manage-users or manage-settings is allowed
}

// Get all child abilities
$children = Guard::getChildren('admin');
// Returns ['manage-users', 'manage-settings']
```

## Ability Grouping
```php
// Create a group of related abilities
Guard::group('content-management', [
    'create-post',
    'edit-post',
    'delete-post'
]);

// Check if ability belongs to group
if (Guard::inGroup('content-management', 'edit-post')) {
    // Special handling for content management abilities
}
```

## Global Before/After Callbacks
```php
// Global before callback - runs before every ability check
Guard::before(function($user, $ability) {
    if ($user->isSuperAdmin()) {
        return true; // Super admins bypass all checks
    }
    return null; // Continue with normal checks
});

// Global after callback - runs after every ability check
Guard::after(function($user, $ability, $result) {
    logAccessAttempt($user, $ability, $result);
});
```

##  Bulk Ability Checks with Groups
```php
// Check multiple abilities at once
if (Guard::all(['create-post', 'edit-post', 'delete-post'])) {
    // User has all content management abilities
}

if (Guard::any(['edit-settings', 'admin-access'])) {
    // User has at least one of these abilities
}
```

## Dynamic Ability Registration
```php
// Register abilities dynamically based on configuration
$dynamicAbilities = config('custom.abilities');
// return [
//     'abilities' => [
//         // Simple boolean check
//         'access-dashboard' => fn($user) => $user->hasRole('member'),

//         // Resource-based check
//         'edit-post' => function($user, $post) {
//             return $user->id === $post->author_id || $user->isAdmin();
//         },

//         // Multiple condition check
//         'manage-settings' => function($user) {
//             return $user->isAdmin() && 
//                    $user->isActive() && 
//                    !$user->isSuspended();
//         }
//     ]
// ];

foreach ($dynamicAbilities as $ability => $callback) {
    Guard::define($ability, $callback);
}

// Check dynamically registered ability
if (Guard::allows('dynamic-ability')) {
    // Handle dynamic ability
}
```

##  Enhanced Policy System with Context
```php
// Policy class with context-aware methods
class DocumentPolicy
{
    public function view($user, $document, $context = [])
    {
        // Check if document is public
        if ($document->is_public) return true;

        // Check for special access in context
        if (isset($context['special_access']) && $context['special_access']) {
            return true;
        }

        return $user->id === $document->user_id;
    }
}

// Usage with context
$context = ['special_access' => true];
Guard::allows('view', $document, $context);
```