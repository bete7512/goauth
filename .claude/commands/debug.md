Structured debugging for goauth issues.

## Arguments
$ARGUMENTS - Optional: description of the problem (e.g., "session module init fails", "CSRF token not validated")

## Instructions

### Step 1: Gather Context
If no argument given, ask:
- Which module is affected?
- What's the symptom (error message, unexpected behavior, panic)?
- What's the expected behavior?

### Step 2: Check Common Failure Points

**Module initialization issues:**
- Is the module registered via `auth.Use()` before `auth.Initialize()`?
- Are its dependencies registered first? (check `Dependencies()` return)
- Is Session + Stateless both registered? (mutual exclusion - will panic)
- Is storage properly configured for this module? (e.g., `Storage.Session()` returns nil if not set up)

**Storage issues:**
- Does the storage implementation satisfy the required interface?
- Are migrations run? (`AutoMigrate: true` or manual `storage.Migrate(ctx)`)
- For custom storage: does it implement `WithTransaction()`?

**Event issues:**
- Is the event handler registered in `RegisterHooks()` or via `auth.On()`?
- Is the async backend running? Check if `EventBus.Close()` was called prematurely
- Check dead-letter queue for failed events

**Route issues:**
- Does the route name follow dot notation? (`"module.action"`)
- Is middleware priority correct? (higher number = runs first)
- Is `auth.Routes()` called after `Initialize()`?

### Step 3: Investigate
- Read the relevant module's `module.go`, `handlers/`, and `services/`
- Read any related test files for expected behavior
- Check if there are related events that should fire
- Trace the dependency chain from config → storage → module → handler

### Step 4: Report
- Root cause with file:line reference
- Suggested fix (code change or configuration change)
- How to verify the fix (which test to run or what to check)
