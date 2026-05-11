# svc-facs-auth

This is a facility that handles user authentication. It extends `bfx-facs-base` to provide authentication management with support for generating and validating tokens, managing users, and handling permissions. It uses SQLite for user and token storage and an LRU for caching.

## Configuration

```javascript
{
  "a0": {
    "superAdmin": "superadmin@localhost",       // Required. Superadmin email address.
    "superAdminPassword": "<strong-password>",   // Required unless allowPasswordlessSuperAdmin is true.
                                                  // Seeded into the id=1 row on first start.
    "allowPasswordlessSuperAdmin": false,        // Opt-out for deployments that register a
                                                  // non-password auth handler before any login.
                                                  // Defaults to false; setting it to true logs no
                                                  // warning so be deliberate.
    "ttl": 300,                                  // Default token TTL in seconds (min 5, max 86400).
    "saltRounds": 10,                            // bcrypt cost factor for password hashing.
    "jwtSecret": "<hs256-shared-secret>",         // OPTIONAL. When set, tokens are HS256 JWTs and
                                                  // auth_tokens is unused. Without it the facility
                                                  // runs in legacy DB-backed mode.
    "jwtIssuer": "my-app",                        // OPTIONAL. When set, `iss` is added on sign and
                                                  // required on verify.
    "trustProxy": false,                          // false (default): bind to req.socket.remoteAddress
                                                  // only. true: trust framework-resolved req.ip
                                                  // (consumers must configure their HTTP framework's
                                                  // trust-proxy chain explicitly).
    "rolesCacheTtl": 30,                         // OPTIONAL (seconds). DB-sourced role cache TTL
                                                  // used by getTokenPerms / tokenHasPerms.
    "requireCurrentPassword": true,              // OPTIONAL. When true (default), updateUser requires
                                                  // currentPassword for self-updates if the user has
                                                  // a password set.
    "passwordPolicy": {                          // OPTIONAL. Enforced in createUser / updateUser
      "minLength": 8,                            //   when a password is being set.
      "requireUpper": false,
      "requireLower": false,
      "requireDigit": false,
      "requireSymbol": false
    },
    "authRateLimit": {                           // OPTIONAL. Opt-in brute-force protection on
      "window": 60,                              //   _resolveAuth, keyed by (email, source ip).
      "maxAttempts": 5,
      "lockoutSec": 900
    },
    "mfaCsrfTtl": 300,                           // OPTIONAL. Lifetime of the csrf_token returned by
                                                  // mfaCallbackHandler, in seconds.
    "roles": {
      "admin": ["miner:rw", "container:rw", "user:rw"],
      "site_manager": ["miner:rw", "container:rw", "user:r"],
      "user": ["jobs:rw"]
    }
  }
}
```

### Migration notes (from 0.1.x)

- `getTokenPerms` and `tokenHasPerms` are now async. Add `await` at every call site. A token-claims-based `getTokenPermsSync` is available for callers that cannot go async.
- `updateUser` now requires `currentPassword` for self-updates when the user has a password set, and gates role mutation / cross-user updates behind `user:rw`. Pass `targetUserId` to update another user.
- `regenerateToken` requires `ips` (or `req`) and rejects when the supplied IPs do not match the original token's binding.
- `extractIps` no longer unions `x-forwarded-for`, `req.ip`, `req.ips` and `req.socket.remoteAddress`. Set `conf.trustProxy: true` to keep the old behaviour after configuring your framework's trust-proxy chain.
- `auth_tokens.token` was renamed to `auth_tokens.token_hash`. On first start the facility drops the old table; legacy-mode clients re-authenticate. JWT mode is unaffected.
- The bootstrapped super-admin is no longer created with `password: null` by default; set `conf.superAdminPassword` or opt out with `conf.allowPasswordlessSuperAdmin: true`.

## Documentation
### `auth.createUser(req)`
Creates a new user with specified roles and permissions.

**Parameters:**
- `req<object>`: Object with user creation details.
    - `email<string>`: Email address of the user.
    - `roles<string[]>`: Array of roles for the user.
    - `password<string>`: Password for the user.

```javascript
const result = await auth.createUser({
  email: 'user@example.com',
  roles: ['admin']
})
```

### `auth.updateUser(req)`
Updates a user. The caller can update their own record (self-update) or — with `user:rw` permission and an explicit `targetUserId` — another user's record.

**Parameters:**
- `req<object>`:
    - `token<string>`: Authentication token for the caller.
    - `targetUserId<number>` *(optional)*: User id to update. Defaults to the caller's own id.
    - `currentPassword<string>` *(required for self-updates when `user.password` is set)*: The caller's existing password. Cross-user updates do not need this — they rely on the `user:rw` permission gate.
    - `email<string>` *(optional)*: New email. Omitted fields preserve their prior value.
    - `name<string>` *(optional)*.
    - `roles<string[]>` *(optional)*: New role set. Must be a subset of `Object.keys(conf.roles)`; `'*'` is rejected. Role mutation (a change from the user's current roles) requires `user:rw` on the caller, even for self-updates.
    - `password<string>` *(optional)*: New password (hashed). Must satisfy `conf.passwordPolicy`.

```javascript
// Self profile update
await auth.updateUser({
  token: '<caller-token>',
  currentPassword: '<existing-password>',
  email: 'new@example.com'
})

// Admin updating another user
await auth.updateUser({
  token: '<admin-token>',
  targetUserId: 42,
  roles: ['site_manager']
})
```

### `auth.compareUser(req)`
Compares fields against the caller's own user row by default. Pass `targetUserId` to compare another user — the caller must hold `user:r`.

**Parameters:**
- `req<object>`:
    - `token<string>`: Authentication token for the caller.
    - `targetUserId<number>` *(optional)*: User id to compare against. Defaults to the caller's own id.
    - `email<string>` *(optional)*.
    - `name<string>` *(optional)*.
    - `roles<string[]>` *(optional)*.
    - `password<string>` *(optional)*.

```javascript
const isMatching = await auth.compareUser({
  token: 'user-token',
  email: 'test@example.com',
  roles: ['user'],
  password: 'securepassword'
})
console.log(isMatching) // true or false
```

### `auth.genToken(req)`
Generates a new authentication token based on the provided parameters. It validates the input, allocates resources, and stores the token data.

**Parameters:**
- `req<object>`: Object containing token generation details.
    - `ips<string[]>`: List of IP addresses associated with the token.
    - `userId<number>`: User ID for whom the token is generated.
    - `ttl<number>`: Time-to-live for the token in seconds (default: 300).
    - `metadata<object>`: Optional metadata associated with the token.
    - `pfx<string>`: Prefix for the token (default: 'pub').
    - `scope<string>`: Scope for the token (default: 'api').
    - `roles<string[]>`: Array of roles for the token.

```javascript
const token = await auth.genToken({
  ips: ['192.168.1.1'],
  userId: 1,
  ttl: 3600,
  metadata: { key: 'value' },
  pfx: 'pub',
  scope: 'api',
  roles: ['admin']
})
```

### `auth.regenerateToken(req)`
Regenerates an existing authentication token. The caller must present the new request's IP so the facility can verify it intersects with the binding of the old token.

**Parameters:**
- `req<object>`:
    - `oldToken<string>`: Existing token to be regenerated.
    - `ips<string[]>` *(required unless `req` is provided)*: Source IPs for the regenerate request. Must intersect with `oldToken`'s binding.
    - `req<object>` *(alternative to `ips`)*: An incoming HTTP request; the facility runs `extractIps(req, conf.trustProxy)` to derive the binding.
    - `pfx<string>` *(optional, default `'pub'`)*.
    - `scope<string>` *(optional, default `'api'`)*.
    - `roles<string[]>`: Subset of the old token's roles.

Throws:
- `ERR_OLD_TOKEN_INVALID` — old token cannot be verified.
- `ERR_IPS_REQUIRED` — neither `ips` nor `req` supplied.
- `ERR_IP_MISMATCH` — supplied IPs do not intersect with the binding.
- `ERR_ROLES_INVALID` — requested roles are not a subset of the old token's.

```javascript
const newToken = await auth.regenerateToken({
  oldToken: 'existing-token',
  ips: ['192.168.1.1'],
  roles: ['admin']
})
```

### `auth.getTokenPerms(token)` *(async)*
Verifies the token and resolves its current permissions from the `users` table (LRU-cached per `conf.rolesCacheTtl`). A role change in the DB propagates to subsequent calls without needing to re-issue the token.

**Parameters:**
- `token<string>`: The token to get permissions for.

**Returns:** `Promise<{ superadmin: <boolean>, perms: <string[]> }>`.

```javascript
const perms = await auth.getTokenPerms('some-token')
console.log('Token permissions:', perms)
```

### `auth.getTokenPermsSync(token)`
Token-claims-based fallback for callers that cannot go async. Reads roles directly from the token (JWT claims in JWT mode, suffix in legacy mode). Faster, but reflects the state at issuance — **not suitable for authZ enforcement on sensitive operations.**

### `auth.resolveToken(token, ips)`
Validates a token and checks if it is associated with the given IP addresses.

**Parameters:**
- `token<string>`: The token to resolve.
- `ips<string[]>`: List of IP addresses to validate.

```javascript
const user = await auth.resolveToken('some-token', ['192.168.1.1'])
```
Note: User data (`user`) is coming from the `auth_token` table.

### `auth.tokenHasPerms(token, perm)` *(async)*
Checks whether the token's user has the required permission. Uses `getTokenPerms` under the hood, so it reflects the live `users.roles` (LRU-cached).

**Parameters:**
- `token<string>`: The token to check.
- `perm<string>`: Permission to check, e.g. `'miner:r'`.

**Returns:** `Promise<boolean>`.

```javascript
const hasPerms = await auth.tokenHasPerms('some-token', 'miner:r')
console.log('Token has required permissions:', hasPerms)
```

### `auth.cleanupTokens()`
Cleans up expired tokens from the database.

```javascript
await auth.cleanupTokens()
```

### `auth.addHandlers(handlers)`
Adds authentication handlers to the service.

**Parameters:**
- `handlers<object>`: Object containing authentication handlers, each key is a handler name and value is a handler function.

```javascript
auth.addHandlers({
  'handler-name': async (ctx, req) => {
    // Handler logic
  }
})
```

### `auth.authCallbackHandler(type, req)`
Handles authentication callbacks by resolving tokens and returning authentication results.

**Parameters:**
- `type<string>`: Type of authentication callback.
- `req<object>`: Request object containing callback details.

```javascript
const token = await auth.authCallbackHandler('callback-type', request)
```

### `auth.getUserById(id)`
Return the user with the given id

**Parameters:**
- `id<string>`: id of the user.

```javascript
const user = await auth.getUserById('3')
```

### `auth.getUserByEmail(email)`
Return the user with the given email

**Parameters:**
- `id<string>`: email of the user.

```javascript
const user = await auth.getUserByEmail('new@example.com')
```

### `auth.listUsers()`
Returns a list of users present

```javascript
const users = await auth.listUsers('callback-type', request)
```

### `auth.deleteUser(id)`
Deletes the user with the provided id.

**Parameters:**
- `id<string>`: id of the user.

```javascript
await auth.deleteUser('23')
```

### `auth.revokeToken(token)` *(async)*
Revokes a single session. Idempotent — already-revoked or malformed tokens return `false`. JWT mode removes the jti from the LRU; legacy mode deletes the row from `auth_tokens` and evicts the LRU.

```javascript
const ok = await auth.revokeToken('some-token') // true on first call, false thereafter
```

### `auth.revokeAllForUser(userId)` *(async)*
Force-revokes every active session for a user. Use this as the back end for an admin "sign out all devices" action.

```javascript
await auth.revokeAllForUser(42)
```

### `auth.mfaHandler(type, req)`
Handles multi-factor authentication (MFA) by invoking the specified MFA handler.

**Parameters:**
- `type<string>`: The type/name of the MFA handler to invoke (e.g., `'totp'`).
- `req<object>`: The request object containing necessary authentication details.

**Throws:**
- `ERR_HANDLER_INVALID` if the specified handler does not exist or is not a function.

```javascript
const result = await auth.mfaHandler('totp', { totp: '123456' , ...<Object> })
```

### `auth.mfaCallbackHandler(type, req, getUserMfaMethods)`
First step of the MFA-protected login flow. If the user has MFA enabled, the bearer token is stashed server-side under a single-use `csrf_token` keyed in the LRU (under `mfa-csrf:<uuid>`) and the caller receives a challenge. If MFA is not required, the bearer token is returned immediately.

**Parameters:**
- `type<string>`: The type of authentication callback.
- `req<object>`: The request object.
- `getUserMfaMethods<function>`: `async (caller, token, req) => string[]` — returns the list of enabled MFA methods for the user.

**Returns:**
- If MFA is required: `{ csrf_token, mfa_required: true, mfa_methods }`.
- If MFA is not required: `{ token }`.

**Throws:**
- `ERR_MFA_METHOD_HANDLER_INVALID` if `getUserMfaMethods` is not a function.

### `auth.addMfaCompleteHandlers(handlers)`
Register per-factor verifiers for the second step of the MFA flow.

```javascript
auth.addMfaCompleteHandlers({
  totp:    async (ctx, csrfToken, proof) => verifyTotp(ctx.userTotp(csrfToken), proof),
  passkey: async (ctx, csrfToken, proof) => verifyPasskey(proof)
})
```

### `auth.mfaCompleteHandler(csrfToken, factor, proof)` *(async)*
Second step of the MFA-protected login flow. Looks up the `csrf_token` issued by `mfaCallbackHandler`, consumes it (single-use, even on failure), enforces `conf.mfaCsrfTtl` (default 300s), verifies the factor's `proof` via the registered handler, and returns the stashed bearer token on success.

**Throws:**
- `ERR_MFA_CSRF_INVALID` — missing, expired, or already-consumed `csrf_token`.
- `ERR_HANDLER_INVALID` — no handler registered for `factor`.
- `ERR_MFA_FACTOR_INVALID` — factor verifier returned falsy.

```javascript
const { token } = await auth.mfaCompleteHandler(csrfToken, 'totp', '123456')
```
