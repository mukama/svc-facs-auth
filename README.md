# svc-facs-auth
 
This is a facility to handle user authentivcaton that extends from `bfx-facs-base` to provide authentication management with support for generating and validating tokens, managing users, and handling permissions. It uses SQLite for storing user and token information and LRU for caching.

## Configuration

This facility requires a config file in the following structure:

```javascript
{
  "a0": {
    "superAdmin": "superadmin@localhost", // Superadmin email address
    "ttl": 300, // Default token time-to-live in seconds
    "trustProxy": false, // false: bind to req.socket.remoteAddress only. true: trust req.ip
    "saltRounds": 10, // Number of salt rounds for password hashing
    "roles": { // Roles with associated permissions
      "admin": [
        "miner:rw",
        "container:rw",
        "user:rw"
      ],
      "site_manager": [
        "miner:rw",
        "container:rw",
        "user:r"
      ],
      "user": ["jobs:rw"]
    }
  }
}
```

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
Updates an existing user. Self-updates require `currentPassword` when the user has a password set; cross-user updates require `user:rw` on the caller and an explicit `targetUserId`.

**Parameters:**
- `req<object>`: Object with user update details.
    - `token<string>`: Authentication token for the user.
    - `targetUserId<number> (optional)`: User id to update. Defaults to caller's own id.
    - `currentPassword<string> (required for self-updates with a password set)`.
    - `email<string>`: Email address of the user.
    - `roles<string[]>`: Array of roles for the user.
    - `password<string>`: New password for the user.

```javascript
const result = await auth.updateUser({
  token: 'some-token',
  email: 'new@example.com',
  roles: ['admin']
})
```

### `auth.compareUser(req)`
Compares user details (email, password, roles) with the stored user information.

**Parameters:**
- `req<object>`: Object containing user details for comparison.
    - `token<string>`: Authentication token for the user.
    - `targetUserId<number> (optional)`: Compare another user; caller needs `user:r`.
    - `email<string> (optional)`: Email address to compare.
    - `roles<string[]> (optional)`: Array of roles to compare.
    - `password<string> (optional)`: Password to compare.

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
Regenerates an existing authentication token. It validates the old token, checks permissions, and creates a new token.

**Parameters:**
- `req<object>`: Object with token regeneration details.
    - `oldToken<string>`: Existing token to be regenerated.
    - `ips<string[]>`: Source IPs for the regenerate request (required unless `req` is provided). Must intersect with the old token's binding.
    - `req<object> (optional)`: Incoming HTTP request; IP derived via `extractIps(req, conf.trustProxy)`.
    - `ttl<number>`: Time-to-live for the new token in seconds (default: 300).
    - `pfx<string>`: Prefix for the new token (default: 'pub').
    - `scope<string>`: Scope for the new token (default: 'api').
    - `roles<string[]>`: Array of roles for the new token.

```javascript
const newToken = await auth.regenerateToken({
  oldToken: 'existing-token',
  ips: ['192.168.1.1'],
  ttl: 3600,
  pfx: 'pub',
  scope: 'api',
  roles: ['admin']
})
```

### `auth.getTokenPerms(token)` *(async)*
Retrieves permissions associated with a token. Reads roles from the `users` table (LRU-cached per `conf.rolesCacheTtl`, default 30s) so DB-side role changes propagate without re-issuing the token.

**Parameters:**
- `token<string>`: The token to get permissions for.

**Returns:**
- `{ superadmin: <boolean>, perms: <string[]> }` with token permissions.

```javascript
const perms = auth.getTokenPerms('some-token')
console.log('Token permissions:', perms)
```

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
Checks if a token has the required permissions.

**Parameters:**
- `token<string>`: The token to check.
- `perm<string>`: Permission to check.

**Returns:**
- `true` if the token has the required permissions.
- `false` otherwise.

```javascript
const hasPerms = auth.tokenHasPerms('some-token', 'miner:r')
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

### `auth.revokeToken(token)`
Revokes a single session. Idempotent — returns `false` for invalid or already-revoked tokens, `true` on success.

### `auth.revokeAllForUser(userId)`
Revokes every active session for a user.

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
Handles authentication callbacks with MFA support. If MFA is required, returns a CSRF token and the list of required MFA methods; otherwise, returns the authentication token.

**Parameters:**
- `type<string>`: The type of authentication callback.
- `req<object>`: The request object containing callback details.
- `getUserMfaMethods<function>`: A function that returns the list of enabled MFA methods for the user.

**Returns:**
- If MFA is required:
  An object containing `csrf_token`, `mfa_required: true`, and `mfa_methods` (array of enabled MFA methods).
- If MFA is not required:
  An object containing the authentication `token`.

**Throws:**
- `ERR_MFA_METHOD_HANDLER_INVALID` if getUserMfaMethods is not a function.

### `auth.addMfaCompleteHandlers(handlers)`
Registers per-factor verifiers used by `mfaCompleteHandler`. Each handler is `async (caller, csrfToken, proof) => boolean`.

### `auth.mfaCompleteHandler(csrfToken, factor, proof)`
Second step of the MFA flow. Looks up the `csrf_token` issued by `mfaCallbackHandler`, consumes it (single-use, even on failure), enforces `conf.mfaCsrfTtl` (default 300s), and verifies the proof. Returns `{ token }` on success.

**Throws:**
- `ERR_MFA_CSRF_INVALID` — missing, expired, or already-consumed `csrf_token`.
- `ERR_HANDLER_INVALID` — no handler registered for `factor`.
- `ERR_MFA_FACTOR_INVALID` — factor verifier returned falsy.
