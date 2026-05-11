'use strict'

const test = require('brittle')
const crypto = require('crypto')
const { promiseSleep } = require('@bitfinex/lib-js-util-promise')
const { omit } = require('@bitfinexcom/lib-js-util-base')
const async = require('async')

const Fac = require('..')
const caller = { ctx: { root: __dirname } }

const sqliteFac = require('./helper/sqlite.fac')()
const lruFac = require('./helper/lru.fac')()

const authFac = new Fac(caller, {
  sqlite: sqliteFac,
  ns: 'a0',
  lru: lruFac
}, { env: 'test' })

test('init', async (t) => {
  // init the database
  await new Promise((resolve, _reject) => authFac.start(resolve))

  // check if users table is created
  const usersTable = await authFac._sqlite.getAsync(
    'SELECT name FROM sqlite_master WHERE type="table" AND name="users"'
  )
  t.ok(usersTable, 'users table created')

  // check if auth_tokens table is created
  const authTokensTable = await authFac._sqlite.getAsync(
    'SELECT name FROM sqlite_master WHERE type="table" AND name="auth_tokens"'
  )
  t.ok(authTokensTable, 'auth_tokens table created')

  // check if superadmin is created
  const superAdmin = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'superadmin@localhost'
  )
  t.alike(superAdmin, {
    id: 1,
    email: 'superadmin@localhost',
    roles: JSON.stringify(['*']),
    password: null,
    name: null,
    lastActiveAt: null
  }, 'superAdmin created')
})

test('createUser', async (t) => {
  // create a user with correct email, roles as array of strings
  await authFac.createUser({ email: 'test1@localhost', name: 'Test User 1', roles: ['user'] })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test1@localhost'
  )

  t.alike(user, {
    id: 2,
    email: 'test1@localhost',
    roles: JSON.stringify(['user']),
    password: null,
    name: 'Test User 1',
    lastActiveAt: null
  }, 'valid user created')

  // create a user with missing email
  await t.exception(
    async () => await authFac.createUser({ roles: ['user'] }),
    /ERR_MISSING_EMAIL/,
    'throw error on missing email'
  )

  // create a user with missing roles
  await t.exception(
    async () => await authFac.createUser({ email: 'test2@localhost' }),
    /ERR_MISSING_ROLES/,
    'throw error on missing roles'
  )

  // create a user with existing email
  await t.exception(
    async () => await authFac.createUser({ email: 'test1@localhost', roles: ['user'] }),
    /ERR_USER_EXISTS/,
    'throw error on existing email'
  )
})

test('createToken', async (t) => {
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['normal_user']
  })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-roles:normal_user'
  // match all except uuid with regex
  t.is(token.match(/pub:api:[a-z0-9-]*-roles:normal_user/)[0], token, 'valid token created')
})

test('regenerateToken', async (t) => {
  // create a token with correct email and password
  const oldToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user', 'site_manager']
  })

  // regenerate token with correct old token
  const newToken = await authFac.regenerateToken({ oldToken, ips: ['127.0.0.1'], roles: ['user', 'site_manager'] })

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-roles:user'
  // match all except uuid with regex
  t.is(newToken.match(/pub:api:[a-z0-9-]*-roles:user:site_manager/)[0], newToken, 'valid token regenerated')

  // regenerate token with incorrect old token
  await t.exception(
    async () => await authFac.regenerateToken({ oldToken: 'incorrect', ips: ['127.0.0.1'] }),
    /ERR_OLD_TOKEN_INVALID/,
    'throw error on incorrect old token'
  )

  // regenerate token with incorrect roles
  await t.exception(
    async () => await authFac.regenerateToken({ oldToken, ips: ['127.0.0.1'], roles: ['admin'] }),
    /ERR_ROLES_INVALID/,
    'throw error on incorrect roles'
  )

  // H1: regenerate from a non-bound IP is rejected
  await t.exception(
    async () => await authFac.regenerateToken({ oldToken, ips: ['8.8.8.8'], roles: ['user'] }),
    /ERR_IP_MISMATCH/,
    'throw error when calling IP not in token binding'
  )

  // H1: regenerate without ips and without req is rejected
  await t.exception(
    async () => await authFac.regenerateToken({ oldToken, roles: ['user'] }),
    /ERR_IPS_REQUIRED/,
    'throw error when neither ips nor req supplied'
  )

  // H1: req-derived IP path works
  const reqOk = { socket: { remoteAddress: '127.0.0.1' } }
  await t.execution(
    async () => await authFac.regenerateToken({ oldToken, req: reqOk, roles: ['user'] }),
    'derives IP from req via extractIps + trustProxy'
  )

  const oldSuperAdminToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['*']
  })

  // regenerate token with super admin role
  await t.execution(
    async () => await authFac.regenerateToken({ oldToken: oldSuperAdminToken, ips: ['127.0.0.1'], roles: ['*'] }),
    'valid super admin token regenerated'
  )
})

test('tokenPerms', async (t) => {
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user']
  })

  // check if token has correct permissions
  t.is(await authFac.tokenHasPerms(token, 'jobs:r'), true, 'token has jobs:r')
  t.is(await authFac.tokenHasPerms(token, 'jobs:w'), true, 'token has jobs:w')
  t.not(await authFac.tokenHasPerms(token, 'miner:r'), true, 'token does not have miner:r')

  // check if superadmin token has all permissions
  const superAdminToken = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 1,
    roles: ['*']
  })

  t.is(await authFac.tokenHasPerms(superAdminToken, 'jobs:r'), true, 'superadmin token has jobs:r')
  t.is(await authFac.tokenHasPerms(superAdminToken, 'jobs:xyz'), true, 'superadmin token has unknown permission')
})

test('updateUser', async (t) => {
  const userId = 2
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId,
    roles: ['user']
  })

  await async.times(3, async () => (
    authFac.genToken({
      ips: ['127.0.0.1'],
      userId,
      roles: ['user']
    })
  ))

  const tokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', userId
  )

  // update user with new email and password
  // NOTE: password is hashed before storing
  await authFac.updateUser({ token, email: 'test3@localhost', roles: ['user'], password: 'newpassword' })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test3@localhost'
  )

  t.alike(omit(user, ['password', 'name', 'lastActiveAt']), {
    id: 2,
    email: 'test3@localhost',
    roles: JSON.stringify(['user'])
  }, 'user updated correctly')

  const dbTokensAfterUpdate = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', user.id
  )
  t.is(dbTokensAfterUpdate.length, 0, 'tokens of user deleted from db')

  const numCachedTokensAfterUpdate = tokens.map(token => authFac._lru.get(`gotokens:${token}`)).filter(token => !!token).length
  t.is(numCachedTokensAfterUpdate, 0, 'tokens of user deleted from cache')

  const resolvedToken = await authFac.resolveToken(tokens[0])
  t.is(resolvedToken, null, 'cannot resolve old token after user update')
})

test('compareUser', async (t) => {
  // Create a user with email, roles, and password
  const password = 'securepassword'
  await authFac.createUser({ email: 'compare@localhost', name: 'Test User', roles: ['user'], password })

  // Fetch the user from the database
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'compare@localhost'
  )

  // Generate an authentication token for the user
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: user.id,
    roles: ['user']
  })

  // Test with correct email
  t.is(
    await authFac.compareUser({ token, email: 'compare@localhost' }),
    true,
    'compareUser should return true for matching email'
  )

  // Test with incorrect email
  t.is(
    await authFac.compareUser({ token, email: 'wrong@localhost' }),
    false,
    'compareUser should return false for incorrect email'
  )

  // Test with correct name
  t.is(
    await authFac.compareUser({ token, name: 'Test User' }),
    true,
    'compareUser should return true for matching name'
  )

  // Test with incorrect name
  t.is(
    await authFac.compareUser({ token, name: 'Wrong User' }),
    false,
    'compareUser should return false for incorrect name'
  )

  // Test with correct roles
  t.is(
    await authFac.compareUser({ token, roles: ['user'] }),
    true,
    'compareUser should return true for matching roles'
  )

  // Test with incorrect roles
  t.is(
    await authFac.compareUser({ token, roles: ['admin'] }),
    false,
    'compareUser should return false for incorrect roles'
  )

  // Test with correct password
  t.is(
    await authFac.compareUser({ token, password }),
    true,
    'compareUser should return true for matching password'
  )

  // Test with incorrect password
  t.is(
    await authFac.compareUser({ token, password: 'wrongpassword' }),
    false,
    'compareUser should return false for incorrect password'
  )

  // Test with multiple correct fields (email, password, roles)
  t.is(
    await authFac.compareUser({ token, email: 'compare@localhost', password, roles: ['user'] }),
    true,
    'compareUser should return true when all fields match'
  )

  // Test with one incorrect field
  t.is(
    await authFac.compareUser({ token, email: 'compare@localhost', password, roles: ['admin'] }),
    false,
    'compareUser should return false if one field does not match'
  )

  // Test with missing fields (should throw error)
  await t.exception(
    async () => await authFac.compareUser({ token }),
    /ERR_NO_FIELDS_PROVIDED/,
    'compareUser should throw error if no fields are provided'
  )
})

test('authHandlers', async (t) => {
  // add a simple auth handler
  authFac.addHandlers({
    password: (ctx, req) => {
      if (!req.email || !req.password) {
        throw new Error('ERR_MISSING_EMAIL_PASSWORD')
      }
      return req
    },
    nonPassword: (ctx, req) => {
      if (!req.email) {
        throw new Error('ERR_MISSING_EMAIL')
      }
      return req
    }
  })

  const reqWithSocket = (body) => ({ ...body, socket: { remoteAddress: '127.0.0.1' } })

  // create a token with correct email and password
  const token = await authFac.authCallbackHandler('password', reqWithSocket({ email: 'test3@localhost', password: 'newpassword' }))

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-roles:user'
  // match all except uuid with regex
  t.is(token.match(/pub:api:[a-z0-9-]*-roles:user/)[0], token, 'valid token created with password auth handler')

  // throw error in wrong password (H3: collapsed to ERR_AUTH_FAIL)
  await t.exception(
    async () => await authFac.authCallbackHandler('password', reqWithSocket({ email: 'test3@localhost', password: 'incorrect' })),
    /ERR_AUTH_FAIL/,
    'throw error on incorrect password'
  )

  // create a valid token with non-password auth handler
  const token2 = await authFac.authCallbackHandler('nonPassword', reqWithSocket({ email: 'test3@localhost' }))

  // Token should be like 'pub:api:60f410c1-ea10-4ec8-95e0-bf06be87858d-roles:user'
  // match all except uuid with regex
  t.is(token2.match(/pub:api:[a-z0-9-]*-roles:user/)[0], token2, 'valid token created with non-password auth handler')

  // create a token with incorrect email and password (H3: collapsed to ERR_AUTH_FAIL)
  await t.exception(
    async () => await authFac.authCallbackHandler('password', reqWithSocket({ email: 'test100@localhost', password: 'incorrect' })),
    /ERR_AUTH_FAIL/,
    'throw error on incorrect email and password'
  )
})

test('mfaHandler', async t => {
  authFac.addMfaHandlers({
    totp: async (ctx, req) => ({ ok: true, ctx, req })
  })

  const result = await authFac.mfaHandler('totp', { foo: 1 })
  t.is(result.ok, true)
  t.ok(result.ctx)
  t.alike(result.req, { foo: 1 })
  await t.exception(
    async () => await authFac.mfaHandler('notfound', {}),
    /ERR_HANDLER_INVALID/
  )
})

test('mfaCallbackHandler', async t => {
  // No MFA required
  authFac.authCallbackHandler = async () => 'token123'
  const getUserMfaMethodsNone = async () => []
  const resultNone = await authFac.mfaCallbackHandler('any', {}, getUserMfaMethodsNone)
  t.alike(resultNone, { token: 'token123' })

  // MFA required
  authFac.authCallbackHandler = async () => 'token456'
  const getUserMfaMethodsSome = async () => ['totp', 'passkey']
  const resultSome = await authFac.mfaCallbackHandler('any', {}, getUserMfaMethodsSome)
  t.ok(resultSome.csrf_token)
  t.is(resultSome.mfa_required, true)
  t.alike(resultSome.mfa_methods, ['totp', 'passkey'])
  // H5: csrf_token entry is now namespaced and wraps the token with a createdAt timestamp
  const csrfEntry = authFac._lru.get(`mfa-csrf:${resultSome.csrf_token}`)
  t.is(csrfEntry.token, 'token456')
  t.ok(typeof csrfEntry.createdAt === 'number')

  // Invalid getUserMfaMethods
  authFac.authCallbackHandler = async () => 'token789'
  await t.exception(
    async () => await authFac.mfaCallbackHandler('any', {}, null),
    /ERR_MFA_METHOD_HANDLER_INVALID/
  )
  await t.exception(
    async () => await authFac.mfaCallbackHandler('any', {}, 123),
    /ERR_MFA_METHOD_HANDLER_INVALID/
  )
})

test('cleanupTokens', async (t) => {
  // create a token with correct email and password
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['user'],
    ttl: 5
  })

  // check if token is created
  let authTokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE token = ?', token
  )

  t.is(authTokens.length, 1, 'token created')

  // wait 6s and cleanup tokens
  await promiseSleep(6000)
  await authFac.cleanupTokens()

  // check if token is deleted
  authTokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE token = ?', token
  )

  t.is(authTokens.length, 0, 'token deleted')
})

test('getUser', async (t) => {
  await authFac.createUser({ email: 'test6@localhost', roles: ['user'] })
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test6@localhost'
  )
  const expected = {
    id: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles,
    lastActiveAt: user.lastActiveAt
  }

  let res = await authFac.getUserById(user.id)
  t.alike(res, expected, 'user fetched by id')
  t.is(res.password, undefined, 'password is not returned')

  res = await authFac.getUserByEmail(user.email)
  t.alike(res, expected, 'user fetched by email')
  t.is(res.password, undefined, 'password is not returned')
})

test('listUsers', async (t) => {
  await authFac.createUser({ email: 'test4@localhost', roles: ['user'] })

  const users = await authFac.listUsers()

  t.is(Array.isArray(users), true, 'list of users returned')
  t.is(users.every(user => user.id !== undefined && user.email !== undefined && user.roles !== undefined), true, 'user has details')
  t.is(users.every(user => user.password === undefined), true, 'password is not returned')
})

test('deleteUser', async (t) => {
  await authFac.createUser({ email: 'test5@localhost', roles: ['user'] })

  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test5@localhost'
  )

  await async.times(3, async () => authFac.genToken({
    ips: ['127.0.0.1'],
    userId: user.id,
    roles: ['normal_user']
  }))

  const tokens = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', user.id
  )

  await t.execution(async () => await authFac.deleteUser(user.id), 'delete user is successful')

  const userToCheck = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test5@localhost'
  )

  t.is(userToCheck, undefined, 'user is deleted')
  await t.exception(async () => await authFac.deleteUser(1), 'super user can not be deleted')

  const dbTokensAfterDelete = await authFac._sqlite.allAsync(
    'SELECT * FROM auth_tokens WHERE userId = ?', user.id
  )
  t.is(dbTokensAfterDelete.length, 0, 'tokens of user deleted from db')

  const numCachedTokensAfterDelete = tokens.map(token => authFac._lru.get(`gotokens:${token}`)).filter(token => !!token).length
  t.is(numCachedTokensAfterDelete, 0, 'tokens of user deleted from cache')

  const resolvedToken = await authFac.resolveToken(tokens[0])
  t.is(resolvedToken, null, 'cannot resolve old token after user delete')
})

test('updateLastActive', async (t) => {
  await authFac.createUser({ email: 'test@localhost', roles: ['user'] })
  const user = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'test@localhost'
  )

  const userBefore = await authFac.getUserById(user.id)
  t.is(userBefore.lastActiveAt, null, 'lastActiveAt is initially null')

  await authFac.updateLastActive(user.id)

  const userAfter = await authFac.getUserById(user.id)
  t.ok(userAfter.lastActiveAt, 'lastActiveAt is set after update')
  t.is(typeof userAfter.lastActiveAt, 'number', 'lastActiveAt is a number')
})

test('H5: mfaCompleteHandler enforces single-use csrf_token, TTL, and factor proof', async (t) => {
  authFac.addMfaCompleteHandlers({
    totp: async (ctx, csrf, proof) => proof === '123456'
  })

  const issue = () => {
    const csrfToken = crypto.randomUUID()
    authFac._lru.set(`mfa-csrf:${csrfToken}`, { token: 'final-bearer', createdAt: Date.now() })
    return csrfToken
  }

  // (1) Wrong factor proof — single-use entry consumed, returns ERR_MFA_FACTOR_INVALID
  const csrf1 = issue()
  await t.exception(
    async () => await authFac.mfaCompleteHandler(csrf1, 'totp', 'wrong'),
    /ERR_MFA_FACTOR_INVALID/,
    'wrong proof rejected'
  )
  t.absent(authFac._lru.get(`mfa-csrf:${csrf1}`), 'csrf entry consumed even on factor failure')

  // (2) Replay of the same csrf_token (now consumed) fails with ERR_MFA_CSRF_INVALID
  await t.exception(
    async () => await authFac.mfaCompleteHandler(csrf1, 'totp', '123456'),
    /ERR_MFA_CSRF_INVALID/,
    'replay after consumption rejected'
  )

  // (3) Unknown csrf_token is rejected
  await t.exception(
    async () => await authFac.mfaCompleteHandler('00000000-0000-0000-0000-000000000000', 'totp', '123456'),
    /ERR_MFA_CSRF_INVALID/,
    'unknown csrf_token rejected'
  )

  // (4) Expired csrf_token (createdAt older than mfaCsrfTtl) is rejected
  const csrf4 = crypto.randomUUID()
  authFac._lru.set(`mfa-csrf:${csrf4}`, { token: 'stale', createdAt: Date.now() - 10 * 60 * 1000 })
  await t.exception(
    async () => await authFac.mfaCompleteHandler(csrf4, 'totp', '123456'),
    /ERR_MFA_CSRF_INVALID/,
    'expired csrf_token rejected'
  )

  // (5) Happy path — correct proof releases the bearer token
  const csrf5 = issue()
  const result = await authFac.mfaCompleteHandler(csrf5, 'totp', '123456')
  t.is(result.token, 'final-bearer', 'returns the stashed bearer token')
  t.absent(authFac._lru.get(`mfa-csrf:${csrf5}`), 'csrf entry consumed on success')

  // (6) Unknown factor — ERR_HANDLER_INVALID (not the same code as csrf/proof issues so the
  //     caller can distinguish configuration errors from auth failures)
  const csrf6 = issue()
  await t.exception(
    async () => await authFac.mfaCompleteHandler(csrf6, 'passkey', 'whatever'),
    /ERR_HANDLER_INVALID/,
    'unregistered factor handler throws'
  )
})

test('H3: auth failures collapse to ERR_AUTH_FAIL; dummy hash is initialised', async (t) => {
  // _dummyHash is seeded at _start
  t.ok(typeof authFac._dummyHash === 'string' && authFac._dummyHash.startsWith('$2'), 'dummy bcrypt hash initialised at _start')

  authFac.addHandlers({
    'h3-pw': (ctx, req) => {
      if (!req.email) throw new Error('ERR_MISSING_EMAIL')
      return req
    }
  })

  // user with a password set
  const password = 'H3-known-password!1'
  await authFac.createUser({ email: 'h3-known@localhost', roles: ['user'], password })

  // user without a password
  await authFac.createUser({ email: 'h3-nopass@localhost', roles: ['user'] })

  const req = (body) => ({ ...body, socket: { remoteAddress: '127.0.0.1' } })

  // call _resolveAuth directly — the mfaCallbackHandler test above replaces
  // authCallbackHandler on the shared instance with a stub
  // (1) unknown email + any password
  await t.exception(
    async () => await authFac._resolveAuth('h3-pw', req({ email: 'h3-unknown@localhost', password: 'anything' })),
    /ERR_AUTH_FAIL/,
    'unknown email yields ERR_AUTH_FAIL'
  )

  // (2) known email + wrong password
  await t.exception(
    async () => await authFac._resolveAuth('h3-pw', req({ email: 'h3-known@localhost', password: 'wrong' })),
    /ERR_AUTH_FAIL/,
    'wrong password yields ERR_AUTH_FAIL'
  )

  // (3) known email with no password set + caller provides one
  await t.exception(
    async () => await authFac._resolveAuth('h3-pw', req({ email: 'h3-nopass@localhost', password: 'anything' })),
    /ERR_AUTH_FAIL/,
    'password-not-set yields ERR_AUTH_FAIL (no enumeration)'
  )
})

test('H2: getTokenPerms sources roles from users table, not from the token claims', async (t) => {
  await authFac.createUser({ email: 'h2@localhost', roles: ['user'] })
  const user = await authFac._sqlite.getAsync('SELECT * FROM users WHERE email = ?', 'h2@localhost')
  const token = await authFac.genToken({ ips: ['127.0.0.1'], userId: user.id, roles: ['user'] })

  t.ok(await authFac.tokenHasPerms(token, 'jobs:r'), 'jobs:r granted initially (user role)')
  t.absent(await authFac.tokenHasPerms(token, 'miner:r'), 'miner:r not granted initially')

  // Promote the user to admin in the DB and invalidate the role cache
  await authFac._sqlite.runAsync('UPDATE users SET roles = ? WHERE id = ?', [JSON.stringify(['admin']), user.id])
  authFac._lru.remove(`user-roles:${user.id}`)

  // The same un-rotated token now reflects the live DB role assignment
  t.ok(await authFac.tokenHasPerms(token, 'miner:r'), 'miner:r granted after DB role promotion')
  t.ok(await authFac.tokenHasPerms(token, 'user:rw'), 'user:rw granted after DB role promotion')

  // Demote in DB, invalidate cache — perms drop again on next check
  await authFac._sqlite.runAsync('UPDATE users SET roles = ? WHERE id = ?', [JSON.stringify(['user']), user.id])
  authFac._lru.remove(`user-roles:${user.id}`)
  t.absent(await authFac.tokenHasPerms(token, 'miner:r'), 'miner:r dropped after DB demotion')
})

test('C2 + L2: legacy token format and regex validation', async (t) => {
  // L2: new tokens have no userId in the suffix
  const token = await authFac.genToken({
    ips: ['127.0.0.1'],
    userId: 9,
    roles: ['user']
  })
  t.absent(/^pub:api:[a-f0-9-]{36}-9-roles:/.test(token), 'token suffix no longer embeds userId')
  t.ok(/^pub:api:[a-f0-9-]{36}-roles:user$/.test(token), 'token matches new format pub:api:<uuid>-roles:<roles>')

  // userId is still tracked in the auth_tokens row, not in the string
  const row = await authFac._sqlite.getAsync('SELECT userId FROM auth_tokens WHERE token = ?', token)
  t.is(row.userId, 9, 'userId stored in DB column, not parsed from token')

  // C2: garbage tokens are rejected by _getTokenFromDb format check (returns null, not an error)
  t.is(await authFac._getTokenFromDb('not-a-token'), null, 'rejects malformed token')
  t.is(await authFac._getTokenFromDb('p'), null, 'rejects single-char token (old regex bug)')
  t.is(await authFac._getTokenFromDb(''), null, 'rejects empty token')
  t.is(await authFac._getTokenFromDb(null), null, 'rejects non-string token')

  // C2: backward-compat — regex still accepts the legacy "with userId" form
  await authFac._sqlite.runAsync(
    'INSERT INTO auth_tokens(token, userId, ips, metadata, created, ttl) VALUES (?, ?, ?, ?, ?, ?)',
    ['pub:api:11111111-2222-3333-4444-555555555555-7-roles:user', 9, JSON.stringify(['127.0.0.1']), JSON.stringify({}), Math.floor(Date.now() / 1000), 3000]
  )
  const legacyRow = await authFac._getTokenFromDb('pub:api:11111111-2222-3333-4444-555555555555-7-roles:user')
  t.ok(legacyRow, 'legacy token format still readable from DB (transition compatibility)')
})

test('C1: createUser rejects roles outside conf.roles and the "*" marker', async (t) => {
  await t.exception(
    async () => await authFac.createUser({ email: 'c1a@localhost', roles: ['nonexistent'] }),
    /ERR_ROLES_INVALID/,
    'rejects role not in conf.roles'
  )

  await t.exception(
    async () => await authFac.createUser({ email: 'c1b@localhost', roles: ['*'] }),
    /ERR_ROLES_INVALID/,
    'rejects the "*" super-admin marker'
  )

  await t.exception(
    async () => await authFac.createUser({ email: 'c1c@localhost', roles: ['user', '*'] }),
    /ERR_ROLES_INVALID/,
    'rejects "*" mixed with valid roles'
  )
})

test('C1 + H4: updateUser role validation, permission gates, and currentPassword', async (t) => {
  const password = 'OriginalPassword!1'
  await authFac.createUser({ email: 'c1-victim@localhost', roles: ['user'], password })
  const victim = await authFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'c1-victim@localhost'
  )

  // Privilege escalation attempt: victim with `user` role tries to set their own roles to '*'
  const victimToken = await authFac.genToken({ ips: ['127.0.0.1'], userId: victim.id, roles: ['user'] })

  await t.exception(
    async () => await authFac.updateUser({
      token: victimToken,
      currentPassword: password,
      email: 'c1-victim@localhost',
      roles: ['*']
    }),
    /ERR_ROLES_INVALID/,
    'rejects "*" in updateUser roles'
  )

  await t.exception(
    async () => await authFac.updateUser({
      token: victimToken,
      currentPassword: password,
      email: 'c1-victim@localhost',
      roles: ['nonexistent']
    }),
    /ERR_ROLES_INVALID/,
    'rejects unknown role in updateUser roles'
  )

  // Self-role-mutation to a different valid role still requires user:rw (`user` role has only jobs:rw)
  await t.exception(
    async () => await authFac.updateUser({
      token: victimToken,
      currentPassword: password,
      email: 'c1-victim@localhost',
      roles: ['admin']
    }),
    /ERR_PERMISSION_DENIED/,
    'self role-mutation denied without user:rw permission'
  )

  // H4: a self-update without currentPassword is rejected when user.password is set
  await t.exception(
    async () => await authFac.updateUser({
      token: victimToken,
      email: 'c1-victim-new@localhost'
    }),
    /ERR_CURRENT_PASSWORD_REQUIRED/,
    'requires currentPassword when user has password set'
  )

  // H4: wrong currentPassword is rejected
  await t.exception(
    async () => await authFac.updateUser({
      token: victimToken,
      currentPassword: 'WrongPassword!',
      email: 'c1-victim-new@localhost'
    }),
    /ERR_CURRENT_PASSWORD_INVALID/,
    'rejects wrong currentPassword'
  )

  // H4: correct currentPassword + non-role mutation succeeds
  await t.execution(
    async () => await authFac.updateUser({
      token: victimToken,
      currentPassword: password,
      email: 'c1-victim-new@localhost'
    }),
    'self profile update succeeds with valid currentPassword'
  )

  // C1: a superadmin token (roles ['*']) CAN mutate target user's roles
  const adminToken = await authFac.genToken({ ips: ['127.0.0.1'], userId: 1, roles: ['*'] })
  await t.execution(
    async () => await authFac.updateUser({
      token: adminToken,
      targetUserId: victim.id,
      email: 'c1-victim-new@localhost',
      roles: ['admin']
    }),
    'superadmin can update another user\'s roles'
  )

  // C1: a non-superadmin without user:rw can NOT update another user
  const noPermsToken = await authFac.genToken({ ips: ['127.0.0.1'], userId: 2, roles: ['user'] })
  await t.exception(
    async () => await authFac.updateUser({
      token: noPermsToken,
      targetUserId: victim.id,
      email: 'c1-victim-takeover@localhost'
    }),
    /ERR_PERMISSION_DENIED/,
    'cross-user update denied without user:rw'
  )
})

// ---------- JWT mode (conf.jwtSecret set) ----------

const jwt = require('jsonwebtoken')
const JWT_SECRET = 'test-secret-do-not-use-in-prod'

const jwtSqliteFac = require('./helper/sqlite.fac')()
const jwtLruFac = require('./helper/lru.fac')()
const jwtAuthFac = new Fac(caller, {
  sqlite: jwtSqliteFac,
  ns: 'a0',
  lru: jwtLruFac
}, { env: 'test' })

test('jwt: init with jwtSecret set', async (t) => {
  await new Promise((resolve) => jwtAuthFac.start(resolve))
  jwtAuthFac.conf.jwtSecret = JWT_SECRET
  t.is(jwtAuthFac._isJwtMode, true, 'jwt mode active')
})

test('jwt: genToken returns HS256 JWT with expected claims', async (t) => {
  const token = await jwtAuthFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['normal_user']
  })

  const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })
  t.is(decoded.sub, 2, 'sub claim is userId')
  t.is(decoded.iss, undefined, 'iss claim absent when jwtIssuer not configured')
  t.alike(decoded.roles, ['normal_user'], 'roles claim matches')
  t.is(decoded.ips, undefined, 'ips not embedded in JWT (kept server-side)')
  t.is(decoded.metadata, undefined, 'metadata not embedded in JWT (kept server-side)')
  t.ok(decoded.jti, 'jti claim present')
  t.ok(decoded.exp, 'exp claim present')
  t.ok(decoded.iat, 'iat claim present')
})

test('jwt: issuer is opt-in via conf.jwtIssuer', async (t) => {
  jwtAuthFac.conf.jwtIssuer = 'my-app'
  try {
    const token = await jwtAuthFac.genToken({
      ips: ['127.0.0.1'],
      userId: 2,
      roles: ['normal_user']
    })

    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: 'my-app' })
    t.is(decoded.iss, 'my-app', 'iss claim set when configured')

    t.exception(
      () => jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: 'other' }),
      /jwt issuer invalid/,
      'rejects verification with mismatched issuer'
    )

    t.ok(await jwtAuthFac.resolveToken(token, ['127.0.0.1']), 'fac resolves matching issuer')
  } finally {
    delete jwtAuthFac.conf.jwtIssuer
  }
})

test('jwt: resolveToken accepts a valid token and rejects a tampered one', async (t) => {
  const token = await jwtAuthFac.genToken({
    ips: ['127.0.0.1'],
    userId: 2,
    roles: ['normal_user']
  })

  const res = await jwtAuthFac.resolveToken(token, ['127.0.0.1'])
  t.ok(res, 'valid token resolves')
  t.is(res.userId, 2, 'resolved shape has userId')

  const [h, p, s] = token.split('.')
  const tampered = `${h}.${p.slice(0, -1)}${p.slice(-1) === 'A' ? 'B' : 'A'}.${s}`
  t.is(await jwtAuthFac.resolveToken(tampered, ['127.0.0.1']), null, 'tampered token rejected')
})

test('jwt: updateUser revokes prior tokens', async (t) => {
  await jwtAuthFac.createUser({ email: 'jwt-user@localhost', roles: ['normal_user'] })
  const user = await jwtAuthFac._sqlite.getAsync(
    'SELECT * FROM users WHERE email = ?', 'jwt-user@localhost'
  )

  const tokens = []
  for (let i = 0; i < 3; i++) {
    tokens.push(await jwtAuthFac.genToken({
      ips: ['127.0.0.1'],
      userId: user.id,
      roles: ['normal_user']
    }))
  }

  await jwtAuthFac.updateUser({
    token: tokens[0],
    email: 'jwt-user2@localhost',
    roles: ['normal_user']
  })

  for (const tk of tokens) {
    t.is(await jwtAuthFac.resolveToken(tk, ['127.0.0.1']), null, 'revoked after update')
  }
})

test('jwt: regenerateToken revokes the old jti', async (t) => {
  const oldToken = await jwtAuthFac.genToken({
    ips: ['127.0.0.1'],
    userId: 42,
    roles: ['user']
  })
  const oldJti = jwt.verify(oldToken, JWT_SECRET).jti

  const newToken = await jwtAuthFac.regenerateToken({ oldToken, ips: ['127.0.0.1'], roles: ['user'] })
  const newJti = jwt.verify(newToken, JWT_SECRET).jti

  t.not(newJti, oldJti, 'new token has a different jti')
  t.is(await jwtAuthFac.resolveToken(oldToken, ['127.0.0.1']), null, 'old token rejected after regenerate')
  t.ok(await jwtAuthFac.resolveToken(newToken, ['127.0.0.1']), 'new token still valid')

  const jtis = jwtAuthFac._lru.peek('user-jtis:42')
  t.absent(jtis?.has(oldJti), 'old jti removed from user-jtis set')
  t.ok(jtis?.has(newJti), 'new jti present in user-jtis set')
})

test('jwt: genToken tracks jti in LRU user-jtis entry; cleanupTokens is a no-op', async (t) => {
  const a = await jwtAuthFac.genToken({
    ips: ['127.0.0.1'],
    userId: 1,
    roles: ['*'],
    ttl: 5
  })
  const b = await jwtAuthFac.genToken({
    ips: ['127.0.0.1'],
    userId: 1,
    roles: ['*'],
    ttl: 3000
  })

  const aJti = jwt.verify(a, JWT_SECRET).jti
  const bJti = jwt.verify(b, JWT_SECRET).jti
  const jtis = jwtAuthFac._lru.peek('user-jtis:1')
  t.ok(jtis?.has(aJti), 'first jti tracked in LRU')
  t.ok(jtis?.has(bJti), 'second jti tracked in LRU')

  await t.execution(async () => await jwtAuthFac.cleanupTokens(), 'cleanupTokens no-ops in jwt mode')
})

test('jwt: _assertTtlCoveredByLru rejects ttl > lru.maxAge', (t) => {
  const originalLru = jwtAuthFac._lru
  const originalTtl = jwtAuthFac.conf.ttl

  jwtAuthFac._lru = { cache: { maxAge: 60_000 } }
  jwtAuthFac.conf.ttl = 120
  t.exception(
    () => jwtAuthFac._assertTtlCoveredByLru(),
    /ERR_TTL_EXCEEDS_LRU_MAXAGE/,
    'throws when conf.ttl exceeds lru.maxAge'
  )

  jwtAuthFac.conf.ttl = 60
  t.execution(() => jwtAuthFac._assertTtlCoveredByLru(), 'boundary ttl === maxAge accepted')

  jwtAuthFac._lru = originalLru
  jwtAuthFac.conf.ttl = originalTtl
})
