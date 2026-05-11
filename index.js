'use strict'

const async = require('async')
const Base = require('@bitfinex/bfx-facs-base')
const TABLES = require('./lib/tables')
const { dateNowSec, extractIps, isValidIp, parseSql } = require('./lib/utils')
const { isEqual, isNil, isPlainObject, getArrayUniq, union } = require('@bitfinexcom/lib-js-util-base')
const crypto = require('crypto')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const JWT_ALGORITHM = 'HS256'

const lruKeys = {
  userJtis: (userId) => `user-jtis:${userId}`,
  jtiData: (jti) => `jti-data:${jti}`,
  goTokens: (token) => `gotokens:${token}`,
  userRoles: (userId) => `user-roles:${userId}`,
  mfaCsrf: (csrf) => `mfa-csrf:${csrf}`
}

class AuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'auth'
    this._lru = opts.lru
    this._sqlite = opts.sqlite

    this._authHandlers = {}
    this._mfaHandlers = {}
    this._mfaCompleteHandlers = {}

    this._hasConf = true

    super.init()
  }

  get _isJwtMode () {
    return !!this.conf.jwtSecret
  }

  _hashToken (token) {
    return crypto.createHash('sha256').update(token).digest('hex')
  }

  async _initDb () {
    await async.mapSeries(TABLES, async (tbl) => {
      await this._sqlite.execAsync(tbl)
    })

    // M1 migration: if auth_tokens still carries the legacy `token` column
    // (pre-M1 plaintext storage), drop and recreate with the token_hash
    // schema. Any in-flight legacy-mode tokens are invalidated — clients
    // re-authenticate on next call. JWT-mode deployments are unaffected
    // (auth_tokens is unused).
    const authTokensCols = await this._sqlite.allAsync('PRAGMA table_info(auth_tokens)')
    if (authTokensCols.find(c => c.name === 'token')) {
      await this._sqlite.execAsync('DROP TABLE auth_tokens')
      const authTokensSchema = TABLES.find(t => t.includes('CREATE TABLE IF NOT EXISTS auth_tokens'))
      await this._sqlite.execAsync(authTokensSchema)
    }

    // update existing db if schema updated
    await this._updateDbFromSchema()

    const admin = this.conf.superAdmin
    if (!admin) {
      throw new Error('ERR_SUPER_ADMIN_MISSING')
    }

    const user = await this._sqlite.getAsync('SELECT * FROM users WHERE id = 1 LIMIT 1')
    if (!user) {
      await this._sqlite.runAsync(
        'INSERT INTO users (email, roles) VALUES (?, ?)', [admin, JSON.stringify(['*'])]
      )
    } else if (user.email !== admin) {
      const existingUser = await this.getUserByEmail(admin)
      if (existingUser) {
        await this.deleteUser(existingUser.id)
      }

      await this._sqlite.runAsync(
        'UPDATE users SET email = ? WHERE id = 1', [admin]
      )
    }
  }

  async _updateDbFromSchema () {
    // parse tables schema
    const schema = TABLES.map(sql => parseSql(sql))
    for (const { table, columns } of schema) {
      // Get existing columns from database
      const existingColumns = await this._sqlite.allAsync(`PRAGMA table_info(${table})`)
      const existingColumnNames = existingColumns.map(col => col.name)

      // Check each expected column and add if missing
      for (const [columnName, columnDef] of Object.entries(columns)) {
        if (!existingColumnNames.includes(columnName)) {
          await this._sqlite.execAsync(`ALTER TABLE ${table} ADD COLUMN ${columnDef}`)
        }
      }
    }
  }

  addHandlers (handlers) {
    Object.assign(this._authHandlers, handlers)
  }

  addMfaHandlers (handlers) {
    Object.assign(this._mfaHandlers, handlers)
  }

  addMfaCompleteHandlers (handlers) {
    Object.assign(this._mfaCompleteHandlers, handlers)
  }

  _validateRoles (roles) {
    if (!Array.isArray(roles)) throw new Error('ERR_ROLES_INVALID')
    const validRoles = Object.keys(this.conf.roles || {})
    for (const role of roles) {
      if (role === '*' || !validRoles.includes(role)) {
        throw new Error('ERR_ROLES_INVALID')
      }
    }
  }

  async _requireSelfOrPerm (token, targetUserId, perm) {
    const { userId } = await this._verifyToken(token)
    if (userId === targetUserId) return userId
    if (!(await this.tokenHasPerms(token, perm))) {
      throw new Error('ERR_PERMISSION_DENIED')
    }
    return userId
  }

  async _getUserRolesCached (userId) {
    const key = lruKeys.userRoles(userId)
    const ttlMs = (this.conf.rolesCacheTtl || 30) * 1000
    const cached = this._lru.peek(key)
    if (cached && (Date.now() - cached.at) < ttlMs) {
      return cached.roles
    }
    const row = await this._sqlite.getAsync('SELECT roles FROM users WHERE id = ? LIMIT 1', userId)
    if (!row) return []
    const roles = JSON.parse(row.roles || '[]')
    this._lru.set(key, { roles, at: Date.now() })
    return roles
  }

  _validateTokenOpts ({ ips, userId, ttl, metadata, pfx, scope, roles }) {
    if (!Array.isArray(ips) || !ips.length || !ips.every(ip => isValidIp(ip))) {
      throw new Error('ERR_IPS_INVALID')
    }

    if (!Number.isInteger(userId) || userId < 1) {
      throw new Error('ERR_USERID_INVALID')
    }

    if (!Number.isInteger(ttl) || ttl < 5 || ttl > 86400) { // min 5s, max 1d
      throw new Error('ERR_TTL_INVALID')
    }

    if (!isNil(metadata) && !isPlainObject(metadata)) {
      throw new Error('ERR_METADATA_INVALID')
    }

    if (pfx !== 'pub') {
      throw new Error('ERR_PFX_INVALID')
    }

    if (scope !== 'api') {
      throw new Error('ERR_SCOPE_INVALID')
    }

    if (!Array.isArray(roles) || !roles.every(c => typeof c === 'string')) {
      throw new Error('ERR_ROLES_INVALID')
    }
  }

  async genToken ({ ips, userId, ttl = this.conf.ttl || 300, metadata = {}, pfx = 'pub', scope = 'api', roles = [] }) {
    this._validateTokenOpts({ ips, userId, ttl, metadata, pfx, scope, roles })
    const args = { ips: getArrayUniq(ips), userId, ttl, metadata, pfx, scope, roles }
    return this._isJwtMode ? this._issueJwtToken(args) : this._issueDbToken(args)
  }

  _issueJwtToken ({ ips, userId, ttl, metadata, pfx, scope, roles }) {
    const jti = crypto.randomUUID()
    const signOpts = { algorithm: JWT_ALGORITHM, expiresIn: ttl, ...this._jwtIssuerOpts() }
    const token = jwt.sign(
      { sub: userId, roles, pfx, scope, jti },
      this.conf.jwtSecret,
      signOpts
    )
    this._lru.set(lruKeys.jtiData(jti), { ips, metadata })
    this._trackJti(userId, jti)
    return token
  }

  _jwtIssuerOpts () {
    return this.conf.jwtIssuer ? { issuer: this.conf.jwtIssuer } : {}
  }

  async _issueDbToken ({ ips, userId, ttl, metadata, pfx, scope, roles }) {
    let strRoles = ''
    if (roles.length) {
      strRoles = '-roles:' + roles.join(':')
    }
    const token = `${pfx}:${scope}:${crypto.randomUUID()}${strRoles}`

    await this._sqlite.runAsync(
      'INSERT INTO auth_tokens(token_hash, userId, ips, metadata, created, ttl) VALUES (?, ?, ?, ?, ?, ?)',
      [this._hashToken(token), userId, JSON.stringify(ips), JSON.stringify(metadata), dateNowSec(), ttl]
    )

    return token
  }

  _getUserJtis (userId) {
    return this._lru.peek(lruKeys.userJtis(userId))
  }

  _trackJti (userId, jti) {
    const jtis = this._getUserJtis(userId) || new Set()
    jtis.add(jti)
    this._lru.set(lruKeys.userJtis(userId), jtis)
  }

  async regenerateToken ({ oldToken, ips = null, req = null, pfx = 'pub', scope = 'api', roles = [] }) {
    let old
    try {
      old = await this._verifyToken(oldToken)
    } catch (err) {
      throw new Error('ERR_OLD_TOKEN_INVALID', { cause: err })
    }

    if (!ips && req) ips = extractIps(req, this.conf.trustProxy)
    if (!Array.isArray(ips) || !ips.length) {
      throw new Error('ERR_IPS_REQUIRED')
    }
    if (!ips.some(ip => old.ips.includes(ip))) {
      throw new Error('ERR_IP_MISMATCH')
    }

    const userId = old.userId
    const oldRoles = this._extractRoles(old, oldToken)

    if (!roles.every(c => oldRoles.includes(c))) {
      throw new Error('ERR_ROLES_INVALID')
    }

    const newToken = await this.genToken({ ips, userId, ttl: this.conf.ttl || 300, metadata: old.metadata, pfx, scope, roles })

    if (this._isJwtMode) this._revokeJwtToken(userId, old.jti)

    return newToken
  }

  _extractRoles (verified, rawToken) {
    if (this._isJwtMode) return verified.roles || []
    const roles = []
    const rolesMatch = rawToken.match(/(roles:[a-z_*:]*)/)
    if (rolesMatch && rolesMatch[1]) {
      roles.push(...(rolesMatch[1].replace('roles:', '').split(':')))
    }
    return roles
  }

  async createUser ({ email, name = null, roles = [], password = null }) {
    if (!email) {
      throw new Error('ERR_MISSING_EMAIL')
    }

    if (!Array.isArray(roles) || !roles.length) {
      throw new Error('ERR_MISSING_ROLES')
    }

    this._validateRoles(roles)

    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE email = ? LIMIT 1', email
    )

    if (user) {
      throw new Error('ERR_USER_EXISTS')
    }

    password = password ? await bcrypt.hash(password, this.conf.saltRounds || 10) : null

    await this._sqlite.runAsync(
      'INSERT INTO users (email, name, roles, password) VALUES (?, ?, ?, ?)', [email, name, JSON.stringify(roles), password]
    )
  }

  async updateUser ({ token, targetUserId = null, currentPassword = null, email, name = null, roles = null, password = null }) {
    const verified = await this._verifyToken(token)
    const callerUserId = verified.userId
    const userId = targetUserId ?? callerUserId

    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE id = ? LIMIT 1', userId
    )
    if (!user) {
      throw new Error('ERR_USER_NOT_FOUND')
    }

    const isSelf = userId === callerUserId
    const currentRoles = JSON.parse(user.roles || '[]')
    const isRoleMutation = roles !== null && !isEqual(currentRoles.slice().sort(), roles.slice().sort())

    if (roles !== null) this._validateRoles(roles)

    if ((!isSelf || isRoleMutation) && !(await this.tokenHasPerms(token, 'user:rw'))) {
      throw new Error('ERR_PERMISSION_DENIED')
    }

    const requirePw = this.conf.requireCurrentPassword !== false && isSelf
    if (requirePw && user.password) {
      if (!currentPassword) throw new Error('ERR_CURRENT_PASSWORD_REQUIRED')
      if (!await bcrypt.compare(currentPassword, user.password)) {
        throw new Error('ERR_CURRENT_PASSWORD_INVALID')
      }
    }

    const nextEmail = email ?? user.email
    const nextName = name ?? user.name
    const nextRoles = roles !== null ? JSON.stringify(roles) : user.roles
    const nextPassword = password !== null
      ? await bcrypt.hash(password, this.conf.saltRounds || 10)
      : user.password

    await this._sqlite.runAsync(
      'UPDATE users SET email = ?, name = ?, roles = ?, password = ? WHERE id = ?', [nextEmail, nextName, nextRoles, nextPassword, userId]
    )

    this._lru.remove(lruKeys.userRoles(userId))
    await this._deleteTokensOfUser(userId)
  }

  async compareUser ({ token, email = null, name = null, roles = null, password = null }) {
    const { userId } = await this._verifyToken(token)

    const dbUser = await this._sqlite.getAsync('SELECT * FROM users WHERE id = ? LIMIT 1', userId)
    if (!dbUser) {
      throw new Error('ERR_USER_NOT_FOUND')
    }

    if (!email && !name && !roles && !password) {
      throw new Error('ERR_NO_FIELDS_PROVIDED')
    }

    const checks = [
      !email || dbUser.email === email,
      !name || dbUser.name === name,
      !roles || isEqual(JSON.parse(dbUser.roles || '[]').sort(), roles.sort()),
      !password || await bcrypt.compare(password, dbUser.password)
    ]

    return checks.every(Boolean)
  }

  _mergePerms (arr) {
    if (!Array.isArray(arr) || !arr.length) {
      return
    }

    const perms = arr.reduce((acc, perm) => {
      const [key, val] = perm.split(':')
      acc[key] = new Set([...(acc[key] ?? ''), ...val])
      return acc
    }, {})

    return Object.entries(perms).map(([key, val]) => `${key}:${[...val].sort().join('')}`)
  }

  async getTokenPerms (token) {
    let verified
    try {
      verified = await this._verifyToken(token)
    } catch {
      return { superadmin: false, perms: [] }
    }
    const roles = await this._getUserRolesCached(verified.userId)
    const rolePerms = roles.map(c => c === '*' ? '*' : this.conf.roles[c])

    return {
      superadmin: rolePerms.includes('*'),
      perms: this._mergePerms(union(...rolePerms))
    }
  }

  getTokenPermsSync (token) {
    const roles = this._getRolesFromToken(token)
    const rolePerms = roles.map(c => c === '*' ? '*' : this.conf.roles[c])

    return {
      superadmin: rolePerms.includes('*'),
      perms: this._mergePerms(union(...rolePerms))
    }
  }

  _getRolesFromToken (token) {
    if (this._isJwtMode) {
      try {
        return this._verifyJwtToken(token).roles || []
      } catch {
        return []
      }
    }
    return token.substring(token.indexOf('-roles:'))
      .replace('-roles', '')
      .split(':')
      .filter(Boolean)
  }

  async resolveToken (token, ips, opts = {}) {
    let res
    try {
      res = await this._verifyToken(token)
    } catch {
      return null
    }
    if (!ips.some(ip => res.ips.includes(ip))) return null

    if (opts?.updateLastActive) await this.updateLastActive(res.userId)

    return res
  }

  async updateLastActive (userId) {
    await this._sqlite.runAsync('UPDATE users SET lastActiveAt = ? WHERE id = ?', [dateNowSec(), userId])
  }

  async tokenHasPerms (token, perm) {
    const { superadmin, perms } = await this.getTokenPerms(token)

    if (superadmin) {
      return true
    }

    const [key, required] = perm.split(':')
    const av = perms.find(p => p.startsWith(`${key}:`))?.split(':')[1] ?? ''
    return [...required].every(c => av.includes(c))
  }

  async _verifyToken (token) {
    if (this._isJwtMode) return this._verifyJwtToken(token)
    return this._verifyDbToken(token)
  }

  _verifyJwtToken (token) {
    if (typeof token !== 'string') {
      throw new Error('ERR_TOKEN_INVALID', { cause: new Error('token is not a string') })
    }
    let decoded
    try {
      const verifyOpts = { algorithms: [JWT_ALGORITHM], ...this._jwtIssuerOpts() }
      decoded = jwt.verify(token, this.conf.jwtSecret, verifyOpts)
    } catch (err) {
      throw new Error('ERR_TOKEN_INVALID', { cause: err })
    }
    const data = this._lru.get(lruKeys.jtiData(decoded.jti))
    if (!data) {
      throw new Error('ERR_TOKEN_INVALID', { cause: new Error('jti data missing (revoked or evicted)') })
    }
    return {
      userId: decoded.sub,
      ips: data.ips,
      metadata: data.metadata,
      roles: decoded.roles,
      jti: decoded.jti
    }
  }

  async _verifyDbToken (token) {
    const res = await this._getTokenFromDb(token)
    if (!res) {
      throw new Error('ERR_TOKEN_INVALID', { cause: new Error('token not found') })
    }
    if (res.created + res.ttl < dateNowSec()) {
      throw new Error('ERR_TOKEN_INVALID', { cause: new Error('token expired') })
    }
    return res
  }

  async _getTokenFromDb (token) {
    if (typeof token !== 'string' || !/^pub:api:[a-f0-9-]{36}(?:-\d+)?(?:-roles:[a-z_*:]+)?$/.test(token)) {
      return null
    }

    const hash = this._hashToken(token)
    const ckey = lruKeys.goTokens(hash)
    let res = this._lru.get(ckey)

    if (!res) {
      res = await this._sqlite.getAsync(
        'SELECT * FROM auth_tokens WHERE token_hash = ? LIMIT 1',
        hash)

      if (res) {
        res.metadata = res.metadata ? JSON.parse(res.metadata) : {}
        res.ips = JSON.parse(res.ips)
        this._lru.set(ckey, res)
      }
    }

    return res
  }

  async cleanupTokens () {
    if (this._isJwtMode) return
    await this._sqlite.runAsync(
      'DELETE FROM auth_tokens WHERE created + ttl < ?',
      dateNowSec()
    )
  }

  async mfaHandler (type, req) {
    const handler = this._mfaHandlers[type]
    if (!handler || typeof handler !== 'function') {
      throw new Error('ERR_HANDLER_INVALID')
    }

    return await handler(this.caller, req)
  }

  async mfaCallbackHandler (type, req, getUserMfaMethods) {
    if (!getUserMfaMethods || typeof getUserMfaMethods !== 'function') {
      throw new Error('ERR_MFA_METHOD_HANDLER_INVALID')
    }

    const token = await this.authCallbackHandler(type, req)
    const mfaMethods = await getUserMfaMethods(this.caller, token, req)

    if (mfaMethods && mfaMethods.length > 0) {
      const csrfToken = crypto.randomUUID()
      this._lru.set(lruKeys.mfaCsrf(csrfToken), { token, createdAt: Date.now() })

      return {
        csrf_token: csrfToken,
        mfa_required: true,
        mfa_methods: mfaMethods
      }
    }

    return { token }
  }

  async mfaCompleteHandler (csrfToken, factor, proof) {
    const key = lruKeys.mfaCsrf(csrfToken)
    const entry = this._lru.get(key)
    // Always consume the csrf_token entry — single-use, even on factor failure
    if (entry) this._lru.remove(key)

    const ttlMs = (this.conf.mfaCsrfTtl || 300) * 1000
    if (!entry || (Date.now() - entry.createdAt) > ttlMs) {
      throw new Error('ERR_MFA_CSRF_INVALID')
    }

    const handler = this._mfaCompleteHandlers[factor]
    if (!handler || typeof handler !== 'function') {
      throw new Error('ERR_HANDLER_INVALID')
    }

    const ok = await handler(this.caller, csrfToken, proof)
    if (!ok) throw new Error('ERR_MFA_FACTOR_INVALID')

    return { token: entry.token }
  }

  async authCallbackHandler (type, req) {
    const token = await this._resolveAuth(type, req)

    if (!token) {
      throw new Error('ERR_AUTH_FAIL')
    }

    return token
  }

  async _resolveAuth (type, req) {
    const handler = this._authHandlers[type]
    if (!handler || typeof handler !== 'function') {
      throw new Error('ERR_HANDLER_INVALID')
    }

    const info = await handler(this.caller, req)
    if (!info || !info.email) {
      throw new Error('ERR_EMAIL_INVALID')
    }

    // read user from table `users`
    const user = await this._sqlite.getAsync(
      'SELECT * FROM users WHERE email = ? LIMIT 1', info.email
    )
    if (!user) {
      // constant-time: equalise with the wrong-password branch below
      await bcrypt.compare(info.password || '', this._dummyHash)
      throw new Error('ERR_AUTH_FAIL')
    }

    // check if password matches
    if (info.password) {
      if (!user.password) {
        await bcrypt.compare(info.password, this._dummyHash)
        throw new Error('ERR_AUTH_FAIL')
      }
      if (!await bcrypt.compare(info.password, user.password)) {
        throw new Error('ERR_AUTH_FAIL')
      }
    }

    const userId = user.id

    if (info.password) delete info.password
    if (user.password) delete user.password
    const metadata = { ...info, ...user }
    const ips = extractIps(req, this.conf.trustProxy)

    const roles = []
    if (metadata.roles?.length) {
      roles.push(...JSON.parse(metadata.roles))
    }

    // update last active timestamp for the user
    await this.updateLastActive(userId)

    const token = await this.genToken({ ips, userId, ttl: this.conf.ttl, metadata, roles })
    return token
  }

  async getUserById (id) {
    if (!id) {
      return
    }

    return await this._sqlite.getAsync(
      'SELECT id, email, name, roles, lastActiveAt FROM users WHERE id = ? LIMIT 1', id
    )
  }

  async getUserByEmail (email) {
    if (!email) {
      return
    }

    return await this._sqlite.getAsync(
      'SELECT id, email, name, roles, lastActiveAt FROM users WHERE email = ? LIMIT 1', email
    )
  }

  async listUsers () {
    return await this._sqlite.allAsync('SELECT id, email, name, roles, lastActiveAt FROM users')
  }

  async deleteUser (id) {
    if (!id) {
      return false
    }

    if (id.toString() === '1') {
      throw new Error('ERR_NOT_ALLOWED')
    }

    await this._sqlite.runAsync(
      'DELETE from users WHERE id=?', [id]
    )

    this._lru.remove(lruKeys.userRoles(id))
    await this._deleteTokensOfUser(id)

    return true
  }

  async revokeToken (token) {
    let verified
    try {
      verified = await this._verifyToken(token)
    } catch {
      return false
    }
    if (this._isJwtMode) {
      this._revokeJwtToken(verified.userId, verified.jti)
    } else {
      const hash = this._hashToken(token)
      this._lru.remove(lruKeys.goTokens(hash))
      await this._sqlite.runAsync('DELETE FROM auth_tokens WHERE token_hash = ?', hash)
    }
    return true
  }

  async revokeAllForUser (userId) {
    await this._deleteTokensOfUser(userId)
  }

  async _deleteTokensOfUser (id) {
    if (this._isJwtMode) return this._revokeJwtUserTokens(id)
    return this._revokeDbUserTokens(id)
  }

  _revokeJwtUserTokens (userId) {
    const jtis = this._getUserJtis(userId)
    if (!jtis) return
    for (const jti of jtis) {
      this._lru.remove(lruKeys.jtiData(jti))
    }
    this._lru.remove(lruKeys.userJtis(userId))
  }

  _revokeJwtToken (userId, jti) {
    this._lru.remove(lruKeys.jtiData(jti))
    const jtis = this._getUserJtis(userId)
    if (!jtis) return
    jtis.delete(jti)
    if (jtis.size === 0) this._lru.remove(lruKeys.userJtis(userId))
    else this._lru.set(lruKeys.userJtis(userId), jtis)
  }

  async _revokeDbUserTokens (userId) {
    const rows = await this._sqlite.allAsync(
      'SELECT token_hash from auth_tokens WHERE userId=?', [userId]
    )

    rows.forEach(row => this._lru.remove(lruKeys.goTokens(row.token_hash)))

    await this._sqlite.allAsync(
      'DELETE from auth_tokens WHERE userId=?', [userId]
    )
  }

  _assertTtlCoveredByLru () {
    if (!this._isJwtMode) return
    const lruMaxAgeMs = this._lru?.cache?.maxAge
    if (!lruMaxAgeMs) return
    const ttlSec = this.conf.ttl || 300
    if (ttlSec * 1000 > lruMaxAgeMs) {
      throw new Error(`ERR_TTL_EXCEEDS_LRU_MAXAGE: conf.ttl=${ttlSec}s exceeds lru.maxAge=${lruMaxAgeMs / 1000}s`)
    }
  }

  async _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
        await this._initDb()
        this._assertTtlCoveredByLru()
        this._dummyHash = await bcrypt.hash(crypto.randomUUID(), this.conf.saltRounds || 10)
      }
    ], cb)
  }
}

module.exports = AuthFacility
