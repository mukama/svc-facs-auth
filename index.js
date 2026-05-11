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
  goTokens: (token) => `gotokens:${token}`
}

class AuthFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'auth'
    this._lru = opts.lru
    this._sqlite = opts.sqlite

    this._authHandlers = {}
    this._mfaHandlers = {}

    this._hasConf = true

    super.init()
  }

  get _isJwtMode () {
    return !!this.conf.jwtSecret
  }

  async _initDb () {
    await async.mapSeries(TABLES, async (tbl) => {
      await this._sqlite.execAsync(tbl)
    })

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
    if (!this.tokenHasPerms(token, perm)) {
      throw new Error('ERR_PERMISSION_DENIED')
    }
    return userId
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
    const token = `${pfx}:${scope}:${crypto.randomUUID()}-${userId}${strRoles}`

    await this._sqlite.runAsync(
      'INSERT INTO auth_tokens(token, userId, ips, metadata, created, ttl) VALUES (?, ?, ?, ?, ?, ?)',
      [token, userId, JSON.stringify(ips), JSON.stringify(metadata), dateNowSec(), ttl]
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

  async regenerateToken ({ oldToken, ips = null, pfx = 'pub', scope = 'api', roles = [] }) {
    let old
    try {
      old = await this._verifyToken(oldToken)
    } catch (err) {
      throw new Error('ERR_OLD_TOKEN_INVALID', { cause: err })
    }

    ips = ips || old.ips
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

    if ((!isSelf || isRoleMutation) && !this.tokenHasPerms(token, 'user:rw')) {
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

  getTokenPerms (token) {
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

  tokenHasPerms (token, perm) {
    const { superadmin, perms } = this.getTokenPerms(token)

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
    if (typeof token !== 'string' || /^[a-zA-Z0-9:\-]$/.test(token)) { //eslint-disable-line
      return null
    }

    const ckey = lruKeys.goTokens(token)
    let res = this._lru.get(ckey)

    if (!res) {
      res = await this._sqlite.getAsync(
        'SELECT * FROM auth_tokens WHERE token = ? LIMIT 1',
        token)

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
      this._lru.set(csrfToken, token)

      return {
        csrf_token: csrfToken,
        mfa_required: true,
        mfa_methods: mfaMethods
      }
    }

    return { token }
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
      throw new Error('ERR_USER_INVALID')
    }

    // check if password matches
    if (info.password) {
      if (!user.password) {
        throw new Error('ERR_PASSWORD_NOT_SET')
      }
      if (!await bcrypt.compare(info.password, user.password)) {
        throw new Error('ERR_PASSWORD_INVALID')
      }
    }

    const userId = user.id

    if (info.password) delete info.password
    if (user.password) delete user.password
    const metadata = { ...info, ...user }
    const ips = extractIps(req)

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

    await this._deleteTokensOfUser(id)

    return true
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
    const tokens = await this._sqlite.allAsync(
      'SELECT * from auth_tokens WHERE userId=?', [userId]
    )

    tokens.forEach(({ token }) => this._lru.remove(lruKeys.goTokens(token)))

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
      }
    ], cb)
  }
}

module.exports = AuthFacility
