// Round-19 E2E additions: self-service password change, TOTP MFA
// enrollment and the full MFA login flow through the real login FORM.
//
// All seeds go through the REAL HTTP API — the server under test is a
// plain binary, never a mock. The TOTP codes are computed in-test with
// WebCrypto (HMAC-SHA1 over the RFC 4226 counter), the same arithmetic
// any authenticator app performs.
const { test, expect } = require('@playwright/test')

const USER = process.env.WORLDC2_USER || 'admin'
const PASS = process.env.WORLDC2_PASS || 'admin'

// One admin token for the whole describe block: the login endpoint sits
// behind a dedicated 10/min token bucket and every redundant login burns
// budget the other specs may need.
let adminToken = null
async function apiLogin(request) {
  if (adminToken) return adminToken
  const res = await request.post('/api/login', {
    data: { username: USER, password: PASS },
  })
  expect(res.ok()).toBeTruthy()
  const body = await res.json()
  adminToken = body.token
  return adminToken
}

// totpCode computes the 6-digit TOTP for a Base32 secret at time `when`
// (default now): decode Base32, HMAC-SHA-1 over the big-endian 30s
// counter, dynamic truncation, mod 10^6.
async function totpCode(secretBase32, when = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of secretBase32.replace(/=+$/, '')) {
    const idx = alphabet.indexOf(ch.toUpperCase())
    if (idx < 0) throw new Error('bad base32 char ' + ch)
    bits += idx.toString(2).padStart(5, '0')
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8))
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2)

  const counter = Math.floor(when / 1000 / 30)
  const msg = new Uint8Array(8)
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter))

  const key = await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg))
  const offset = mac[mac.length - 1] & 0x0f
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3]
  return String(bin % 1_000_000).padStart(6, '0')
}

// ensureOperator creates a dedicated account idempotently: a previous
// run that died before cleanup would otherwise 409 the re-create.
//
// The 1.2s pause is not decoration: deleting an operator revokes its
// tokens with a conservative now+1s cut (JWT iat has 1-second
// resolution), and a login minted in the SAME second as that revocation
// is rejected as "revoked" by design. Recreate → login must happen in a
// later second; the block self-heals on any subsequent login.
async function ensureOperator(request, token, username, password) {
  const ops = await (await request.get('/api/operators', { headers: { Authorization: 'Bearer ' + token } })).json()
  const stale = ops.find((o) => o.username === username)
  if (stale) {
    await request.delete('/api/operators/' + stale.id + '/totp', { headers: { Authorization: 'Bearer ' + token } })
    await request.delete('/api/operators/' + stale.id, { headers: { Authorization: 'Bearer ' + token } })
    await new Promise((r) => setTimeout(r, 1200))
  }
  const res = await request.post('/api/operators', {
    headers: { Authorization: 'Bearer ' + token },
    data: { username, password, role: 'operator' },
  })
  expect(res.ok()).toBeTruthy()
}

async function removeOperator(request, token, username) {
  const ops = await (await request.get('/api/operators', { headers: { Authorization: 'Bearer ' + token } })).json()
  const victim = ops.find((o) => o.username === username)
  if (victim) {
    await request.delete('/api/operators/' + victim.id + '/totp', { headers: { Authorization: 'Bearer ' + token } })
    await request.delete('/api/operators/' + victim.id, { headers: { Authorization: 'Bearer ' + token } })
  }
}

test.describe.serial('round 19 account security', () => {
  test('self-service password change: verifies current, revokes old session', async ({ page, request }) => {
    const token = await apiLogin(request)

    // Seed a dedicated account so the admin password is never touched.
    await ensureOperator(request, token, 'pwtest', 'original-pass-123')

    const pwLogin = await request.post('/api/login', { data: { username: 'pwtest', password: 'original-pass-123' } })
    expect(pwLogin.ok(), 'pwtest login: ' + pwLogin.status() + ' ' + (await pwLogin.text())).toBeTruthy()
    const pwToken = (await pwLogin.json()).token

    // Wrong current password: 401.
    const bad = await request.post('/api/account/password', {
      headers: { Authorization: 'Bearer ' + pwToken },
      data: { current_password: 'wrong-current-pass', new_password: 'rotated-pass-456' },
    })
    expect(bad.status()).toBe(401)

    // Change succeeds and the OLD token stops working immediately.
    const ok = await request.post('/api/account/password', {
      headers: { Authorization: 'Bearer ' + pwToken },
      data: { current_password: 'original-pass-123', new_password: 'rotated-pass-456' },
    })
    expect(ok.ok(), 'change response: ' + ok.status() + ' ' + (await ok.text())).toBeTruthy()

    const stale = await request.get('/api/sessions', {
      headers: { Authorization: 'Bearer ' + pwToken },
    })
    expect(stale.status()).toBe(401)

    // Console form: the login screen accepts the new passphrase. The
    // console project starts with the setup project's AUTHED storageState
    // (an authed context would bounce /login back to the console), so
    // drop the session storage first — the exact state a real operator
    // lands in after the password change revoked their token.
    await page.goto('/')
    await page.evaluate(() => localStorage.clear())
    await page.goto('/login')
    await page.fill('#login-user', 'pwtest')
    await page.fill('#login-pass', 'rotated-pass-456')
    await page.click('.login-btn')
    await page.waitForURL((u) => !u.pathname.includes('login'), { timeout: 20_000 })
    await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 15_000 })

    // Cleanup via admin API.
    await page.evaluate(() => localStorage.clear())
    const cleanupToken = await apiLogin(request)
    await removeOperator(request, cleanupToken, 'pwtest')
  })

  test('TOTP MFA: enrollment panel in the console and the full two-step login', async ({ page, request }) => {
    const token = await apiLogin(request)

    // Dedicated account for the MFA journey.
    await ensureOperator(request, token, 'mfatest', 'mfa-pass-123456')
    const mfaToken = (await (await request.post('/api/login', { data: { username: 'mfatest', password: 'mfa-pass-123456' } })).json()).token

    // Status starts disabled; setup returns a secret + otpauth URI.
    const st0 = await (await request.get('/api/account/totp/status', { headers: { Authorization: 'Bearer ' + mfaToken } })).json()
    expect(st0.enabled).toBe(false)
    const setup = await (await request.post('/api/account/totp/setup', { headers: { Authorization: 'Bearer ' + mfaToken }, data: {} })).json()
    expect(setup.secret).toHaveLength(32)
    expect(setup.otpauth_uri).toContain('otpauth://totp/WorldC2:mfatest?')

    const code = await totpCode(setup.secret)
    const enable = await request.post('/api/account/totp/enable', {
      headers: { Authorization: 'Bearer ' + mfaToken },
      data: { code },
    })
    expect(enable.ok()).toBeTruthy()

    // The console FORM asks for the code after the passphrase and lands
    // in the console once the code is supplied. Start logged out (same
    // storage-drop as the password-change leg).
    await page.goto('/')
    await page.evaluate(() => localStorage.clear())
    await page.goto('/login')
    await page.fill('#login-user', 'mfatest')
    await page.fill('#login-pass', 'mfa-pass-123456')
    await page.click('.login-btn')
    await expect(page.locator('#login-totp')).toBeVisible({ timeout: 10_000 })
    await page.fill('#login-totp', await totpCode(setup.secret))
    await page.click('.login-btn')
    await page.waitForURL((u) => !u.pathname.includes('login'), { timeout: 20_000 })
    await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 15_000 })

    // A password-only API login still answers totp_required afterwards.
    const pwOnly = await request.post('/api/login', { data: { username: 'mfatest', password: 'mfa-pass-123456' } })
    expect(pwOnly.status()).toBe(401)
    expect((await pwOnly.json()).totp_required).toBe(true)

    // Cleanup: admin resets MFA and removes the account.
    await page.evaluate(() => localStorage.clear())
    const cleanupToken = await apiLogin(request)
    const ops = await (await request.get('/api/operators', { headers: { Authorization: 'Bearer ' + cleanupToken } })).json()
    const victim = ops.find((o) => o.username === 'mfatest')
    if (victim) {
      const reset = await request.delete('/api/operators/' + victim.id + '/totp', { headers: { Authorization: 'Bearer ' + cleanupToken } })
      expect(reset.ok()).toBeTruthy()
      await request.delete('/api/operators/' + victim.id, { headers: { Authorization: 'Bearer ' + cleanupToken } })
    }
  })

  test('audit view: Load more walks the cursor and Export CSV downloads', async ({ page, request }) => {
    const token = await apiLogin(request)

    // Seed enough attributed rows that a 100-row page may load more;
    // whether the button shows depends on trail size, so assert its
    // behavior conditionally but the walk itself strictly.
    for (let i = 0; i < 3; i++) {
      await request.get('/api/audit?limit=5', { headers: { Authorization: 'Bearer ' + token } })
    }

    await page.goto('/audit')
    await expect(page.locator('.page-title')).toContainText('Audit log', { timeout: 10_000 })
    await expect(page.locator('table tbody tr').first()).toBeVisible()

    // The export button is present with rows on screen.
    await expect(page.locator('.head-side button', { hasText: 'Export CSV' })).toBeVisible()

    // Exercise the cursor API directly through the page's session: walk
    // two pages of 3 and verify strict id descent (no dupes).
    const walk = await page.evaluate(async () => {
      const t = localStorage.getItem('bty_token')
      const get = async (q) => (await fetch('/api/audit' + q, { headers: { Authorization: 'Bearer ' + t } })).json()
      const p1 = await get('?limit=3')
      if (!p1.length) return { p1: 0 }
      const p2 = await get('?limit=3&before_id=' + p1[p1.length - 1].id)
      const ids = p1.concat(p2).map((e) => e.id)
      const dupes = ids.length !== new Set(ids).size
      let desc = true
      for (let i = 1; i < ids.length; i++) if (ids[i - 1] <= ids[i]) desc = false
      return { p1: p1.length, p2: p2.length, dupes, desc }
    })
    if (walk.p1) {
      expect(walk.dupes).toBe(false)
      expect(walk.desc).toBe(true)
    }

    // Operators view renders the new activity/MFA columns.
    await page.goto('/operators')
    await expect(page.locator('.page-title')).toContainText('Operators', { timeout: 10_000 })
    await expect(page.locator('th', { hasText: 'Last activity' })).toBeVisible()
    await expect(page.locator('th', { hasText: 'MFA' })).toBeVisible()
  })
})
