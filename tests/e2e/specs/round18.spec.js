// Round-18 E2E additions: command palette (Ctrl+K), audit operator
// attribution column/filter and the webhook test-delivery button.
//
// All seeds go through the REAL HTTP API — the server under test is a
// plain binary, never a mock.
const { test, expect } = require('@playwright/test')

const USER = process.env.WORLDC2_USER || 'admin'
const PASS = process.env.WORLDC2_PASS || 'admin'

// apiLogin returns a Bearer token from the real /api/login endpoint.
async function apiLogin(request) {
  const res = await request.post('/api/login', {
    data: { username: USER, password: PASS },
  })
  expect(res.ok()).toBeTruthy()
  const body = await res.json()
  return body.token
}

test.describe.serial('round 18 console surface', () => {
  test('command palette opens with Ctrl+K, filters and navigates', async ({ page }) => {
    await page.goto('/')
    await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 15_000 })

    // Ctrl+K opens the palette and focuses its input.
    await page.keyboard.press('Control+k')
    const dialog = page.locator('.palette')
    await expect(dialog).toBeVisible()
    await expect(page.locator('.palette-input')).toBeFocused()

    // Every navigable view is offered, plus the logout action.
    await expect(dialog.locator('.palette-item')).not.toHaveCount(0)
    await expect(dialog.locator('.palette-item', { hasText: 'Dashboard' })).toBeVisible()
    await expect(dialog.locator('.palette-item', { hasText: 'Logout' })).toBeVisible()

    // Typing filters the list down to matching entries.
    await page.fill('.palette-input', 'vault')
    const items = dialog.locator('.palette-item')
    await expect(items).toHaveCount(1)
    await expect(items.first()).toContainText(/Credential Vault|Vault/i)

    // Enter navigates: the Vault view must render.
    await page.keyboard.press('Enter')
    await expect(dialog).toBeHidden()
    await expect(page).toHaveURL(/\/vault$/)
    await expect(page.locator('.page-title')).toContainText(/Vault/i, { timeout: 10_000 })

    // Escape closes the palette after reopening.
    await page.keyboard.press('Control+k')
    await expect(dialog).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(dialog).toBeHidden()
  })

  test('audit view shows the operator column and the user filter queries the API', async ({ page, request }) => {
    const token = await apiLogin(request)

    // Seed a distinct action so this test's trail rows are identifiable.
    const seed = await request.get('/api/audit?limit=5', {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(seed.ok()).toBeTruthy()
    const entries = await seed.json()
    expect(Array.isArray(entries)).toBeTruthy()
    // Attribution contract over the API the console consumes.
    expect(entries.length).toBeGreaterThan(0)
    expect(entries[0]).toHaveProperty('operator')
    expect(entries[0]).toHaveProperty('action')

    await page.goto('/audit')
    await expect(page.locator('.page-title')).toHaveText(/Audit log/i)

    // The operator column renders attributed rows with a pill, system
    // rows with the muted "system" marker.
    await expect(page.locator('th', { hasText: 'Operator' })).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('.op-pill, td >> text=system').first()).toBeVisible()

    // The server-side operator filter drives the request: pick the admin
    // select option and assert the API received ?user=.
    const reqPromise = page.waitForRequest((r) => r.url().includes('/api/audit') && r.url().includes('user=admin'))
    await page.selectOption('select[aria-label="Operator filter"]', 'admin')
    const req = await reqPromise
    expect(req).toBeTruthy()
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 10_000 })
  })

  test('webhook test button reports the delivery outcome and updates the ledger', async ({ page, request }) => {
    const token = await apiLogin(request)

    // Register a destination pointing at a dead port — the test button
    // must answer honestly with delivered:false, not hide the failure.
    const whRes = await request.post('/api/webhooks', {
      headers: { Authorization: `Bearer ${token}` },
      data: { url: 'http://127.0.0.1:1/e2e-sink', timeout_ms: 1000 },
    })
    expect(whRes.status()).toBe(201)
    const whBody = await whRes.json()
    const webhookId = whBody.id

    await page.goto('/webhooks')
    await expect(page.locator('.page-title')).toHaveText(/Webhooks/i)

    const row = page.locator('tr', { hasText: 'e2e-sink' })
    await expect(row).toBeVisible({ timeout: 15_000 })

    // Click the send icon and expect the honest failure notification.
    await row.locator('button[aria-label="Send test event"]').click()
    await expect(page.locator('.toast-error, .toast', { hasText: /Test failed/i }).first())
      .toBeVisible({ timeout: 15_000 })

    // The attempt folded into the ledger the row renders.
    await expect(row.locator('.stat-badge.fail')).toBeVisible({ timeout: 15_000 })

    // Cleanup through the real API.
    const del = await request.delete('/api/webhooks?id=' + webhookId, {
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(del.ok()).toBeTruthy()
  })
})
