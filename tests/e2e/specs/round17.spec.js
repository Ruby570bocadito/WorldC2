// Round-17 E2E additions: audit log view, Files CSV export + ConfirmModal
// adoption, and the Dashboard SIEM webhook health panel.
//
// All seeds go through the REAL HTTP API (the same calls the console makes),
// never through test hooks — the server under test is a plain binary.
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

test.describe.serial('round 17 console surface', () => {
  test('audit log view renders live entries and its filters work', async ({ page }) => {
    await page.goto('/audit')
    await expect(page.locator('.page-title')).toHaveText(/Audit log/i)

    // The trail is never empty on a live server: this very navigation plus
    // the login flow just wrote api_call/auth_success rows.
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 15_000 })

    // Action filter select is populated from real entries.
    await expect(page.locator('select[aria-label="Action filter"]')).toBeVisible()

    // Search filter: a nonsense term collapses to the empty state; clearing
    // it brings the rows back.
    await page.fill('input[aria-label="Filter audit entries"]', 'no-such-detail-' + Date.now())
    await expect(page.locator('.empty-state')).toBeVisible({ timeout: 5_000 })
    await page.fill('input[aria-label="Filter audit entries"]', '')
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 5_000 })
  })

  test('files: export appears with rows and the purge confirms in two steps', async ({ page, request }) => {
    await page.goto('/files')
    await expect(page.locator('.page-title')).toHaveText(/Files/i)

    // Empty listing: no export button, the empty state explains itself.
    await expect(page.locator('.empty-state').first()).toBeVisible()
    await expect(page.locator('button:has-text("Export CSV")')).toHaveCount(0)

    // Seed one loot record through the real API — the exact POST the
    // exfil path uses (session_id is a stand-in; the discard server does
    // not care that no agent row backs it).
    const token = await apiLogin(request)
    const store = await request.post('/api/files', {
      headers: { Authorization: 'Bearer ' + token },
      data: {
        session_id: 'e2e-sess',
        filename: 'e2e-report.bin',
        module: 'e2e',
        data: 'aGk=',
      },
    })
    expect(store.ok()).toBeTruthy()

    await page.reload()
    const row = page.locator('td.mono.fw', { hasText: 'e2e-report.bin' })
    await expect(row).toBeVisible({ timeout: 10_000 })

    const exportBtn = page.locator('button:has-text("Export CSV")')
    await expect(exportBtn).toBeEnabled()
    const [download] = await Promise.all([page.waitForEvent('download'), exportBtn.click()])
    expect(download.suggestedFilename()).toMatch(/^worldc2-files-\d{4}-\d{2}-\d{2}\.csv$/)

    // Purge uses the shared ConfirmModal: Esc cancels and the row stays.
    await page.locator('tr', { hasText: 'e2e-report.bin' }).locator('button[aria-label="Purge file"]').click()
    const modal = page.locator('[role="alertdialog"]')
    await expect(modal).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(modal).toBeHidden()
    await expect(row).toBeVisible()
  })

  test('dashboard surfaces the SIEM webhook health panel for admins', async ({ page, request }) => {
    // Register a webhook through the real API (a dead port is fine — the
    // panel shows the ledger, and a failed delivery is honest data too).
    const token = await apiLogin(request)
    const hook = await request.post('/api/webhooks', {
      headers: { Authorization: 'Bearer ' + token },
      data: {
        url: 'http://127.0.0.1:9/e2e-noop',
        timeout_ms: 500,
        events: ['operator_login'],
      },
    })
    expect(hook.ok()).toBeTruthy()

    await page.goto('/')
    const panel = page.locator('.panel-title', { hasText: 'SIEM webhook health' })
    await expect(panel).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('.wh-row').first()).toBeVisible()
  })
})
