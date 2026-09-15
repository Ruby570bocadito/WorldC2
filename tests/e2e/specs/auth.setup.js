// Authentication setup for the console E2E suite.
//
// The console keeps its JWT in localStorage, so every test needs an
// authenticated storage state. This setup project logs in ONCE and saves
// the context state to .auth/operator.json; the `console` project
// declares this one as a dependency and loads the state, which is the
// canonical Playwright auth pattern (fast, and each test still gets an
// isolated context).
const { test: setup, expect } = require('@playwright/test')
const fs = require('fs')
const path = require('path')

const USER = process.env.WORLDC2_USER || 'admin'
const PASS = process.env.WORLDC2_PASS || 'admin'

const STATE_FILE = path.join(__dirname, '..', '.auth', 'operator.json')

setup('authenticate as operator', async ({ page }) => {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true })
  await page.goto('/login')
  await page.fill('input[type="text"]', USER)
  await page.fill('input[type="password"]', PASS)
  await page.click('button[type="submit"]')
  await page.waitForURL((u) => !u.pathname.includes('login'))
  await expect(page.locator('.page-title')).toBeVisible()
  await page.context().storageState({ path: STATE_FILE })
})
