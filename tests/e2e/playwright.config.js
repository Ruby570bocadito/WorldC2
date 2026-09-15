// Playwright configuration for the WorldC2 console E2E suite.
//
// The suite drives a REAL server: start one (see README.md in this
// directory) and point WORLDC2_BASE_URL at it. Everything is
// configurable through environment variables so CI and local runs use
// the same code path:
//
//   WORLDC2_BASE_URL  console origin          (default http://127.0.0.1:19090)
//   WORLDC2_USER      operator username       (default admin)
//   WORLDC2_PASS      operator password       (default admin)
//
const { defineConfig, devices } = require('@playwright/test')
const path = require('path')

const BASE_URL = process.env.WORLDC2_BASE_URL || 'http://127.0.0.1:19090'
const AUTH_STATE = path.join(__dirname, '.auth', 'operator.json')

module.exports = defineConfig({
  testDir: './specs',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 900 },
  },
  projects: [
    {
      // Logs in once and writes .auth/operator.json (localStorage JWT).
      name: 'setup',
      testMatch: /auth\.setup\.js/,
    },
    {
      // The console flows — every test starts authenticated.
      name: 'console',
      testMatch: /critical-flow\.spec\.js/,
      dependencies: ['setup'],
      use: { storageState: AUTH_STATE },
    },
  ],
})
