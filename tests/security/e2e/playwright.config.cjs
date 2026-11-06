const { defineConfig } = require('@playwright/test');
const path = require('node:path');
const port = process.env.ELFINDER_E2E_PORT || '30871';
module.exports = defineConfig({
  testDir: __dirname,
  testMatch: 'security.spec.cjs',
  timeout: 20000,
  expect: { timeout: 5000 },
  workers: 1,
  retries: 0,
  outputDir: path.resolve(__dirname, '../../../build/test-results'),
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    headless: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    launchOptions: process.env.ELFINDER_CHROMIUM ? { executablePath: process.env.ELFINDER_CHROMIUM } : {}
  },
  projects: [
    { name: 'full-jquery3', metadata: { bundle: 'full', jquery: '3' } },
    { name: 'minimal-jquery3', metadata: { bundle: 'minimal', jquery: '3' } },
    { name: 'full-jquery4', metadata: { bundle: 'full', jquery: '4' } },
    { name: 'minimal-jquery4', metadata: { bundle: 'minimal', jquery: '4' } },
    { name: 'full-minified-jquery4', metadata: { bundle: 'full', jquery: '4', minified: true } },
    { name: 'minimal-minified-jquery4', metadata: { bundle: 'minimal', jquery: '4', minified: true } },
    { name: 'http', testMatch: 'protocol.spec.cjs' }
  ],
  webServer: {
    command: 'node tests/security/e2e/server.cjs',
    cwd: path.resolve(__dirname, '../../..'),
    url: `http://127.0.0.1:${port}/health`,
    reuseExistingServer: false,
    timeout: 15000,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 }
  }
});
