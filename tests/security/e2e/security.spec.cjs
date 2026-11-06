const { test, expect } = require('@playwright/test');

async function initialize(page, metadata) {
  await page.request.get('/login');
  await page.goto(`/?bundle=${metadata.bundle}&jquery=${metadata.jquery}&minified=${metadata.minified ? 1 : 0}`);
  await page.waitForFunction(() => window.fm && fm.cwd() && fm.cwd().hash);
}

async function command(page, data) {
  return page.evaluate(data => new Promise(resolve => {
    fm.request({ data, preventDefault: false, preventFail: true })
      .done(result => resolve({ ok: true, result }))
      .fail(error => resolve({ ok: false, error }));
  }), data);
}

test.beforeEach(async ({ page }, testInfo) => initialize(page, testInfo.project.metadata));

test('initializes the shipped browser client and issues a CSRF header', async ({ page }) => {
  const state = await page.evaluate(() => ({ cwd: fm.cwd().hash, token: fm.customHeaders[fm.csrfHeaderName] }));
  expect(state.cwd).toBe('le2e_Lw');
  expect(state.token).toMatch(/^[a-f0-9]{64}$/);
  await expect(page.locator('.elfinder-cwd-filename').filter({ hasText: 'hello.txt' })).toBeVisible();
});

test('creates renames and deletes through the browser client with a valid token', async ({ page }) => {
  const created = await command(page, { cmd: 'mkdir', target: 'le2e_Lw', name: 'browser-folder' });
  expect(created.ok).toBe(true);
  const hash = created.result.added[0].hash;
  const renamed = await command(page, { cmd: 'rename', target: hash, name: 'renamed-folder' });
  expect(renamed.ok).toBe(true);
  const current = renamed.result.added ? renamed.result.added[0] : renamed.result.changed[0];
  const deleted = await command(page, { cmd: 'rm', targets: [current.hash] });
  expect(deleted.ok).toBe(true);
  await expect(page.locator('.elfinder-cwd-filename').filter({ hasText: 'renamed-folder' })).toHaveCount(0);
});

test('uploads an actual browser File and can download its exact contents', async ({ page }) => {
  const result = await page.evaluate(() => new Promise(resolve => {
    const file = new File(['browser upload content'], 'browser-upload.txt', { type: 'text/plain' });
    fm.upload({ files: [file], type: 'files', target: fm.cwd().hash })
      .done(data => resolve({ ok: true, data }))
      .fail(error => resolve({ ok: false, error }));
  }));
  expect(result.ok).toBe(true);
  const file = result.data.added.find(file => file.name === 'browser-upload.txt');
  expect(file).toBeTruthy();
  const response = await page.request.get(`/connector?cmd=file&target=${encodeURIComponent(file.hash)}&download=1`);
  expect(response.status()).toBe(200);
  expect(await response.text()).toBe('browser upload content');
  expect(response.headers()['content-disposition']).toContain('attachment');
});

test('a direct mutation without CSRF fails without changing the volume', async ({ page }) => {
  const response = await page.request.post('/connector', { form: { cmd: 'mkdir', target: 'le2e_Lw', name: 'without-token' } });
  expect(response.status()).toBe(403);
  expect((await response.json()).csrfReload).toBe(true);
  const listing = await command(page, { cmd: 'open', target: 'le2e_Lw' });
  expect(listing.result.files.some(file => file.name === 'without-token')).toBe(false);
});

test('expired CSRF refreshes without automatically replaying the failed mutation', async ({ page }) => {
  const oldToken = await page.evaluate(() => fm.customHeaders[fm.csrfHeaderName]);
  await page.request.post('/control/expire');
  const failed = await command(page, { cmd: 'mkdir', target: 'le2e_Lw', name: 'expired-request' });
  expect(failed.ok).toBe(false);
  await expect.poll(() => page.evaluate(() => fm.customHeaders[fm.csrfHeaderName])).not.toBe(oldToken);
  const listing = await command(page, { cmd: 'open', target: 'le2e_Lw' });
  expect(listing.result.files.some(file => file.name === 'expired-request')).toBe(false);
  const retry = await command(page, { cmd: 'mkdir', target: 'le2e_Lw', name: 'expired-request' });
  expect(retry.ok).toBe(true);
});

test('untrusted filenames render as text in the file list', async ({ page }) => {
  const response = await page.request.post('/control/seed');
  const names = (await response.json()).names;
  await command(page, { cmd: 'open', target: 'le2e_Lw' });
  for (const name of names) {
    await expect(page.locator('.elfinder-cwd-filename').filter({ hasText: name })).toBeVisible();
  }
  expect(await page.evaluate(() => window.__elfinderXss)).toBe(0);
  await expect(page.locator('.elfinder-cwd-filename img')).toHaveCount(0);
});

test('symlink alias metadata is escaped in the info dialog', async ({ page }, testInfo) => {
  test.skip(testInfo.project.metadata.bundle === 'minimal', 'Minimal bundle does not ship the info command');
  await page.request.post('/control/seed');
  await command(page, { cmd: 'open', target: 'le2e_Lw' });
  await page.evaluate(() => {
    const file = Object.values(fm.files()).find(file => file.name === 'alias.txt');
    fm.exec('info', [file.hash]);
  });
  await expect(page.locator('.elfinder-info-tb')).toBeVisible();
  expect(await page.evaluate(() => window.__elfinderXss)).toBe(0);
  await expect(page.locator('.elfinder-info-tb img')).toHaveCount(0);
});

test('postMessage from an untrusted origin cannot modify the file cache', async ({ page }) => {
  const result = await page.evaluate(() => {
    const target = fm.cwd().hash;
    for (const origin of ['http://127.0.0.1.attacker.invalid', location.origin + '.attacker.invalid', 'null']) {
      window.dispatchEvent(new MessageEvent('message', {
        origin,
        data: JSON.stringify({ type: 'io.studio-42.github', data: { added: [{ hash: 'injected-message', phash: target, name: 'injected-message.txt', mime: 'text/plain', read: 1, write: 1, size: 1 }] } })
      }));
    }
    return !!fm.file('injected-message');
  });
  expect(result).toBe(false);
});

test('playsound rejects markup and path traversal without creating DOM nodes', async ({ page }) => {
  await page.evaluate(() => {
    for (const soundFile of ['../outside.wav', 'x.wav"><img src=x onerror=window.__elfinderXss=1>', 'javascript:alert(1).wav']) {
      fm.trigger('playsound', { soundFile });
    }
  });
  expect(await page.evaluate(() => window.__elfinderXss)).toBe(0);
  await expect(page.locator('audio img')).toHaveCount(0);
});
