const { test, expect, request: playwrightRequest } = require('@playwright/test');

async function session(request) {
  await request.get('/login');
  const response = await request.get('/connector?cmd=open&init=1');
  expect(response.status()).toBe(200);
  return (await response.json()).csrf;
}

async function chunk(request, token, options) {
  const response = await request.post('/connector', {
    headers: { 'X-elFinder-CSRF': token },
    multipart: {
      cmd: 'upload', target: options.target || 'le2e_Lw', cid: String(options.cid || 12345),
      chunk: `${options.name || 'chunked.txt'}.${options.index || 0}_${options.last === undefined ? 1 : options.last}.part`,
      range: options.range,
      'upload[]': { name: 'blob', mimeType: 'application/octet-stream', buffer: Buffer.from(options.data || 'abc') }
    }
  });
  expect(response.status()).toBe(200);
  return response.json();
}

async function commit(request, token, merged, name, target = 'le2e_Lw') {
  const response = await request.post('/connector', {
    headers: { 'X-elFinder-CSRF': token },
    form: { cmd: 'upload', target, chunk: merged, 'upload[]': name }
  });
  return response.json();
}

test('HTTP connector requires authentication before the CSRF handshake', async ({ request }) => {
  expect((await request.get('/connector?cmd=open&init=1')).status()).toBe(401);
  const token = await session(request);
  expect(token).toMatch(/^[a-f0-9]{64}$/);
});

test('real multipart chunks assemble and commit exact data', async ({ request }) => {
  const token = await session(request);
  const first = await chunk(request, token, { range: '0,3,6' });
  expect(first._chunkmerged).toBeUndefined();
  const second = await chunk(request, token, { index: 1, range: '3,3,6', data: 'def' });
  expect(second._chunkmerged).toBeTruthy();
  const result = await commit(request, token, second._chunkmerged, 'chunked.txt');
  expect(result.error || result.warning).toBeUndefined();
  const file = result.added.find(file => file.name === 'chunked.txt');
  expect(await (await request.get(`/connector?cmd=file&download=1&target=${file.hash}`)).text()).toBe('abcdef');
});

test('duplicate chunks do not count as distinct completed ranges', async ({ request }) => {
  const token = await session(request);
  await chunk(request, token, { name: 'duplicate.txt', range: '0,3,6' });
  const duplicate = await chunk(request, token, { name: 'duplicate.txt', range: '0,3,6' });
  expect(duplicate._chunkmerged).toBeUndefined();
  const last = await chunk(request, token, { name: 'duplicate.txt', index: 1, range: '3,3,6', data: 'def' });
  expect(last._chunkmerged).toBeTruthy();
});

test('malformed and inconsistent chunk ranges are rejected', async ({ request }) => {
  const token = await session(request);
  for (const range of ['not-a-range', '7,3,6', '0,4,6', '0,0,6', '0,3,0']) {
    const result = await chunk(request, token, { name: range.replace(/[^a-z0-9]/g, '') + '.txt', range, last: 0 });
    expect(result._chunkmerged).toBeUndefined();
    expect(result.error).toBeTruthy();
  }
});

test('declared chunk total is checked against the volume upload limit', async ({ request }) => {
  const token = await session(request);
  const result = await chunk(request, token, { name: 'oversized.txt', range: '0,3,1000000' });
  expect(result.error).toBeTruthy();
  expect(result._chunkmerged).toBeUndefined();
});

test('sessions with identical chunk identifiers cannot mix upload content', async ({ request, baseURL }) => {
  const token = await session(request);
  const other = await playwrightRequest.newContext({ baseURL });
  try {
    const otherToken = await session(other);
    await chunk(request, token, { name: 'shared-id.txt', range: '0,3,6', data: 'AAA' });
    const foreign = await chunk(other, otherToken, { name: 'shared-id.txt', index: 1, range: '3,3,6', data: 'BBB' });
    expect(foreign._chunkmerged).toBeUndefined();
    const own = await chunk(request, token, { name: 'shared-id.txt', index: 1, range: '3,3,6', data: 'CCC' });
    expect(own._chunkmerged).toBeTruthy();
    const result = await commit(request, token, own._chunkmerged, 'shared-id.txt');
    const file = result.added[0];
    expect(await (await request.get(`/connector?cmd=file&download=1&target=${file.hash}`)).text()).toBe('AAACCC');
  } finally { await other.dispose(); }
});

test('a completed upload cannot be stolen or deleted by another session', async ({ request, baseURL }) => {
  const token = await session(request);
  const own = await chunk(request, token, { name: 'private.txt', range: '0,3,3', last: 0, data: 'KEY' });
  expect(own._chunkmerged).toBeTruthy();
  const other = await playwrightRequest.newContext({ baseURL });
  try {
    const otherToken = await session(other);
    const foreign = await commit(other, otherToken, own._chunkmerged, 'private.txt');
    expect(foreign.error || foreign.warning).toBeTruthy();
    expect(foreign.added || []).toHaveLength(0);
    const result = await commit(request, token, own._chunkmerged, 'private.txt');
    expect(result.error || result.warning).toBeUndefined();
    expect(result.added[0].name).toBe('private.txt');
  } finally { await other.dispose(); }
});

test('chunked commit still enforces destination MIME policy', async ({ request }) => {
  const token = await session(request);
  const binary = Buffer.from([0, 1, 2, 3, 4]);
  const assembled = await chunk(request, token, { target: 'lsecond_Lw', name: 'payload.php', range: '0,5,5', last: 0, data: binary });
  const result = await commit(request, token, assembled._chunkmerged, 'payload.php', 'lsecond_Lw');
  expect(result.error || result.warning).toBeTruthy();
  expect(result.added || []).toHaveLength(0);
});

test('browser-initiated editor methods require CSRF and disabled plugins cannot execute', async ({ request }) => {
  const token = await session(request);
  const form = { cmd: 'editor', name: 'DisabledFixture', method: 'init' };
  const unprotected = await request.post('/connector', { form });
  expect(unprotected.status()).toBe(403);
  const protectedResponse = await request.post('/connector', { headers: { 'X-elFinder-CSRF': token }, form });
  const body = await protectedResponse.json();
  expect(body.disabledPluginExecuted).toBeUndefined();
  expect(body.error).toBeTruthy();
});

test('signed editor callbacks reach their signature check without a browser CSRF token', async ({ request }) => {
  await session(request);
  const response = await request.post('/connector', { form: { cmd: 'editor', name: 'ZohoOffice', method: 'save' } });
  expect(response.status()).toBe(403);
  expect(await response.text()).toBe(''); // Zoho's signature rejection, not a CSRF JSON response.
});
