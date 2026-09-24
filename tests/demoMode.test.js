const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { hashValue } = require('../src/services/hashService');
const { decryptSecret, generateVerificationToken, hashVerificationToken } = require('../src/services/cryptoService');
const { COOKIE_NAME, createManagementSession } = require('../src/services/managementSessionService');
const { DEMO_SECRET_PLAINTEXT, DEMO_ACCESS_CODE, DEMO_PASSPHRASE } = require('../src/services/demoService');

describe('Demo Mode Test Suite (Step 12)', () => {
  let server;
  const PORT = 3081;

  const mockDb = {
    secrets: [],
    secret_events: [],
    verification_tokens: []
  };

  let originalFrom;
  let originalRpc;

  function makeRequest(method, reqPath, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : null;
      const reqHeaders = {
        ...headers
      };
      if (payload) {
        reqHeaders['Content-Type'] = 'application/json';
        reqHeaders['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: PORT,
          path: reqPath,
          method,
          headers: reqHeaders
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            let json = null;
            try {
              json = JSON.parse(data);
            } catch (e) {
              json = data;
            }
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: json
            });
          });
        }
      );

      req.on('error', reject);
      if (payload) {
        req.write(payload);
      }
      req.end();
    });
  }

  before(async () => {
    process.env.PORT = String(PORT);
    process.env.DEMO_MODE_ENABLED = 'true';
    process.env.NODE_ENV = 'test';

    if (supabase) {
      originalFrom = supabase.from.bind(supabase);
      originalRpc = supabase.rpc ? supabase.rpc.bind(supabase) : null;

      supabase.from = (table) => {
        return {
          insert: async (data) => {
            const rows = Array.isArray(data) ? data : [data];
            if (!mockDb[table]) {
              mockDb[table] = [];
            }
            mockDb[table].push(...rows);
            return { data: rows, error: null };
          },
          select: (fields) => ({
            eq: (col, val) => ({
              order: () => ({
                then: (resolve) => {
                  const filtered = (mockDb[table] || []).filter((r) => r[col] === val);
                  resolve({ data: filtered, error: null });
                }
              }),
              maybeSingle: async () => {
                const found = (mockDb[table] || []).find((r) => r[col] === val);
                if (!found) return { data: null, error: null };
                if (fields && fields !== '*') {
                  const fieldList = fields.split(',').map((f) => f.trim());
                  const resObj = {};
                  fieldList.forEach((f) => {
                    if (found[f] !== undefined) resObj[f] = found[f];
                  });
                  return { data: resObj, error: null };
                }
                return { data: found, error: null };
              },
              then: (resolve) => {
                const filtered = (mockDb[table] || []).filter((r) => r[col] === val);
                resolve({ data: filtered, error: null });
              }
            })
          })
        };
      };

      supabase.rpc = async (funcName, args) => {
        if (funcName === 'reveal_secret_atomically') {
          const { p_secret_id, p_token_hash, p_now } = args;
          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret || secret.status !== 'active' || secret.views_remaining <= 0) {
            return { data: [], error: null };
          }

          const token = (mockDb.verification_tokens || []).find(
            (t) => t.token_hash === p_token_hash && !t.used_at
          );
          if (!token) {
            return { data: [], error: null };
          }
          token.used_at = p_now;

          const isSingleView = secret.max_views === 1;
          const returnedCipher = secret.ciphertext;
          const returnedIv = secret.iv;
          const returnedAuthTag = secret.auth_tag;

          secret.views_remaining = Math.max(0, secret.views_remaining - 1);
          if (isSingleView || secret.views_remaining === 0) {
            secret.status = 'burned';
            secret.ciphertext = null;
            secret.iv = null;
            secret.auth_tag = null;
          }
          secret.revealed_at = p_now;

          return {
            data: [
              {
                secret_id: secret.id,
                ciphertext: returnedCipher,
                iv: returnedIv,
                auth_tag: returnedAuthTag,
                views_remaining: secret.views_remaining,
                status: secret.status,
                max_views: secret.max_views,
                revealed_at: secret.revealed_at
              }
            ],
            error: null
          };
        }
        return { data: null, error: new Error('Unknown RPC') };
      };
    }

    server = http.createServer(app);
    await new Promise((res) => server.listen(PORT, res));
  });

  after(async () => {
    if (supabase) {
      if (originalFrom) supabase.from = originalFrom;
      if (originalRpc) supabase.rpc = originalRpc;
    }
    if (server) {
      await new Promise((res) => server.close(res));
    }
  });

  beforeEach(() => {
    mockDb.secrets = [];
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
    process.env.DEMO_MODE_ENABLED = 'true';
    process.env.NODE_ENV = 'test';
  });

  test('1. Demo routes return 404 when Demo Mode is disabled (DEMO_MODE_ENABLED=false)', async () => {
    process.env.DEMO_MODE_ENABLED = 'false';

    const statusRes = await makeRequest('GET', '/api/demo/status');
    assert.equal(statusRes.status, 404);

    const createRes = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(createRes.status, 404);

    const timelineRes = await makeRequest('GET', '/api/demo/any-id/timeline');
    assert.equal(timelineRes.status, 404);
  });

  test('2. Demo routes return 404 in production mode (NODE_ENV=production) even if DEMO_MODE_ENABLED=true', async () => {
    process.env.NODE_ENV = 'production';
    process.env.DEMO_MODE_ENABLED = 'true';

    const statusRes = await makeRequest('GET', '/api/demo/status');
    assert.equal(statusRes.status, 404);

    const createRes = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(createRes.status, 404);
  });

  test('3. Demo creation endpoint uses DEMO_API_KEY_NOT_REAL only', async () => {
    const res = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(res.status, 200);
    assert.equal(res.body.demo, true);
    assert.ok(res.body.warning);
    assert.ok(res.body.id);
    assert.equal(res.body.access_code, DEMO_ACCESS_CODE);
    assert.equal(res.body.passphrase, DEMO_PASSPHRASE);

    // Verify secret in database
    const dbSecret = mockDb.secrets.find((s) => s.id === res.body.id);
    assert.ok(dbSecret);
    const decrypted = decryptSecret(
      dbSecret.ciphertext,
      dbSecret.iv,
      dbSecret.auth_tag
    );
    assert.equal(decrypted, DEMO_SECRET_PLAINTEXT);
  });

  test('4. Demo secret is encrypted in Supabase with genuine ciphertext, IV, and auth tag', async () => {
    const res = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(res.status, 200);

    const dbSecret = mockDb.secrets.find((s) => s.id === res.body.id);
    assert.ok(dbSecret);
    assert.ok(dbSecret.ciphertext);
    assert.ok(dbSecret.iv);
    assert.ok(dbSecret.auth_tag);

    // Assert plaintext DEMO_API_KEY_NOT_REAL does not appear in database columns
    const secretJson = JSON.stringify(dbSecret);
    assert.equal(secretJson.includes(DEMO_SECRET_PLAINTEXT), false);
  });

  test('5. Demo secret uses access code 123456 and passphrase demo-vault only in local demo response', async () => {
    const res = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(res.status, 200);
    assert.equal(res.body.access_code, '123456');
    assert.equal(res.body.passphrase, 'demo-vault');

    // In DB, access_code and passphrase must be hashed, never plaintext
    const dbSecret = mockDb.secrets.find((s) => s.id === res.body.id);
    assert.notEqual(dbSecret.access_code_hash, '123456');
    assert.notEqual(dbSecret.passphrase_hash, 'demo-vault');
    assert.ok(dbSecret.access_code_hash.startsWith('$2'));
    assert.ok(dbSecret.passphrase_hash.startsWith('$2'));
  });

  test('6. Demo recipient link uses existing bot-safe landing page', async () => {
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(createRes.status, 200);
    const id = createRes.body.id;

    const viewRes = await makeRequest('GET', `/view/${id}`, null, {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    });
    assert.equal(viewRes.status, 200);
    assert.ok(typeof viewRes.body === 'string');
    assert.ok(viewRes.body.includes('VaultLink'));
    // Secret payload must never be revealed on GET /view/:id
    assert.equal(viewRes.body.includes(DEMO_SECRET_PLAINTEXT), false);

    // Check views remaining is still 1
    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.equal(dbSecret.views_remaining, 1);
  });

  test('7. Simulated Slackbot request cannot consume demo secret', async () => {
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(createRes.status, 200);
    const id = createRes.body.id;

    // Extract management session cookie from creation response
    const setCookie = createRes.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : '';

    const simRes = await makeRequest('POST', `/api/demo/${id}/simulate-crawler`, {}, {
      Cookie: cookieHeader
    });

    assert.equal(simRes.status, 200);
    assert.equal(simRes.body.demo, true);
    assert.equal(simRes.body.blocked, true);
    assert.equal(simRes.body.views_remaining, 1);
    assert.equal(simRes.body.message, 'Bot blocked - secret remains protected.');

    // Database check: views_remaining still 1
    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.equal(dbSecret.views_remaining, 1);

    // Audit log check: crawler_blocked event recorded
    const events = mockDb.secret_events.filter((e) => e.secret_id === id);
    const crawlerEvent = events.find((e) => e.event_type === 'crawler_blocked');
    assert.ok(crawlerEvent);
    assert.equal(crawlerEvent.metadata.demo, true);
  });

  test('8. Demo timeline endpoint requires management session authentication', async () => {
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(createRes.status, 200);
    const id = createRes.body.id;

    // Unauthenticated request should 404
    const unauthRes = await makeRequest('GET', `/api/demo/${id}/timeline`);
    assert.equal(unauthRes.status, 404);

    // Authenticated request with session cookie
    const setCookie = createRes.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : '';
    const authRes = await makeRequest('GET', `/api/demo/${id}/timeline`, null, {
      Cookie: cookieHeader
    });
    assert.equal(authRes.status, 200);
    assert.equal(authRes.body.demo, true);
    assert.equal(authRes.body.id, id);
    assert.ok(Array.isArray(authRes.body.journey));
    assert.equal(authRes.body.journey.length, 8);
  });

  test('9. Demo timeline never returns secret, ciphertext, IV, auth tag, or hash fields', async () => {
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    const id = createRes.body.id;
    const setCookie = createRes.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : '';

    const timelineRes = await makeRequest('GET', `/api/demo/${id}/timeline`, null, {
      Cookie: cookieHeader
    });

    assert.equal(timelineRes.status, 200);
    const bodyStr = JSON.stringify(timelineRes.body);

    assert.equal(bodyStr.includes(DEMO_SECRET_PLAINTEXT), false);
    assert.equal(bodyStr.includes('ciphertext'), false);
    assert.equal(bodyStr.includes('auth_tag'), false);
    assert.equal(bodyStr.includes('passphrase_hash'), false);
    assert.equal(bodyStr.includes('access_code_hash'), false);
    assert.equal(bodyStr.includes('management_token_hash'), false);
  });

  test('10. Controlled concurrency test returns exactly 1 success and 19 blocked requests', async () => {
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    const id = createRes.body.id;
    const setCookie = createRes.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : '';

    const concurrencyRes = await makeRequest('POST', `/api/demo/${id}/concurrency-test`, {}, {
      Cookie: cookieHeader
    });

    assert.equal(concurrencyRes.status, 200);
    assert.equal(concurrencyRes.body.total_requests, 20);
    assert.equal(concurrencyRes.body.successful_reveals, 1);
    assert.equal(concurrencyRes.body.blocked_requests, 19);
    assert.equal(concurrencyRes.body.passed, true);
  });

  test('11. Demo concurrency API never returns plaintext secret in response', async () => {
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    const id = createRes.body.id;
    const setCookie = createRes.headers['set-cookie'];
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : '';

    const concurrencyRes = await makeRequest('POST', `/api/demo/${id}/concurrency-test`, {}, {
      Cookie: cookieHeader
    });

    assert.equal(concurrencyRes.status, 200);
    const bodyStr = JSON.stringify(concurrencyRes.body);

    assert.equal(bodyStr.includes('DEMO_CONCURRENCY_TEST_KEY_NOT_REAL'), false);
    assert.equal(bodyStr.includes(DEMO_SECRET_PLAINTEXT), false);
    assert.equal(bodyStr.includes('ciphertext'), false);
  });

  test('12. Real secret ID cannot be used with demo endpoints', async () => {
    // Insert a real secret (not demo)
    const realId = 'real-secret-12345678';
    mockDb.secrets.push({
      id: realId,
      ciphertext: 'fake-real-cipher',
      iv: 'fake-real-iv',
      auth_tag: 'fake-real-tag',
      views_remaining: 1,
      status: 'active'
    });
    // Event without demo: true
    mockDb.secret_events.push({
      secret_id: realId,
      event_type: 'created',
      metadata: { demo: false }
    });

    const session = createManagementSession(realId);
    const realCookie = `${COOKIE_NAME}=${session.sessionToken}`;

    const timelineRes = await makeRequest('GET', `/api/demo/${realId}/timeline`, null, {
      Cookie: realCookie
    });
    assert.equal(timelineRes.status, 404);

    const crawlerRes = await makeRequest('POST', `/api/demo/${realId}/simulate-crawler`, {}, {
      Cookie: realCookie
    });
    assert.equal(crawlerRes.status, 404);

    const concurrencyRes = await makeRequest('POST', `/api/demo/${realId}/concurrency-test`, {}, {
      Cookie: realCookie
    });
    assert.equal(concurrencyRes.status, 404);
  });
});
