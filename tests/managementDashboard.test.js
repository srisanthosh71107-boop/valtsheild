const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { hashValue } = require('../src/services/hashService');
const {
  COOKIE_NAME,
  createManagementSession
} = require('../src/services/managementSessionService');

describe('Sender Management Dashboard Test Suite', () => {
  let server;
  const PORT = 3084;

  const mockDb = {
    secrets: [],
    secret_events: []
  };

  let originalFrom;

  function makeRequest(method, path, body = null, headers = {}) {
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
          path,
          method,
          headers: reqHeaders
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: data
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
    if (supabase) {
      originalFrom = supabase.from.bind(supabase);

      supabase.from = (table) => {
        return {
          insert: async (data) => {
            const rows = Array.isArray(data) ? data : [data];
            if (mockDb[table]) {
              mockDb[table].push(...rows);
            }
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
    }

    server = app.listen(PORT);
  });

  after(() => {
    if (supabase && originalFrom) {
      supabase.from = originalFrom;
    }
    server.close();
  });

  beforeEach(() => {
    mockDb.secrets = [];
    mockDb.secret_events = [];
  });

  test('1. Valid management token creates a session and redirects to clean management URL', async () => {
    const secretId = 'secret_mgmt_token_valid';
    const rawToken = 'my-super-secret-raw-management-token-12345';
    const tokenHash = await hashValue(rawToken);

    mockDb.secrets.push({
      id: secretId,
      management_token_hash: tokenHash,
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const res = await makeRequest('GET', `/manage/${secretId}?token=${rawToken}`);

    // Must be a 302 redirect to clean URL
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, `/manage/${secretId}`);

    // Must set session cookie
    const setCookie = res.headers['set-cookie'];
    assert.ok(setCookie);
    const cookieHeader = Array.isArray(setCookie) ? setCookie[0] : setCookie;
    assert.ok(cookieHeader.includes(COOKIE_NAME));
    assert.ok(cookieHeader.toLowerCase().includes('httponly'));
    assert.ok(cookieHeader.toLowerCase().includes('samesite=strict'));

    // Referrer-Policy must be no-referrer
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
  });

  test('2. Invalid management token shows generic unavailable page', async () => {
    const secretId = 'secret_mgmt_token_invalid';
    const rawToken = 'my-correct-raw-token-1234567890';
    const tokenHash = await hashValue(rawToken);

    mockDb.secrets.push({
      id: secretId,
      management_token_hash: tokenHash,
      status: 'active'
    });

    // Provide incorrect token
    const res = await makeRequest('GET', `/manage/${secretId}?token=wrong-invalid-token-value-99999`);

    assert.equal(res.status, 200);
    assert.ok(res.body.includes('Secure Handover Unavailable'));
    // Never sets session cookie on invalid token
    assert.equal(res.headers['set-cookie'], undefined);
  });

  test('3. Dashboard cannot load without valid session', async () => {
    const secretId = 'secret_mgmt_no_session';
    mockDb.secrets.push({
      id: secretId,
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    // Request dashboard directly with no cookies
    const res = await makeRequest('GET', `/manage/${secretId}`);

    assert.equal(res.status, 200);
    assert.ok(res.body.includes('Secure Handover Unavailable'));
  });

  test('4. Dashboard session cannot access a different secret ID', async () => {
    const secretId1 = 'secret_authorized_1';
    const secretId2 = 'secret_unauthorized_2';

    mockDb.secrets.push(
      {
        id: secretId1,
        status: 'active',
        created_at: new Date().toISOString(),
        available_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_views: 1,
        views_remaining: 1
      },
      {
        id: secretId2,
        status: 'active',
        created_at: new Date().toISOString(),
        available_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        max_views: 1,
        views_remaining: 1
      }
    );

    // Create session specifically for secretId1
    const { sessionToken } = createManagementSession(secretId1);

    // Attempt to access secretId2 with session belonging to secretId1
    const res = await makeRequest('GET', `/manage/${secretId2}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.includes('Secure Handover Unavailable'));
  });

  test('5. Dashboard HTML never contains plaintext secret or hashes', async () => {
    const secretId = 'secret_telemetry_check_5';
    const rawSecret = 'SUPER_SECRET_PLAINTEXT_PAYLOAD_5';
    const rawPass = 'UltraSecurePassphrase!2026';
    const rawCode = '928371';
    const mgmtHash = '$2b$12$mgmtTokenHashToNeverShowInHtml';
    const passHash = '$2b$12$passphraseHashToNeverShowInHtml';
    const codeHash = '$2b$12$accessCodeHashToNeverShowInHtml';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'U2FsdGVkX1+ciphertextNeverShow',
      iv: 'ivNeverShow1234',
      auth_tag: 'tagNeverShow1234',
      passphrase_hash: passHash,
      access_code_hash: codeHash,
      management_token_hash: mgmtHash,
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 2,
      views_remaining: 2
    });

    const { sessionToken } = createManagementSession(secretId);

    const res = await makeRequest('GET', `/manage/${secretId}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });

    assert.equal(res.status, 200);
    const html = res.body;

    // Must contain dashboard title and privacy guarantee
    assert.ok(html.includes('Secure Handover Management'));
    assert.ok(html.includes('This dashboard never displays the secret or recipient credentials.'));

    // Must NEVER contain plaintext secret, ciphertext, IV, auth tag, or any hashes
    assert.ok(!html.includes(rawSecret));
    assert.ok(!html.includes(rawPass));
    assert.ok(!html.includes(rawCode));
    assert.ok(!html.includes('U2FsdGVkX1+ciphertextNeverShow'));
    assert.ok(!html.includes('ivNeverShow1234'));
    assert.ok(!html.includes('tagNeverShow1234'));
    assert.ok(!html.includes(mgmtHash));
    assert.ok(!html.includes(passHash));
    assert.ok(!html.includes(codeHash));
  });

  test('6. Session cookie uses HttpOnly and SameSite=Strict', async () => {
    const secretId = 'secret_cookie_attributes';
    const rawToken = 'raw-token-for-cookie-flags-test-999';
    const tokenHash = await hashValue(rawToken);

    mockDb.secrets.push({
      id: secretId,
      management_token_hash: tokenHash,
      status: 'active'
    });

    const res = await makeRequest('GET', `/manage/${secretId}?token=${rawToken}`);
    const setCookie = res.headers['set-cookie'];
    assert.ok(setCookie);
    const cookieStr = Array.isArray(setCookie) ? setCookie[0] : setCookie;

    assert.ok(cookieStr.toLowerCase().includes('httponly'));
    assert.ok(cookieStr.toLowerCase().includes('samesite=strict'));
    assert.ok(cookieStr.includes('Path=/'));
  });

  test('7. Safe activity timeline renders events', async () => {
    const secretId = 'secret_timeline_test';
    mockDb.secrets.push({
      id: secretId,
      status: 'active',
      created_at: new Date(Date.now() - 3600000).toISOString(),
      available_at: new Date(Date.now() - 3600000).toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    mockDb.secret_events.push(
      {
        secret_id: secretId,
        event_type: 'created',
        created_at: new Date(Date.now() - 3600000).toISOString()
      },
      {
        secret_id: secretId,
        event_type: 'activated',
        created_at: new Date(Date.now() - 1800000).toISOString()
      }
    );

    const { sessionToken } = createManagementSession(secretId);

    const res = await makeRequest('GET', `/manage/${secretId}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.includes('Created'));
    assert.ok(res.body.includes('Activated'));
  });

  test('8. Status-specific messages display correctly for active, scheduled, burned, expired, and revoked', async () => {
    const statuses = [
      { status: 'scheduled', msg: 'The handover will activate at the scheduled time.' },
      { status: 'active', msg: 'This handover remains available until it expires, is revealed, or is revoked.' },
      { status: 'burned', msg: 'The secret was revealed and encrypted data has been permanently removed.' },
      { status: 'expired', msg: 'The handover expired and encrypted data has been removed.' },
      { status: 'revoked', msg: 'The sender permanently revoked this handover.' }
    ];

    for (const item of statuses) {
      const id = `secret_status_${item.status}`;
      mockDb.secrets = [
        {
          id,
          status: item.status,
          created_at: new Date().toISOString(),
          available_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600000).toISOString(),
          max_views: 1,
          views_remaining: item.status === 'active' ? 1 : 0
        }
      ];

      const { sessionToken } = createManagementSession(id);
      const res = await makeRequest('GET', `/manage/${id}`, null, {
        Cookie: `${COOKIE_NAME}=${sessionToken}`
      });

      assert.equal(res.status, 200);
      assert.ok(res.body.includes(item.msg), `Expected status message for ${item.status}`);
    }
  });
});
