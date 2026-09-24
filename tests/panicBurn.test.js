const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { hashValue } = require('../src/services/hashService');
const { encryptSecret } = require('../src/services/cryptoService');
const {
  COOKIE_NAME,
  createManagementSession
} = require('../src/services/managementSessionService');

describe('Panic Burn Test Suite', () => {
  let server;
  const PORT = 3083;

  const mockDb = {
    secrets: [],
    secret_events: [],
    verification_tokens: []
  };

  let originalFrom;
  let originalRpc;

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
    if (supabase) {
      originalFrom = supabase.from.bind(supabase);
      originalRpc = supabase.rpc ? supabase.rpc.bind(supabase) : null;

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

      // Mock database stored procedures
      supabase.rpc = async (funcName, args) => {
        if (funcName === 'panic_burn_secret_atomically') {
          const { p_secret_id, p_now } = args;
          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret) return { data: [], error: null };

          if (secret.status !== 'scheduled' && secret.status !== 'active') {
            return { data: [], error: null };
          }

          // Cryptographically shred all secret material
          secret.ciphertext = null;
          secret.iv = null;
          secret.auth_tag = null;
          secret.passphrase_hash = null;
          secret.access_code_hash = null;
          secret.status = 'revoked';
          secret.revoked_at = p_now || new Date().toISOString();

          return {
            data: [
              {
                id: secret.id,
                status: 'revoked',
                revoked_at: secret.revoked_at
              }
            ],
            error: null
          };
        }

        if (funcName === 'reveal_secret_atomically') {
          const { p_secret_id } = args;
          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret || secret.status !== 'active') {
            return { data: [], error: null };
          }
          return { data: [], error: null };
        }

        return { data: null, error: new Error(`Unknown RPC ${funcName}`) };
      };
    }

    server = app.listen(PORT);
  });

  after(() => {
    if (supabase && originalFrom) {
      supabase.from = originalFrom;
    }
    if (supabase && originalRpc) {
      supabase.rpc = originalRpc;
    }
    server.close();
  });

  beforeEach(() => {
    mockDb.secrets = [];
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
  });

  test('1. Valid management session can panic-burn active secret', async () => {
    const secretId = 'sec_active_burn_123';
    const encrypted = encryptSecret('super-secret-api-key-999');
    const tokenHash = await hashValue('management-token-raw');

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('MyPassphrase123'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: tokenHash,
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.status, 'revoked');
    assert.equal(res.body.message, 'Secure handover permanently revoked.');
    assert.equal(res.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
  });

  test('2. Valid management session can panic-burn scheduled secret', async () => {
    const secretId = 'sec_scheduled_burn_456';
    const encrypted = encryptSecret('future-handover-data');
    const tokenHash = await hashValue('mgmt-token-scheduled');

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('PassphraseFuture'),
      access_code_hash: await hashValue('654321'),
      management_token_hash: tokenHash,
      status: 'scheduled',
      created_at: new Date().toISOString(),
      available_at: new Date(Date.now() + 3600000).toISOString(),
      expires_at: new Date(Date.now() + 7200000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    // Provide CSRF token in request body
    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      { csrf_token: csrfToken },
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`
      }
    );

    assert.equal(res.status, 200);
    assert.equal(res.body.success, true);
    assert.equal(res.body.status, 'revoked');
  });

  test('3. Panic burn removes ciphertext, IV, auth tag, access-code hash, and passphrase hash', async () => {
    const secretId = 'sec_shred_check_789';
    const encrypted = encryptSecret('confidential-financial-report');

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('ShredPassphrase!'),
      access_code_hash: await hashValue('777888'),
      management_token_hash: await hashValue('mgmt-shred-token'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );

    assert.equal(res.status, 200);

    const storedSecret = mockDb.secrets.find((s) => s.id === secretId);
    assert.ok(storedSecret);
    assert.strictEqual(storedSecret.ciphertext, null);
    assert.strictEqual(storedSecret.iv, null);
    assert.strictEqual(storedSecret.auth_tag, null);
    assert.strictEqual(storedSecret.passphrase_hash, null);
    assert.strictEqual(storedSecret.access_code_hash, null);
    assert.equal(storedSecret.status, 'revoked');
    assert.ok(storedSecret.revoked_at);
  });

  test('4. Panic burn retains safe lifecycle metadata and management-token hash', async () => {
    const secretId = 'sec_metadata_preservation_001';
    const tokenHash = await hashValue('token-to-preserve');
    const createdAt = new Date(Date.now() - 100000).toISOString();
    const availableAt = new Date(Date.now() - 50000).toISOString();
    const expiresAt = new Date(Date.now() + 3600000).toISOString();

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'dummy-cipher',
      iv: 'dummy-iv',
      auth_tag: 'dummy-tag',
      passphrase_hash: 'dummy-hash',
      access_code_hash: 'dummy-code',
      management_token_hash: tokenHash,
      status: 'active',
      created_at: createdAt,
      available_at: availableAt,
      expires_at: expiresAt,
      max_views: 3,
      views_remaining: 3
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );

    assert.equal(res.status, 200);

    const stored = mockDb.secrets.find((s) => s.id === secretId);
    assert.equal(stored.id, secretId);
    assert.equal(stored.management_token_hash, tokenHash);
    assert.equal(stored.created_at, createdAt);
    assert.equal(stored.available_at, availableAt);
    assert.equal(stored.expires_at, expiresAt);
    assert.equal(stored.max_views, 3);
    assert.equal(stored.views_remaining, 3);
    assert.equal(stored.status, 'revoked');
    assert.ok(stored.revoked_at);
  });

  test('5. Revealed/burned secret cannot be panic-burned again', async () => {
    const secretId = 'sec_already_burned';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: null,
      iv: null,
      auth_tag: null,
      passphrase_hash: null,
      access_code_hash: null,
      management_token_hash: await hashValue('mgmt-burned'),
      status: 'burned',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 0
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );

    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'Secure handover unavailable.');
  });

  test('6. Expired secret cannot be panic-burned', async () => {
    const secretId = 'sec_already_expired';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: null,
      iv: null,
      auth_tag: null,
      passphrase_hash: null,
      access_code_hash: null,
      management_token_hash: await hashValue('mgmt-expired'),
      status: 'expired',
      created_at: new Date(Date.now() - 7200000).toISOString(),
      available_at: new Date(Date.now() - 7200000).toISOString(),
      expires_at: new Date(Date.now() - 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );

    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'Secure handover unavailable.');
  });

  test('7. Invalid or missing CSRF token is rejected', async () => {
    const secretId = 'sec_csrf_test_999';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'test',
      status: 'active',
      management_token_hash: 'dummy',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString()
    });

    const { sessionToken } = createManagementSession(secretId);

    // Missing CSRF token
    const resNoCsrf = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`
      }
    );
    assert.equal(resNoCsrf.status, 400);
    assert.equal(resNoCsrf.body.error, 'Secure handover unavailable.');

    // Incorrect CSRF token
    const resBadCsrf = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': 'wrong-csrf-token-abc'
      }
    );
    assert.equal(resBadCsrf.status, 400);
    assert.equal(resBadCsrf.body.error, 'Secure handover unavailable.');
  });

  test('8. After panic burn, verification and reveal return generic unavailable response', async () => {
    const secretId = 'sec_post_burn_checks';
    const accessCode = '654321';
    const passphrase = 'PostBurnPassphrase123!';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'cipher-123',
      iv: 'iv-123',
      auth_tag: 'tag-123',
      passphrase_hash: await hashValue(passphrase),
      access_code_hash: await hashValue(accessCode),
      management_token_hash: await hashValue('token-123'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    // Execute panic burn
    const burnRes = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );
    assert.equal(burnRes.status, 200);

    // Recipient verification must fail with generic error
    const verifyRes = await makeRequest('POST', `/api/secrets/${secretId}/verify`, {
      access_code: accessCode,
      passphrase: passphrase
    });
    assert.equal(verifyRes.status, 400);
    assert.equal(verifyRes.body.error, 'Secure handover unavailable or verification failed.');

    // Reveal must fail with generic 404
    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: 'some-verification-token-12345'
    });
    assert.equal(revealRes.status, 404);
    assert.equal(revealRes.body.error, 'Secret not found, expired, or already destroyed.');

    // Recipient landing page must show generic unavailable
    const viewRes = await makeRequest('GET', `/view/${secretId}`);
    assert.equal(viewRes.status, 200);
    assert.ok(viewRes.body.includes('This secure handover is unavailable, expired, or has already been destroyed.'));
    assert.ok(!viewRes.body.includes('Access Code'));
  });

  test('9. Audit event is created without sensitive values', async () => {
    const secretId = 'sec_audit_check_321';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'cipher-material',
      iv: 'iv-material',
      auth_tag: 'tag-material',
      passphrase_hash: 'pass-hash',
      access_code_hash: 'code-hash',
      management_token_hash: 'mgmt-hash',
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${sessionToken}`,
        'X-CSRF-Token': csrfToken
      }
    );
    assert.equal(res.status, 200);

    const auditEvent = mockDb.secret_events.find(
      (e) => e.secret_id === secretId && e.event_type === 'panic_burned'
    );
    assert.ok(auditEvent, 'Audit event panic_burned must be recorded');
    assert.equal(auditEvent.metadata.source, 'sender_management_dashboard');

    // Verify no secret payload or hashes are leaked in event
    const eventString = JSON.stringify(auditEvent);
    assert.ok(!eventString.includes('cipher-material'));
    assert.ok(!eventString.includes('pass-hash'));
    assert.ok(!eventString.includes('code-hash'));
  });

  test('10. Bot User-Agent cannot panic burn', async () => {
    const secretId = 'sec_bot_burn_attempt';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'secret-cipher',
      status: 'active',
      management_token_hash: 'token-hash',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString()
    });

    const { sessionToken, csrfToken } = createManagementSession(secretId);

    const botAgents = [
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
      'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
      'Twitterbot/1.0',
      'TelegramBot (like TwitterBot)',
      'WhatsApp/2.21.12.21 A',
      'Baiduspider+(+http://www.baidu.com/search/spider.htm)'
    ];

    for (const userAgent of botAgents) {
      const res = await makeRequest(
        'POST',
        `/api/secrets/${secretId}/panic-burn`,
        {},
        {
          Cookie: `${COOKIE_NAME}=${sessionToken}`,
          'X-CSRF-Token': csrfToken,
          'User-Agent': userAgent
        }
      );
      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Secure handover unavailable.');
    }

    // Ensure status remains active
    const stored = mockDb.secrets.find((s) => s.id === secretId);
    assert.equal(stored.status, 'active');
  });

  test('11. Panic burn rejects missing or cross-tenant session cookies', async () => {
    const secretId = 'sec_session_isolation';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'cipher',
      status: 'active',
      management_token_hash: 'hash',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString()
    });

    // 1. Missing cookie
    const resNoCookie = await makeRequest('POST', `/api/secrets/${secretId}/panic-burn`, {});
    assert.equal(resNoCookie.status, 400);

    // 2. Cookie belonging to a different secret ID
    const otherSession = createManagementSession('sec_different_id_999');
    const resOtherSession = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${otherSession.sessionToken}`,
        'X-CSRF-Token': otherSession.csrfToken
      }
    );
    assert.equal(resOtherSession.status, 400);

    // 3. Invalid ID format in path
    const resInvalidId = await makeRequest(
      'POST',
      `/api/secrets/invalid!id/panic-burn`,
      {},
      {
        Cookie: `${COOKIE_NAME}=${otherSession.sessionToken}`,
        'X-CSRF-Token': otherSession.csrfToken
      }
    );
    assert.equal(resInvalidId.status, 400);
  });
});
