const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { nanoid } = require('nanoid');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const {
  encryptSecret,
  decryptSecret,
  generateVerificationToken,
  hashVerificationToken,
  generateAcknowledgementToken,
  hashAcknowledgementToken,
  generateManagementToken
} = require('../src/services/cryptoService');
const { hashValue, compareValue } = require('../src/services/hashService');
const {
  COOKIE_NAME,
  createManagementSession
} = require('../src/services/managementSessionService');
const { runLifecycleMaintenance } = require('../src/services/lifecycleSweeperService');

describe('Security Hardening & 24 Core Verifications (Step 13)', () => {
  let server;
  const PORT = 3079;

  const mockDb = {
    secrets: [],
    secret_events: [],
    verification_tokens: [],
    acknowledgement_tokens: []
  };

  let originalFrom;
  let originalRpc;

  function makeRequest(method, reqPath, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : null;
      const reqHeaders = { ...headers };
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
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            let json = null;
            try {
              json = JSON.parse(data);
            } catch {
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
      if (payload) req.write(payload);
      req.end();
    });
  }

  before(async () => {
    process.env.PORT = String(PORT);
    process.env.NODE_ENV = 'test';
    process.env.DEMO_MODE_ENABLED = 'true';

    if (supabase) {
      originalFrom = supabase.from.bind(supabase);
      originalRpc = supabase.rpc ? supabase.rpc.bind(supabase) : null;

      supabase.from = (table) => ({
        insert: async (data) => {
          const rows = Array.isArray(data) ? data : [data];
          if (!mockDb[table]) mockDb[table] = [];
          mockDb[table].push(...rows);
          return { data: rows, error: null };
        },
        update: (updates) => ({
          eq: async (col, val) => {
            const rows = (mockDb[table] || []).filter((r) => r[col] === val);
            rows.forEach((r) => Object.assign(r, updates));
            return { data: rows, error: null };
          }
        }),
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
          }),
          then: (resolve) => {
            resolve({ data: mockDb[table] || [], error: null });
          }
        })
      });

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
          if (!token) return { data: [], error: null };
          token.used_at = p_now;

          const isSingle = secret.max_views === 1;
          const cipher = secret.ciphertext;
          const iv = secret.iv;
          const tag = secret.auth_tag;

          secret.views_remaining = Math.max(0, secret.views_remaining - 1);
          if (isSingle || secret.views_remaining === 0) {
            secret.status = 'burned';
            secret.ciphertext = null;
            secret.iv = null;
            secret.auth_tag = null;
          }
          secret.revealed_at = p_now;

          return {
            data: [{
              secret_id: secret.id,
              ciphertext: cipher,
              iv,
              auth_tag: tag,
              views_remaining: secret.views_remaining,
              status: secret.status,
              max_views: secret.max_views,
              revealed_at: secret.revealed_at
            }],
            error: null
          };
        }
        if (funcName === 'panic_burn_secret_atomically') {
          const { p_secret_id, p_now } = args;
          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret || secret.status === 'burned' || secret.status === 'revoked' || secret.status === 'expired') {
            return { data: [], error: null };
          }
          secret.status = 'revoked';
          secret.ciphertext = null;
          secret.iv = null;
          secret.auth_tag = null;
          secret.passphrase_hash = null;
          secret.access_code_hash = null;
          secret.revoked_at = p_now;
          return {
            data: [{
              id: secret.id,
              status: 'revoked',
              revoked_at: secret.revoked_at
            }],
            error: null
          };
        }
        if (funcName === 'acknowledge_secret_atomically') {
          const { p_secret_id, p_token_hash, p_now } = args;
          const token = (mockDb.acknowledgement_tokens || []).find(
            (t) => t.secret_id === p_secret_id && t.token_hash === p_token_hash && !t.used_at
          );
          if (!token) return { data: [], error: null };
          token.used_at = p_now;

          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret) return { data: [], error: null };
          secret.acknowledged_at = p_now;

          return {
            data: [{
              secret_id: secret.id,
              acknowledged_at: secret.acknowledged_at
            }],
            error: null
          };
        }
        if (funcName === 'maintain_secret_lifecycle') {
          const nowStr = args.p_now || new Date().toISOString();
          const nowTime = new Date(nowStr).getTime();
          const activatedList = [];
          const expiredList = [];

          mockDb.secrets.forEach((s) => {
            if (s.status === 'scheduled' && new Date(s.available_at).getTime() <= nowTime) {
              s.status = 'active';
              activatedList.push(s.id);
            }
            if ((s.status === 'active' || s.status === 'scheduled') && new Date(s.expires_at).getTime() <= nowTime) {
              s.status = 'expired';
              s.ciphertext = null;
              s.iv = null;
              s.auth_tag = null;
              s.passphrase_hash = null;
              s.access_code_hash = null;
              expiredList.push(s.id);
            }
          });
          return { data: [{ activated_ids: activatedList, expired_ids: expiredList }], error: null };
        }
        return { data: null, error: null };
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
    if (server) await new Promise((res) => server.close(res));
  });

  beforeEach(() => {
    mockDb.secrets = [];
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
    mockDb.acknowledgement_tokens = [];
    process.env.DEMO_MODE_ENABLED = 'true';
    process.env.NODE_ENV = 'test';
  });

  // 1. Server startup validation
  test('1. Server startup validation', async () => {
    const res = await makeRequest('GET', '/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'ok');
    assert.equal(res.body.app, 'VaultLink Secure Handover Room');
  });

  // 2. AES-256-GCM encrypt/decrypt
  test('2. AES-256-GCM encrypt/decrypt', () => {
    const plaintext = 'TEST_SECRET_NOT_REAL';
    const enc = encryptSecret(plaintext);
    assert.ok(enc.ciphertext);
    assert.ok(enc.iv);
    assert.ok(enc.authTag);
    const decrypted = decryptSecret(enc.ciphertext, enc.iv, enc.authTag);
    assert.equal(decrypted, plaintext);
  });

  // 3. Unique IV for every secret
  test('3. Unique IV for every secret', () => {
    const enc1 = encryptSecret('TEST_SECRET_NOT_REAL');
    const enc2 = encryptSecret('TEST_SECRET_NOT_REAL');
    assert.notEqual(enc1.iv, enc2.iv);
  });

  // 4. Tampered ciphertext, IV, and auth tag fail safely
  test('4. Tampered ciphertext, IV, and auth tag fail safely', () => {
    const enc = encryptSecret('TEST_SECRET_NOT_REAL');
    const tamperedCipher = Buffer.from(enc.ciphertext, 'base64');
    tamperedCipher[0] ^= 0xff;

    assert.throws(() => {
      decryptSecret(tamperedCipher.toString('base64'), enc.iv, enc.authTag);
    });

    const tamperedIv = Buffer.from(enc.iv, 'base64');
    tamperedIv[0] ^= 0xff;
    assert.throws(() => {
      decryptSecret(enc.ciphertext, tamperedIv.toString('base64'), enc.authTag);
    });

    const tamperedTag = Buffer.from(enc.authTag, 'base64');
    tamperedTag[0] ^= 0xff;
    assert.throws(() => {
      decryptSecret(enc.ciphertext, enc.iv, tamperedTag.toString('base64'));
    });
  });

  // 5. No plaintext secret is saved in Supabase
  test('5. No plaintext secret is saved in Supabase', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'secure-passphrase',
      access_code: '123456'
    });
    assert.equal(res.status, 201);
    const dbSecret = mockDb.secrets.find((s) => s.id === res.body.id);
    assert.ok(dbSecret);
    const jsonStr = JSON.stringify(dbSecret);
    assert.equal(jsonStr.includes('TEST_SECRET_NOT_REAL'), false);
  });

  // 6. No passphrase, access code, or tokens are saved raw
  test('6. No passphrase, access code, or tokens are saved raw', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'super-secret-passphrase',
      access_code: '654321'
    });
    assert.equal(res.status, 201);
    const dbSecret = mockDb.secrets.find((s) => s.id === res.body.id);
    assert.notEqual(dbSecret.passphrase_hash, 'super-secret-passphrase');
    assert.notEqual(dbSecret.access_code_hash, '654321');
    assert.ok(dbSecret.passphrase_hash.startsWith('$2'));
    assert.ok(dbSecret.access_code_hash.startsWith('$2'));
  });

  // 7. Secret creation validation
  test('7. Secret creation validation', async () => {
    // Missing secret
    const res1 = await makeRequest('POST', '/api/secrets', {
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    assert.equal(res1.status, 400);

    // Short passphrase
    const res2 = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'short',
      access_code: '123456'
    });
    assert.equal(res2.status, 400);

    // Invalid PIN
    const res3 = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: 'abc'
    });
    assert.equal(res3.status, 400);
  });

  // 8. Bot preview never burns a secret
  test('8. Bot preview never burns a secret', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    // Slackbot preview request
    const botRes = await makeRequest('GET', `/view/${id}`, null, {
      'User-Agent': 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)'
    });
    assert.equal(botRes.status, 200);

    // Secret views_remaining must remain 1
    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.equal(dbSecret.views_remaining, 1);
  });

  // 9. Scheduled secret stays locked before available_at
  test('9. Scheduled secret stays locked before available_at', async () => {
    const future = new Date(Date.now() + 3600000).toISOString();
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 7200,
      max_views: 1,
      available_at: future,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    assert.equal(res.status, 201);
    const id = res.body.id;

    // Attempt verify before release time
    const verifyRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '123456',
      passphrase: 'valid-passphrase'
    });
    assert.equal(verifyRes.status, 400);
  });

  // 10. Scheduled secret activates automatically
  test('10. Scheduled secret activates automatically', async () => {
    const id = nanoid(21);
    mockDb.secrets.push({
      id,
      status: 'scheduled',
      available_at: new Date(Date.now() - 1000).toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      views_remaining: 1,
      max_views: 1
    });

    const result = await runLifecycleMaintenance(new Date());
    assert.equal(result.activated_ids.length, 1);
    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.equal(dbSecret.status, 'active');
  });

  // 11. Expired secret has crypto material removed
  test('11. Expired secret has crypto material removed', async () => {
    const id = nanoid(21);
    mockDb.secrets.push({
      id,
      status: 'active',
      available_at: new Date(Date.now() - 7200000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      ciphertext: 'sample-ciphertext',
      iv: 'sample-iv',
      auth_tag: 'sample-tag',
      passphrase_hash: 'sample-pass-hash',
      access_code_hash: 'sample-code-hash',
      views_remaining: 1,
      max_views: 1
    });

    const result = await runLifecycleMaintenance(new Date());
    assert.equal(result.expired_ids.length, 1);
    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.equal(dbSecret.status, 'expired');
    assert.equal(dbSecret.ciphertext, null);
    assert.equal(dbSecret.iv, null);
    assert.equal(dbSecret.auth_tag, null);
    assert.equal(dbSecret.passphrase_hash, null);
    assert.equal(dbSecret.access_code_hash, null);
  });

  // 12. Wrong access code/passphrase returns generic failure
  test('12. Wrong access code/passphrase returns generic failure', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    // Wrong code
    const resWrongCode = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '999999',
      passphrase: 'valid-passphrase'
    });
    assert.equal(resWrongCode.status, 400);
    assert.equal(resWrongCode.body.error, 'Secure handover unavailable or verification failed.');

    // Wrong passphrase
    const resWrongPass = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '123456',
      passphrase: 'wrong-passphrase'
    });
    assert.equal(resWrongPass.status, 400);
    assert.equal(resWrongPass.body.error, 'Secure handover unavailable or verification failed.');
  });

  // 13. Verification rate limit works
  test('13. Verification rate limit works', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    // 5 allowed failed attempts
    for (let i = 0; i < 5; i++) {
      const failRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
        access_code: '000000',
        passphrase: 'valid-passphrase'
      });
      assert.equal(failRes.status, 400);
    }

    // 6th attempt should return 429
    const limitedRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '000000',
      passphrase: 'valid-passphrase'
    });
    assert.equal(limitedRes.status, 429);
    assert.equal(limitedRes.body.error, 'Too many verification attempts. Please try again later.');
  });

  // 14. One-time reveal works
  test('14. One-time reveal works', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    const verifyRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '123456',
      passphrase: 'valid-passphrase'
    });
    assert.equal(verifyRes.status, 200);
    const token = verifyRes.body.verification_token;

    const revealRes = await makeRequest('POST', `/api/secrets/${id}/reveal`, {
      verification_token: token
    });
    assert.equal(revealRes.status, 200);
    assert.equal(revealRes.body.secret, 'TEST_SECRET_NOT_REAL');
  });

  // 15. 20 parallel reveal requests return exactly 1 HTTP 200 and 19 HTTP 404
  test('15. 20 parallel reveal requests return exactly 1 HTTP 200 and 19 HTTP 404', async () => {
    const id = nanoid(21);
    const enc = encryptSecret('TEST_PARALLEL_REVEAL_NOT_REAL');
    mockDb.secrets.push({
      id,
      status: 'active',
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      auth_tag: enc.authTag,
      views_remaining: 1,
      max_views: 1,
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 1000).toISOString()
    });

    const tokens = [];
    for (let i = 0; i < 20; i++) {
      const rawToken = generateVerificationToken();
      const tokenHash = hashVerificationToken(rawToken);
      tokens.push(rawToken);
      mockDb.verification_tokens.push({
        secret_id: id,
        token_hash: tokenHash,
        expires_at: new Date(Date.now() + 120000).toISOString()
      });
    }

    const requests = tokens.map((t) =>
      makeRequest('POST', `/api/secrets/${id}/reveal`, { verification_token: t })
    );
    const results = await Promise.all(requests);

    const successCount = results.filter((r) => r.status === 200).length;
    const blockedCount = results.filter((r) => r.status === 404).length;

    assert.equal(successCount, 1);
    assert.equal(blockedCount, 19);
  });

  // 16. Used verification token fails
  test('16. Used verification token fails', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_MULTI_VIEW_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 2,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    const verifyRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '123456',
      passphrase: 'valid-passphrase'
    });
    const token = verifyRes.body.verification_token;

    // First use succeeds
    const firstReveal = await makeRequest('POST', `/api/secrets/${id}/reveal`, {
      verification_token: token
    });
    assert.equal(firstReveal.status, 200);

    // Second use with the same token fails
    const secondReveal = await makeRequest('POST', `/api/secrets/${id}/reveal`, {
      verification_token: token
    });
    assert.equal(secondReveal.status, 404);
  });

  // 17. Panic Burn blocks receiver and removes crypto material
  test('17. Panic Burn blocks receiver and removes crypto material', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    const session = createManagementSession(id);
    const burnRes = await makeRequest('POST', `/api/secrets/${id}/panic-burn`, {}, {
      Cookie: `${COOKIE_NAME}=${session.sessionToken}`,
      'x-csrf-token': session.csrfToken
    });
    assert.equal(burnRes.status, 200);

    // Receiver should get 400 on verify
    const verifyRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '123456',
      passphrase: 'valid-passphrase'
    });
    assert.equal(verifyRes.status, 400);

    // Crypto material destroyed
    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.equal(dbSecret.status, 'revoked');
    assert.equal(dbSecret.ciphertext, null);
  });

  // 18. Acknowledgement updates sender dashboard
  test('18. Acknowledgement updates sender dashboard', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    const verifyRes = await makeRequest('POST', `/api/secrets/${id}/verify`, {
      access_code: '123456',
      passphrase: 'valid-passphrase'
    });
    const revealRes = await makeRequest('POST', `/api/secrets/${id}/reveal`, {
      verification_token: verifyRes.body.verification_token
    });
    const ackToken = revealRes.body.acknowledgement_token;

    const ackRes = await makeRequest('POST', `/api/secrets/${id}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.body.acknowledged, true);

    const dbSecret = mockDb.secrets.find((s) => s.id === id);
    assert.ok(dbSecret.acknowledged_at);
  });

  // 19. Management session protects dashboard
  test('19. Management session protects dashboard', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;

    // Without session cookie: redirects to token exchange or shows generic unavailable
    const noAuthRes = await makeRequest('GET', `/manage/${id}`);
    assert.equal(noAuthRes.status, 200);
    assert.ok(noAuthRes.body.includes('Secure Handover Unavailable'));

    // With valid session cookie
    const session = createManagementSession(id);
    const authRes = await makeRequest('GET', `/manage/${id}`, null, {
      Cookie: `${COOKIE_NAME}=${session.sessionToken}`
    });
    assert.equal(authRes.status, 200);
    assert.ok(authRes.body.includes('SENDER MANAGEMENT CONSOLE') || authRes.body.includes('Secure Handover Management'));
  });

  // 20. CSRF protection protects Panic Burn
  test('20. CSRF protection protects Panic Burn', async () => {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: 'TEST_SECRET_NOT_REAL',
      ttl_seconds: 3600,
      max_views: 1,
      passphrase: 'valid-passphrase',
      access_code: '123456'
    });
    const id = res.body.id;
    const session = createManagementSession(id);

    // Missing CSRF token
    const noCsrf = await makeRequest('POST', `/api/secrets/${id}/panic-burn`, {}, {
      Cookie: `${COOKIE_NAME}=${session.sessionToken}`
    });
    assert.equal(noCsrf.status, 400);

    // Wrong CSRF token
    const wrongCsrf = await makeRequest('POST', `/api/secrets/${id}/panic-burn`, {}, {
      Cookie: `${COOKIE_NAME}=${session.sessionToken}`,
      'x-csrf-token': 'wrong-token'
    });
    assert.equal(wrongCsrf.status, 400);
  });

  // 21. Demo Mode is unavailable when disabled
  test('21. Demo Mode is unavailable when disabled', async () => {
    process.env.DEMO_MODE_ENABLED = 'false';
    const statusRes = await makeRequest('GET', '/api/demo/status');
    assert.equal(statusRes.status, 404);
  });

  // 22. Demo Mode is unavailable in production
  test('22. Demo Mode is unavailable in production', async () => {
    process.env.NODE_ENV = 'production';
    process.env.DEMO_MODE_ENABLED = 'true';
    const createRes = await makeRequest('POST', '/api/demo/create', {});
    assert.equal(createRes.status, 404);
  });

  // 23. Sensitive routes use no-store headers
  test('23. Sensitive routes use no-store headers', async () => {
    const id = 'test-header-check-id';
    const routes = [
      { method: 'GET', path: `/view/${id}` },
      { method: 'GET', path: `/manage/${id}` },
      { method: 'POST', path: `/api/secrets/${id}/verify` },
      { method: 'POST', path: `/api/secrets/${id}/reveal` },
      { method: 'POST', path: `/api/secrets/${id}/acknowledge` },
      { method: 'POST', path: `/api/secrets/${id}/panic-burn` }
    ];

    for (const r of routes) {
      const res = await makeRequest(r.method, r.path);
      const cc = res.headers['cache-control'] || '';
      const pragma = res.headers['pragma'] || '';
      const robots = res.headers['x-robots-tag'] || '';
      const referrer = res.headers['referrer-policy'] || '';
      const frame = res.headers['x-frame-options'] || '';
      const nosniff = res.headers['x-content-type-options'] || '';

      assert.ok(cc.includes('no-store'), `${r.path} must have Cache-Control: no-store`);
      assert.ok(pragma.includes('no-cache'), `${r.path} must have Pragma: no-cache`);
      assert.ok(robots.includes('noindex'), `${r.path} must have X-Robots-Tag: noindex`);
      assert.ok(referrer.includes('no-referrer'), `${r.path} must have Referrer-Policy: no-referrer`);
      assert.ok(frame.includes('DENY') || frame.includes('SAMEORIGIN'), `${r.path} must restrict frame embedding`);
      assert.ok(nosniff.includes('nosniff'), `${r.path} must have X-Content-Type-Options: nosniff`);
    }
  });

  // 24. No API response exposes stack traces or secrets
  test('24. No API response exposes stack traces or secrets', async () => {
    // Dispatch invalid raw JSON body to verify safe 400 rejection without stack trace
    const rawRes = await new Promise((resolve) => {
      const payload = '{"bad_json":';
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: PORT,
          path: '/api/secrets',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
          }
        },
        (res) => {
          let data = '';
          res.on('data', (c) => { data += c; });
          res.on('end', () => resolve({ status: res.statusCode, body: data }));
        }
      );
      req.write(payload);
      req.end();
    });

    assert.equal(rawRes.status, 400);
    assert.equal(rawRes.body.includes('stack'), false);
    assert.equal(rawRes.body.includes('SyntaxError'), false);
    assert.equal(rawRes.body.includes('at '), false);
  });
});
