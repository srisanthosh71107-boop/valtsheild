const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const {
  encryptSecret,
  generateVerificationToken,
  hashVerificationToken
} = require('../src/services/cryptoService');
const { hashValue } = require('../src/services/hashService');

describe('POST /api/secrets/:id/reveal Test Suite', () => {
  let server;
  const PORT = 3086;

  const mockDb = {
    secrets: [],
    secret_events: [],
    verification_tokens: []
  };

  let originalFrom;
  let originalRpc;

  // Concurrency mutex per secret_id to simulate PostgreSQL row-level locks (FOR UPDATE)
  const secretLocks = new Map();
  async function withSecretLock(secretId, fn) {
    while (secretLocks.has(secretId)) {
      await secretLocks.get(secretId);
    }
    let resolve;
    const promise = new Promise((res) => {
      resolve = res;
    });
    secretLocks.set(secretId, promise);
    try {
      return await fn();
    } finally {
      secretLocks.delete(secretId);
      resolve();
    }
  }

  // Helper function to perform HTTP requests
  function makeRequest(method, path, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : null;
      const reqHeaders = {
        'Content-Type': 'application/json',
        ...headers
      };
      if (payload) {
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
              maybeSingle: async () => {
                const found = (mockDb[table] || []).find((r) => r[col] === val);
                if (!found) return { data: null, error: null };
                if (fields && fields !== '*') {
                  const fieldList = fields.split(',').map((f) => f.trim());
                  const filtered = {};
                  fieldList.forEach((f) => {
                    if (found[f] !== undefined) filtered[f] = found[f];
                  });
                  return { data: filtered, error: null };
                }
                return { data: found, error: null };
              }
            })
          })
        };
      };

      // Mock atomic RPC reveal_secret_atomically
      supabase.rpc = async (funcName, args) => {
        if (funcName === 'reveal_secret_atomically') {
          const { p_secret_id, p_token_hash, p_now } = args;
          const nowTime = p_now ? new Date(p_now).getTime() : Date.now();

          return withSecretLock(p_secret_id, async () => {
            // 1. Lock and validate matching verification token row
            const token = mockDb.verification_tokens.find(
              (t) => t.token_hash === p_token_hash && t.secret_id === p_secret_id
            );

            if (!token) return { data: [], error: null };
            if (token.used_at !== null && token.used_at !== undefined) return { data: [], error: null };
            if (new Date(token.expires_at).getTime() <= nowTime) return { data: [], error: null };

            // 2. Lock matching secret row
            const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
            if (!secret) return { data: [], error: null };
            if (secret.status !== 'active') return { data: [], error: null };
            if (new Date(secret.available_at).getTime() > nowTime) return { data: [], error: null };
            if (new Date(secret.expires_at).getTime() <= nowTime) return { data: [], error: null };
            if (secret.views_remaining <= 0) return { data: [], error: null };

            // 3. Mark verification token as used
            token.used_at = p_now || new Date().toISOString();

            // Extract cipher payload
            const ciphertext = secret.ciphertext;
            const iv = secret.iv;
            const auth_tag = secret.auth_tag;
            const newViews = secret.views_remaining - 1;
            const burned = newViews <= 0;

            // 4. Update or Shred secret
            if (burned) {
              secret.ciphertext = null;
              secret.iv = null;
              secret.auth_tag = null;
              secret.passphrase_hash = null;
              secret.access_code_hash = null;
              secret.views_remaining = 0;
              secret.status = 'burned';
              secret.revealed_at = p_now || new Date().toISOString();
            } else {
              secret.views_remaining = newViews;
              secret.revealed_at = secret.revealed_at || (p_now || new Date().toISOString());
            }

            return {
              data: [
                {
                  ciphertext,
                  iv,
                  auth_tag,
                  views_remaining: newViews,
                  burned
                }
              ],
              error: null
            };
          });
        }
        return { data: null, error: new Error('Unknown RPC function') };
      };
    }

    server = app.listen(PORT);
  });

  after(() => {
    if (supabase) {
      if (originalFrom) supabase.from = originalFrom;
      if (originalRpc) supabase.rpc = originalRpc;
    }
    server.close();
  });

  beforeEach(() => {
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
    mockDb.secrets = [];
  });

  test('1. Verified recipient can reveal one-view secret once', async () => {
    const rawSecret = 'SUPER_SECRET_PRODUCTION_KEY_999';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_single_view_1';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    const tokenHash = hashVerificationToken(rawToken);

    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: tokenHash,
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.secret, rawSecret);
    assert.equal(res.body.views_remaining, 0);
    assert.equal(res.body.burned, true);
    assert.equal(res.body.display_seconds, 15);

    // Verify cache-control headers
    assert.ok(res.headers['cache-control'].includes('no-store'));
    assert.ok(res.headers['cache-control'].includes('no-cache'));
    assert.ok(res.headers['x-robots-tag'].includes('noindex'));
  });

  test('2. Second reveal request returns HTTP 404', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_2';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_single_view_2';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken1 = generateVerificationToken();
    const rawToken2 = generateVerificationToken();

    mockDb.verification_tokens.push(
      {
        id: 1,
        secret_id: secretId,
        token_hash: hashVerificationToken(rawToken1),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      },
      {
        id: 2,
        secret_id: secretId,
        token_hash: hashVerificationToken(rawToken2),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      }
    );

    // First reveal succeeds
    const res1 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken1
    });
    assert.equal(res1.status, 200);

    // Second reveal fails with 404
    const res2 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken2
    });
    assert.equal(res2.status, 404);
    assert.equal(res2.body.error, 'Secret not found, expired, or already destroyed.');
  });

  test('3. Reusing same verification token returns HTTP 404', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_3';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_reuse_token_3';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 3,
      views_remaining: 3,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    // First use works
    const res1 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });
    assert.equal(res1.status, 200);

    // Second use of the exact same token returns 404
    const res2 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });
    assert.equal(res2.status, 404);
    assert.equal(res2.body.error, 'Secret not found, expired, or already destroyed.');
  });

  test('4. Invalid verification token returns HTTP 404', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_4';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_invalid_token_4';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: 'invalid-nonexistent-token-1234567890'
    });

    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'Secret not found, expired, or already destroyed.');
  });

  test('5. Expired verification token returns HTTP 404', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_5';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_expired_token_5';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() - 5000).toISOString(), // Expired 5 seconds ago
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });

    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'Secret not found, expired, or already destroyed.');
  });

  test('6. Bot User-Agent cannot reveal', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_6';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_bot_reveal_6';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest(
      'POST',
      `/api/secrets/${secretId}/reveal`,
      { verification_token: rawToken },
      { 'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' }
    );

    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'Secret not found, expired, or already destroyed.');
    // Token was never consumed
    assert.equal(mockDb.verification_tokens[0].used_at, null);
  });

  test('7. Tampered ciphertext returns safe error without leaking crypto details', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_7';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_tampered_7';

    // Tamper ciphertext
    const tamperedCiphertext = Buffer.from(encrypted.ciphertext, 'base64');
    tamperedCiphertext[0] ^= 0xff;

    mockDb.secrets.push({
      id: secretId,
      ciphertext: tamperedCiphertext.toString('base64'),
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });

    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'Secret not found, expired, or already destroyed.');
    // Must not leak OpenSSL or crypto error messages
    assert.ok(!JSON.stringify(res.body).toLowerCase().includes('openssl'));
    assert.ok(!JSON.stringify(res.body).toLowerCase().includes('auth'));
  });

  test('8. One-view secret has ciphertext, IV, auth tag, passphrase hash, and access code hash removed after successful reveal', async () => {
    const rawSecret = 'CONFIDENTIAL_DATA_8';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_shred_8';

    const secretRecord = {
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    };
    mockDb.secrets.push(secretRecord);

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.secret, rawSecret);

    // Verify all sensitive payload fields in the database have been completely nullified / shredded
    assert.equal(secretRecord.ciphertext, null);
    assert.equal(secretRecord.iv, null);
    assert.equal(secretRecord.auth_tag, null);
    assert.equal(secretRecord.passphrase_hash, null);
    assert.equal(secretRecord.access_code_hash, null);
    assert.equal(secretRecord.views_remaining, 0);
    assert.equal(secretRecord.status, 'burned');
    assert.ok(secretRecord.revealed_at !== undefined && secretRecord.revealed_at !== null);
  });

  test('9. 20 parallel reveal requests produce exactly 1 HTTP 200 and 19 HTTP 404s', async () => {
    const rawSecret = 'CONCURRENT_CRITICAL_SECRET_9';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_concurrent_9';

    const secretRecord = {
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    };
    mockDb.secrets.push(secretRecord);

    // Create 20 unique valid verification tokens
    const tokens = [];
    for (let i = 0; i < 20; i++) {
      const rawToken = generateVerificationToken();
      tokens.push(rawToken);
      mockDb.verification_tokens.push({
        id: i + 1,
        secret_id: secretId,
        token_hash: hashVerificationToken(rawToken),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      });
    }

    // Fire all 20 reveal requests simultaneously in parallel
    const requests = tokens.map((token) =>
      makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
        verification_token: token
      })
    );

    const responses = await Promise.all(requests);

    const successResponses = responses.filter((r) => r.status === 200);
    const notFoundResponses = responses.filter((r) => r.status === 404);

    assert.equal(successResponses.length, 1, 'Exactly 1 request must receive HTTP 200');
    assert.equal(notFoundResponses.length, 19, 'Exactly 19 requests must receive HTTP 404');
    assert.equal(successResponses[0].body.secret, rawSecret);
    assert.equal(successResponses[0].body.burned, true);

    // Secret must be burned
    assert.equal(secretRecord.status, 'burned');
    assert.equal(secretRecord.views_remaining, 0);
    assert.equal(secretRecord.ciphertext, null);
  });

  test('10. Multi-view secret decrements exactly once per valid reveal', async () => {
    const rawSecret = 'MULTI_VIEW_SECRET_10';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_multi_view_10';

    const secretRecord = {
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 3,
      views_remaining: 3,
      status: 'active'
    };
    mockDb.secrets.push(secretRecord);

    const token1 = generateVerificationToken();
    const token2 = generateVerificationToken();
    const token3 = generateVerificationToken();
    const token4 = generateVerificationToken();

    mockDb.verification_tokens.push(
      {
        id: 1,
        secret_id: secretId,
        token_hash: hashVerificationToken(token1),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      },
      {
        id: 2,
        secret_id: secretId,
        token_hash: hashVerificationToken(token2),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      },
      {
        id: 3,
        secret_id: secretId,
        token_hash: hashVerificationToken(token3),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      },
      {
        id: 4,
        secret_id: secretId,
        token_hash: hashVerificationToken(token4),
        expires_at: new Date(Date.now() + 120000).toISOString(),
        used_at: null
      }
    );

    // View 1
    const res1 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, { verification_token: token1 });
    assert.equal(res1.status, 200);
    assert.equal(res1.body.views_remaining, 2);
    assert.equal(res1.body.burned, false);
    assert.equal(secretRecord.views_remaining, 2);
    assert.equal(secretRecord.status, 'active');
    assert.notEqual(secretRecord.ciphertext, null);

    // View 2
    const res2 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, { verification_token: token2 });
    assert.equal(res2.status, 200);
    assert.equal(res2.body.views_remaining, 1);
    assert.equal(res2.body.burned, false);
    assert.equal(secretRecord.views_remaining, 1);
    assert.equal(secretRecord.status, 'active');

    // View 3 (Final view -> triggers burn)
    const res3 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, { verification_token: token3 });
    assert.equal(res3.status, 200);
    assert.equal(res3.body.views_remaining, 0);
    assert.equal(res3.body.burned, true);
    assert.equal(secretRecord.views_remaining, 0);
    assert.equal(secretRecord.status, 'burned');
    assert.equal(secretRecord.ciphertext, null);

    // View 4 (Attempt on burned secret)
    const res4 = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, { verification_token: token4 });
    assert.equal(res4.status, 404);
  });

  test('11. API response includes no encryption metadata', async () => {
    const rawSecret = 'METADATA_CHECK_SECRET_11';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_metadata_11';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });

    assert.equal(res.status, 200);
    const keys = Object.keys(res.body);

    assert.ok(keys.includes('secret'));
    assert.ok(keys.includes('views_remaining'));
    assert.ok(keys.includes('burned'));
    assert.ok(keys.includes('display_seconds'));

    assert.equal(res.body.ciphertext, undefined);
    assert.equal(res.body.iv, undefined);
    assert.equal(res.body.auth_tag, undefined);
    assert.equal(res.body.authTag, undefined);
    assert.equal(res.body.passphrase_hash, undefined);
    assert.equal(res.body.access_code_hash, undefined);
    assert.equal(res.body.management_token_hash, undefined);
    assert.equal(res.body.key, undefined);
  });

  test('12. Audit event contains no plaintext secret', async () => {
    const rawSecret = 'SUPER_SENSITIVE_AUDIT_CHECK_12';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_test_audit_12';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgttoken',
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      available_at: new Date(Date.now() - 60000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    const rawToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(rawToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });

    assert.equal(res.status, 200);

    const revealedEvents = mockDb.secret_events.filter(
      (e) => e.secret_id === secretId && e.event_type === 'revealed'
    );

    assert.equal(revealedEvents.length, 1);
    const event = revealedEvents[0];

    const eventJson = JSON.stringify(event);
    assert.ok(!eventJson.includes(rawSecret), 'Audit event must not contain raw secret');
    assert.ok(!eventJson.includes(encrypted.ciphertext), 'Audit event must not contain ciphertext');
    assert.ok(!eventJson.includes(rawToken), 'Audit event must not contain raw verification token');
    assert.equal(event.metadata.burned, true);
    assert.equal(event.metadata.views_remaining, 0);
  });
});
