const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { hashValue } = require('../src/services/hashService');
const { hashVerificationToken } = require('../src/services/cryptoService');
const rateLimiter = require('../src/services/verificationRateLimitService');

describe('POST /api/secrets/:id/verify Test Suite', () => {
  let server;
  const PORT = 3087;

  const mockDb = {
    secrets: [],
    secret_events: [],
    verification_tokens: []
  };

  let originalFrom;

  const validAccessCode = '849201';
  const validPassphrase = 'UltraSecurePassphrase!2026';
  let validCodeHash;
  let validPassHash;

  before(async () => {
    validCodeHash = await hashValue(validAccessCode);
    validPassHash = await hashValue(validPassphrase);

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
    rateLimiter.resetAll();
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
    mockDb.secrets = [
      {
        id: 'active_secret_test_12345',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: validPassHash,
        access_code_hash: validCodeHash,
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 3600000).toISOString(), // +1 hr
        available_at: new Date(Date.now() - 60000).toISOString(), // -1 min
        max_views: 2,
        views_remaining: 2,
        status: 'active'
      },
      {
        id: 'scheduled_secret_test_123',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: validPassHash,
        access_code_hash: validCodeHash,
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 7200000).toISOString(),
        available_at: new Date(Date.now() + 3600000).toISOString(), // +1 hr (future)
        max_views: 1,
        views_remaining: 1,
        status: 'scheduled'
      },
      {
        id: 'expired_secret_test_12345',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: validPassHash,
        access_code_hash: validCodeHash,
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() - 3600000).toISOString(), // -1 hr
        available_at: new Date(Date.now() - 7200000).toISOString(),
        max_views: 1,
        views_remaining: 1,
        status: 'expired'
      },
      {
        id: 'revoked_secret_test_12345',
        ciphertext: null,
        iv: null,
        auth_tag: null,
        passphrase_hash: validPassHash,
        access_code_hash: validCodeHash,
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        available_at: new Date(Date.now() - 60000).toISOString(),
        max_views: 1,
        views_remaining: 1,
        status: 'revoked'
      },
      {
        id: 'zero_views_secret_test_12',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: validPassHash,
        access_code_hash: validCodeHash,
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        available_at: new Date(Date.now() - 60000).toISOString(),
        max_views: 1,
        views_remaining: 0,
        status: 'active'
      }
    ];
  });

  function verifyRequest(secretId, payload, userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', ip = '127.0.0.1') {
    return new Promise((resolve, reject) => {
      const dataString = JSON.stringify(payload);
      const req = http.request(
        {
          hostname: 'localhost',
          port: PORT,
          path: `/api/secrets/${secretId}/verify`,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(dataString),
            'User-Agent': userAgent,
            'X-Forwarded-For': ip
          }
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => { body += chunk; });
          res.on('end', () => {
            try {
              resolve({
                statusCode: res.statusCode,
                headers: res.headers,
                body: body ? JSON.parse(body) : null
              });
            } catch (err) {
              resolve({ statusCode: res.statusCode, headers: res.headers, body });
            }
          });
        }
      );
      req.on('error', reject);
      req.write(dataString);
      req.end();
    });
  }

  const validPayload = {
    access_code: validAccessCode,
    passphrase: validPassphrase
  };

  test('1. Correct access code and passphrase returns 200 and a token', async () => {
    const res = await verifyRequest('active_secret_test_12345', validPayload);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.verified, true);
    assert.ok(res.body.verification_token);
    assert.equal(typeof res.body.verification_token, 'string');
    assert.equal(res.body.expires_in_seconds, 120);
  });

  test('2. Wrong access code returns generic failure', async () => {
    const res = await verifyRequest('active_secret_test_12345', {
      ...validPayload,
      access_code: '000000'
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
  });

  test('3. Wrong passphrase returns same generic failure', async () => {
    const res = await verifyRequest('active_secret_test_12345', {
      ...validPayload,
      passphrase: 'IncorrectPassphrase123!'
    });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
  });

  test('4. Scheduled secret cannot be verified', async () => {
    const res = await verifyRequest('scheduled_secret_test_123', validPayload);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
  });

  test('5. Expired secret cannot be verified', async () => {
    const res = await verifyRequest('expired_secret_test_12345', validPayload);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
  });

  test('6. Revoked secret cannot be verified', async () => {
    const res = await verifyRequest('revoked_secret_test_12345', validPayload);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
  });

  test('7. Empty views secret cannot be verified', async () => {
    const res = await verifyRequest('zero_views_secret_test_12', validPayload);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
  });

  test('8. Bot User-Agent cannot verify', async () => {
    const res = await verifyRequest(
      'active_secret_test_12345',
      validPayload,
      'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)'
    );
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'Secure handover unavailable or verification failed.');
    assert.equal(mockDb.verification_tokens.length, 0);
  });

  test('9. Raw verification token does not appear in database', async () => {
    const res = await verifyRequest('active_secret_test_12345', validPayload);
    assert.equal(res.statusCode, 200);
    const rawToken = res.body.verification_token;

    const storedTokensString = JSON.stringify(mockDb.verification_tokens);
    assert.ok(!storedTokensString.includes(rawToken), 'Raw verification token must never appear in database');
  });

  test('10. Stored token hash differs from raw token', async () => {
    const res = await verifyRequest('active_secret_test_12345', validPayload);
    assert.equal(res.statusCode, 200);
    const rawToken = res.body.verification_token;

    assert.equal(mockDb.verification_tokens.length, 1);
    const storedRecord = mockDb.verification_tokens[0];

    assert.notEqual(storedRecord.token_hash, rawToken);
    const expectedHash = hashVerificationToken(rawToken);
    assert.equal(storedRecord.token_hash, expectedHash);
  });

  test('11. Token expires in 2 minutes', async () => {
    const beforeCall = Date.now();
    const res = await verifyRequest('active_secret_test_12345', validPayload);
    assert.equal(res.statusCode, 200);

    const storedRecord = mockDb.verification_tokens[0];
    const expiryTimestamp = new Date(storedRecord.expires_at).getTime();

    // Check that expiry is approximately 120,000 ms in future (+/- 5000ms)
    assert.ok(expiryTimestamp >= beforeCall + 115000);
    assert.ok(expiryTimestamp <= beforeCall + 125000);
  });

  test('12. Six failed attempts returns HTTP 429 after five allowed failures', async () => {
    const testIp = '198.51.100.42';

    // Attempts 1 to 5: standard 400 generic error
    for (let i = 1; i <= 5; i++) {
      const failRes = await verifyRequest(
        'active_secret_test_12345',
        { ...validPayload, access_code: '000000' },
        'Mozilla/5.0',
        testIp
      );
      assert.equal(failRes.statusCode, 400, `Attempt ${i} should be 400`);
      assert.equal(failRes.body.error, 'Secure handover unavailable or verification failed.');
    }

    // Attempt 6: rate limited with 429
    const limitedRes = await verifyRequest(
      'active_secret_test_12345',
      { ...validPayload, access_code: '000000' },
      'Mozilla/5.0',
      testIp
    );
    assert.equal(limitedRes.statusCode, 429);
    assert.equal(limitedRes.body.error, 'Too many verification attempts. Please try again later.');
  });

  test('13. Successful verification clears failed-attempt count', async () => {
    const testIp = '198.51.100.77';

    // 4 failed attempts
    for (let i = 1; i <= 4; i++) {
      await verifyRequest('active_secret_test_12345', { ...validPayload, access_code: '000000' }, 'Mozilla/5.0', testIp);
    }

    // 1 successful verification
    const successRes = await verifyRequest('active_secret_test_12345', validPayload, 'Mozilla/5.0', testIp);
    assert.equal(successRes.statusCode, 200);

    // Failed attempt counter should now be cleared; another 5 failures should be permitted
    for (let i = 1; i <= 5; i++) {
      const retryRes = await verifyRequest(
        'active_secret_test_12345',
        { ...validPayload, access_code: '000000' },
        'Mozilla/5.0',
        testIp
      );
      assert.equal(retryRes.statusCode, 400, `Post-clear attempt ${i} should return 400, not 429`);
    }
  });

  test('14. Success and failure audit logs do not contain credentials', async () => {
    // 1 failure
    await verifyRequest('active_secret_test_12345', {
      access_code: '999999',
      passphrase: 'WrongSecretPassword123!'
    });

    // 1 success
    await verifyRequest('active_secret_test_12345', validPayload);

    const logsString = JSON.stringify(mockDb.secret_events);

    // Must not contain plaintext credentials
    assert.ok(!logsString.includes('999999'));
    assert.ok(!logsString.includes('WrongSecretPassword123!'));
    assert.ok(!logsString.includes(validAccessCode));
    assert.ok(!logsString.includes(validPassphrase));

    // Check that verification_failed and verification_passed events were recorded safely
    const failedEvent = mockDb.secret_events.find((e) => e.event_type === 'verification_failed');
    assert.ok(failedEvent);
    assert.equal(failedEvent.metadata.reason, 'generic_verification_failure');

    const passedEvent = mockDb.secret_events.find((e) => e.event_type === 'verification_passed');
    assert.ok(passedEvent);
    assert.equal(passedEvent.metadata.expires_in_seconds, 120);
  });
});
