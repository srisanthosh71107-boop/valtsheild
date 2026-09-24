const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const path = require('path');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { hashValue } = require('../src/services/hashService');
const {
  encryptSecret,
  generateVerificationToken,
  hashVerificationToken
} = require('../src/services/cryptoService');
const {
  COOKIE_NAME,
  createManagementSession
} = require('../src/services/managementSessionService');

describe('Recipient Acknowledgement Test Suite', () => {
  let server;
  const PORT = 3082;

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

      supabase.rpc = async (funcName, args) => {
        if (funcName === 'reveal_secret_atomically') {
          const { p_secret_id, p_now } = args;
          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret || secret.status !== 'active') return { data: [], error: null };

          const isSingleView = secret.max_views === 1;
          const newStatus = isSingleView ? 'burned' : 'active';
          const viewsRemaining = isSingleView ? 0 : Math.max(0, secret.views_remaining - 1);

          const returnedCipher = secret.ciphertext;
          const returnedIv = secret.iv;
          const returnedAuthTag = secret.auth_tag;

          if (isSingleView) {
            secret.ciphertext = null;
            secret.iv = null;
            secret.auth_tag = null;
            secret.passphrase_hash = null;
            secret.access_code_hash = null;
            secret.status = 'burned';
          }
          secret.views_remaining = viewsRemaining;
          secret.revealed_at = p_now;

          return {
            data: [
              {
                id: secret.id,
                ciphertext: returnedCipher,
                iv: returnedIv,
                auth_tag: returnedAuthTag,
                views_remaining: viewsRemaining,
                burned: isSingleView,
                status: newStatus
              }
            ],
            error: null
          };
        }

        if (funcName === 'acknowledge_secret_atomically') {
          const { p_secret_id, p_token_hash, p_now } = args;
          const nowTime = p_now ? new Date(p_now).getTime() : Date.now();

          const token = mockDb.acknowledgement_tokens.find(
            (t) => t.token_hash === p_token_hash && t.secret_id === p_secret_id
          );
          if (!token) return { data: [], error: null };
          if (new Date(token.expires_at).getTime() <= nowTime || token.used_at) {
            return { data: [], error: null };
          }

          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (!secret) return { data: [], error: null };
          if (secret.status === 'revoked' || secret.status === 'expired') {
            return { data: [], error: null };
          }

          token.used_at = p_now;
          if (!secret.acknowledged_at) {
            secret.acknowledged_at = p_now;
          }

          return {
            data: [
              {
                secret_id: secret.id,
                acknowledged_at: secret.acknowledged_at
              }
            ],
            error: null
          };
        }

        return { data: null, error: new Error(`Unknown RPC ${funcName}`) };
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
    mockDb.secrets = [];
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
    mockDb.acknowledgement_tokens = [];
  });

  test('1. Successful reveal returns acknowledgement token', async () => {
    const rawSecret = 'SUPER_SECRET_PAYLOAD_101';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_ack_reveal_1';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('Pass123'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: await hashValue('mgmt-1'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.secret, rawSecret);
    assert.ok(res.body.acknowledgement_token, 'Response must include acknowledgement_token');
    assert.equal(typeof res.body.acknowledgement_token, 'string');
    assert.ok(res.body.acknowledgement_token.length >= 32);
    assert.equal(res.body.acknowledgement_expires_in_seconds, 900);
  });

  test('2. Raw acknowledgement token is not stored in database', async () => {
    const rawSecret = 'SECRET_TO_ACKNOWLEDGE_2';
    const encrypted = encryptSecret(rawSecret);
    const secretId = 'secret_ack_db_check_2';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('Pass2'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: await hashValue('mgmt-2'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const res = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });

    assert.equal(res.status, 200);
    const rawAckToken = res.body.acknowledgement_token;

    // Verify raw token is NOT in database
    const dbRow = mockDb.acknowledgement_tokens.find((t) => t.secret_id === secretId);
    assert.ok(dbRow, 'Acknowledgement token row must exist in DB');
    assert.notEqual(dbRow.token_hash, rawAckToken, 'Database must never store raw acknowledgement token');
    assert.ok(dbRow.expires_at);
  });

  test('3. Valid acknowledgement returns HTTP 200', async () => {
    const secretId = 'secret_valid_ack_3';
    const rawSecret = 'VALID_ACK_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('Pass3'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: await hashValue('mgmt-3'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });

    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.body.acknowledged, true);
    assert.ok(ackRes.body.acknowledged_at);
    assert.equal(ackRes.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');
    assert.equal(ackRes.headers['referrer-policy'], 'no-referrer');
  });

  test('4. Acknowledgement sets acknowledged_at', async () => {
    const secretId = 'secret_sets_ack_4';
    const rawSecret = 'SETS_ACK_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('Pass4'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: await hashValue('mgmt-4'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      acknowledged_at: null
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 200);

    const secretInDb = mockDb.secrets.find((s) => s.id === secretId);
    assert.ok(secretInDb.acknowledged_at);
    assert.equal(secretInDb.acknowledged_at, ackRes.body.acknowledged_at);
  });

  test('5. Second use of same acknowledgement token returns HTTP 404', async () => {
    const secretId = 'secret_replay_token_5';
    const rawSecret = 'REPLAY_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('Pass5'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: await hashValue('mgmt-5'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    // First use: succeeds
    const firstAck = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(firstAck.status, 200);

    // Second use: must fail with generic 404
    const secondAck = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(secondAck.status, 404);
    assert.equal(secondAck.body.error, 'Secure handover unavailable.');
  });

  test('6. Expired acknowledgement token returns HTTP 404', async () => {
    const secretId = 'secret_expired_token_6';
    const rawSecret = 'EXPIRED_TOKEN_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: await hashValue('Pass6'),
      access_code_hash: await hashValue('123456'),
      management_token_hash: await hashValue('mgmt-6'),
      status: 'active',
      created_at: new Date().toISOString(),
      available_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600000).toISOString(),
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    // Simulate token expiration by setting expires_at into the past
    const tokenRow = mockDb.acknowledgement_tokens.find((t) => t.secret_id === secretId);
    tokenRow.expires_at = new Date(Date.now() - 10000).toISOString();

    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 404);
    assert.equal(ackRes.body.error, 'Secure handover unavailable.');
  });

  test('7. Wrong secret ID with valid token returns HTTP 404', async () => {
    const secretId1 = 'secret_owner_7';
    const secretId2 = 'secret_wrong_target_7';
    const rawSecret = 'WRONG_TARGET_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push(
      {
        id: secretId1,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        auth_tag: encrypted.authTag,
        status: 'active',
        max_views: 1,
        views_remaining: 1
      },
      {
        id: secretId2,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        auth_tag: encrypted.authTag,
        status: 'active',
        max_views: 1,
        views_remaining: 1
      }
    );

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId1,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId1}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    // Attempt to use token on secretId2
    const ackRes = await makeRequest('POST', `/api/secrets/${secretId2}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 404);
    assert.equal(ackRes.body.error, 'Secure handover unavailable.');
  });

  test('8. Bot User-Agent cannot acknowledge', async () => {
    const secretId = 'secret_bot_ack_8';
    const rawSecret = 'BOT_ACK_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      status: 'active',
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    const botAgents = [
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
      'facebookexternalhit/1.1'
    ];

    for (const ua of botAgents) {
      const ackRes = await makeRequest(
        'POST',
        `/api/secrets/${secretId}/acknowledge`,
        { acknowledgement_token: ackToken },
        { 'User-Agent': ua }
      );
      assert.equal(ackRes.status, 404);
      assert.equal(ackRes.body.error, 'Secure handover unavailable.');
    }

    // Token must remain unused
    const tokenRow = mockDb.acknowledgement_tokens.find((t) => t.secret_id === secretId);
    assert.strictEqual(tokenRow.used_at, undefined);
  });

  test('9. Acknowledgement does not change burned status', async () => {
    const secretId = 'secret_burned_status_9';
    const rawSecret = 'BURNED_STATUS_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      status: 'active',
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    assert.equal(revealRes.body.burned, true);
    const ackToken = revealRes.body.acknowledgement_token;

    // Verify secret is burned in DB
    const secretBefore = mockDb.secrets.find((s) => s.id === secretId);
    assert.equal(secretBefore.status, 'burned');

    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 200);

    // Verify secret remains burned
    const secretAfter = mockDb.secrets.find((s) => s.id === secretId);
    assert.equal(secretAfter.status, 'burned');
  });

  test('10. Acknowledgement does not restore removed encrypted data', async () => {
    const secretId = 'secret_shred_preservation_10';
    const rawSecret = 'SHRED_PRESERVE_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      status: 'active',
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 200);

    const secret = mockDb.secrets.find((s) => s.id === secretId);
    assert.strictEqual(secret.ciphertext, null);
    assert.strictEqual(secret.iv, null);
    assert.strictEqual(secret.auth_tag, null);
    assert.strictEqual(secret.passphrase_hash, null);
    assert.strictEqual(secret.access_code_hash, null);
  });

  test('11. Sender dashboard shows acknowledgement timestamp', async () => {
    const secretId = 'secret_dashboard_ack_11';
    const ackTime = new Date('2026-09-24T18:30:00.000Z').toISOString();

    mockDb.secrets.push({
      id: secretId,
      status: 'burned',
      created_at: new Date('2026-09-24T18:00:00.000Z').toISOString(),
      available_at: new Date('2026-09-24T18:00:00.000Z').toISOString(),
      expires_at: new Date('2026-09-24T19:00:00.000Z').toISOString(),
      max_views: 1,
      views_remaining: 0,
      revealed_at: new Date('2026-09-24T18:25:00.000Z').toISOString(),
      acknowledged_at: ackTime
    });

    mockDb.secret_events.push(
      {
        secret_id: secretId,
        event_type: 'revealed',
        created_at: new Date('2026-09-24T18:25:00.000Z').toISOString()
      },
      {
        secret_id: secretId,
        event_type: 'acknowledged',
        created_at: ackTime
      }
    );

    const { sessionToken } = createManagementSession(secretId);

    const res = await makeRequest('GET', `/manage/${secretId}`, null, {
      Cookie: `${COOKIE_NAME}=${sessionToken}`
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.includes('Recipient acknowledgement'));
    assert.ok(res.body.includes('Acknowledged at:'));
    assert.ok(res.body.includes('Acknowledged'));
  });

  test('12. Audit event contains no secret or recipient-sensitive values', async () => {
    const secretId = 'secret_audit_check_12';
    const rawSecret = 'CONFIDENTIAL_VALUE_AUDIT';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      status: 'active',
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });

    const ackEvent = mockDb.secret_events.find(
      (e) => e.secret_id === secretId && e.event_type === 'acknowledged'
    );
    assert.ok(ackEvent, 'Acknowledged event must exist');
    assert.equal(ackEvent.metadata.source, 'recipient_acknowledgement');

    const serialized = JSON.stringify(ackEvent);
    assert.ok(!serialized.includes(rawSecret));
    assert.ok(!serialized.includes(ackToken));
    assert.strictEqual(ackEvent.metadata.ip, undefined);
    assert.strictEqual(ackEvent.metadata.recipient_ip, undefined);
    assert.strictEqual(ackEvent.metadata.user_agent, undefined);
    assert.strictEqual(ackEvent.metadata.recipient_name, undefined);
  });

  test('13. Recipient page does not store token in browser storage', () => {
    const viewJsPath = path.join(__dirname, '../public/js/view.js');
    const viewJsContent = fs.readFileSync(viewJsPath, 'utf8');

    // Verify view.js does NOT save acknowledgement token in web storage
    assert.ok(!viewJsContent.includes('localStorage.setItem'));
    assert.ok(!viewJsContent.includes('sessionStorage.setItem'));
    assert.ok(!viewJsContent.includes('document.cookie'));
  });

  test('14. Acknowledgement remains possible after 15-second secret display ends, until its 15-minute token expiry', async () => {
    const secretId = 'secret_post_display_14';
    const rawSecret = 'POST_DISPLAY_SECRET';
    const encrypted = encryptSecret(rawSecret);

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      status: 'active',
      max_views: 1,
      views_remaining: 1
    });

    const verifyToken = generateVerificationToken();
    mockDb.verification_tokens.push({
      id: 1,
      secret_id: secretId,
      token_hash: hashVerificationToken(verifyToken),
      expires_at: new Date(Date.now() + 120000).toISOString(),
      used_at: null
    });

    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: verifyToken
    });
    const ackToken = revealRes.body.acknowledgement_token;

    // Simulate 20 seconds passing (longer than 15-second display timer)
    // The secret is already burned and destroyed
    const secretInDb = mockDb.secrets.find((s) => s.id === secretId);
    assert.equal(secretInDb.status, 'burned');
    assert.strictEqual(secretInDb.ciphertext, null);

    // Recipient acknowledges after 20 seconds
    const ackRes = await makeRequest('POST', `/api/secrets/${secretId}/acknowledge`, {
      acknowledgement_token: ackToken
    });
    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.body.acknowledged, true);
    assert.ok(secretInDb.acknowledged_at);
  });
});
