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
const {
  startLifecycleSweeper,
  runLifecycleMaintenance,
  stopLifecycleSweeperForTests
} = require('../src/services/lifecycleSweeperService');

describe('Lifecycle Sweeper & Automated Expiry Cleanup Test Suite', () => {
  let server;
  const PORT = 3085;

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
            eq: (col1, val1) => ({
              eq: (col2, val2) => ({
                limit: async () => {
                  const filtered = (mockDb[table] || []).filter(
                    (r) => r[col1] === val1 && r[col2] === val2
                  );
                  return { data: filtered, error: null };
                },
                then: (resolve) => {
                  const filtered = (mockDb[table] || []).filter(
                    (r) => r[col1] === val1 && r[col2] === val2
                  );
                  resolve({ data: filtered, error: null });
                }
              }),
              limit: async () => {
                const filtered = (mockDb[table] || []).filter((r) => r[col1] === val1);
                return { data: filtered, error: null };
              },
              maybeSingle: async () => {
                const found = (mockDb[table] || []).find((r) => r[col1] === val1);
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
                const filtered = (mockDb[table] || []).filter((r) => r[col1] === val1);
                resolve({ data: filtered, error: null });
              }
            })
          })
        };
      };

      // Mock RPC functions
      supabase.rpc = async (funcName, args) => {
        const { p_now } = args || {};
        const nowTime = p_now ? new Date(p_now).getTime() : Date.now();

        if (funcName === 'maintain_secret_lifecycle') {
          const activatedIds = [];
          const expiredIds = [];

          // 1. Activate scheduled secrets
          mockDb.secrets.forEach((secret) => {
            if (
              secret.status === 'scheduled' &&
              new Date(secret.available_at).getTime() <= nowTime &&
              new Date(secret.expires_at).getTime() > nowTime
            ) {
              secret.status = 'active';
              activatedIds.push(secret.id);
            }
          });

          // 2. Expire old secrets (scheduled or active)
          mockDb.secrets.forEach((secret) => {
            if (
              (secret.status === 'scheduled' || secret.status === 'active') &&
              new Date(secret.expires_at).getTime() <= nowTime
            ) {
              secret.ciphertext = null;
              secret.iv = null;
              secret.auth_tag = null;
              secret.passphrase_hash = null;
              secret.access_code_hash = null;
              secret.status = 'expired';
              expiredIds.push(secret.id);
            }
          });

          return {
            data: {
              activated_ids: activatedIds,
              expired_ids: expiredIds
            },
            error: null
          };
        }

        if (funcName === 'reveal_secret_atomically') {
          const { p_secret_id, p_token_hash } = args;
          const token = mockDb.verification_tokens.find(
            (t) => t.token_hash === p_token_hash && t.secret_id === p_secret_id
          );
          if (!token || token.used_at || new Date(token.expires_at).getTime() <= nowTime) {
            return { data: [], error: null };
          }
          const secret = mockDb.secrets.find((s) => s.id === p_secret_id);
          if (
            !secret ||
            secret.status !== 'active' ||
            new Date(secret.available_at).getTime() > nowTime ||
            new Date(secret.expires_at).getTime() <= nowTime ||
            secret.views_remaining <= 0
          ) {
            return { data: [], error: null };
          }

          token.used_at = p_now;
          const newViews = secret.views_remaining - 1;
          const burned = newViews <= 0;
          const row = {
            ciphertext: secret.ciphertext,
            iv: secret.iv,
            auth_tag: secret.auth_tag,
            views_remaining: newViews,
            burned
          };

          if (burned) {
            secret.ciphertext = null;
            secret.iv = null;
            secret.auth_tag = null;
            secret.status = 'burned';
            secret.views_remaining = 0;
          } else {
            secret.views_remaining = newViews;
          }

          return { data: [row], error: null };
        }

        return { data: null, error: new Error('Unknown RPC') };
      };
    }

    server = app.listen(PORT);
  });

  after(() => {
    stopLifecycleSweeperForTests();
    if (supabase) {
      if (originalFrom) supabase.from = originalFrom;
      if (originalRpc) supabase.rpc = originalRpc;
    }
    server.close();
  });

  beforeEach(() => {
    stopLifecycleSweeperForTests();
    mockDb.secrets = [];
    mockDb.secret_events = [];
    mockDb.verification_tokens = [];
  });

  test('1. Scheduled secret before available_at remains scheduled', async () => {
    const secretId = 'secret_scheduled_future';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'dummyCiphertext',
      iv: 'dummyIv',
      auth_tag: 'dummyAuthTag',
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgmttoken',
      available_at: new Date(Date.now() + 60000).toISOString(), // 1 min in future
      expires_at: new Date(Date.now() + 120000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'scheduled',
      created_at: new Date().toISOString()
    });

    const result = await runLifecycleMaintenance();

    assert.ok(!result.activated_ids.includes(secretId));
    assert.ok(!result.expired_ids.includes(secretId));
    assert.equal(mockDb.secrets[0].status, 'scheduled');
  });

  test('2. Scheduled secret at available_at becomes active', async () => {
    const secretId = 'secret_scheduled_ready';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'dummyCiphertext',
      iv: 'dummyIv',
      auth_tag: 'dummyAuthTag',
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgmttoken',
      available_at: new Date(Date.now() - 5000).toISOString(), // 5s ago
      expires_at: new Date(Date.now() + 60000).toISOString(), // 1 min in future
      max_views: 1,
      views_remaining: 1,
      status: 'scheduled',
      created_at: new Date(Date.now() - 10000).toISOString()
    });

    const result = await runLifecycleMaintenance();

    assert.ok(result.activated_ids.includes(secretId));
    assert.equal(mockDb.secrets[0].status, 'active');
    // Encrypted payloads intact
    assert.equal(mockDb.secrets[0].ciphertext, 'dummyCiphertext');
    assert.equal(mockDb.secrets[0].iv, 'dummyIv');
    assert.equal(mockDb.secrets[0].auth_tag, 'dummyAuthTag');

    // Audit event created
    const activatedEvent = mockDb.secret_events.find(
      (e) => e.secret_id === secretId && e.event_type === 'activated'
    );
    assert.ok(activatedEvent);
    assert.equal(activatedEvent.metadata.source, 'background_sweeper');
  });

  test('3. Active secret after expires_at becomes expired', async () => {
    const secretId = 'secret_active_expired';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'dummyCiphertext',
      iv: 'dummyIv',
      auth_tag: 'dummyAuthTag',
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgmttoken',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 5000).toISOString(), // Expired 5s ago
      max_views: 1,
      views_remaining: 1,
      status: 'active',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    const result = await runLifecycleMaintenance();

    assert.ok(result.expired_ids.includes(secretId));
    assert.equal(mockDb.secrets[0].status, 'expired');

    const expiredEvent = mockDb.secret_events.find(
      (e) => e.secret_id === secretId && e.event_type === 'expired'
    );
    assert.ok(expiredEvent);
    assert.equal(expiredEvent.metadata.source, 'background_sweeper');
  });

  test('4. Scheduled secret after expires_at becomes expired without becoming active', async () => {
    const secretId = 'secret_scheduled_expired_directly';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'dummyCiphertext',
      iv: 'dummyIv',
      auth_tag: 'dummyAuthTag',
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgmttoken',
      available_at: new Date(Date.now() - 10000).toISOString(),
      expires_at: new Date(Date.now() - 5000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'scheduled',
      created_at: new Date(Date.now() - 20000).toISOString()
    });

    const result = await runLifecycleMaintenance();

    assert.ok(!result.activated_ids.includes(secretId));
    assert.ok(result.expired_ids.includes(secretId));
    assert.equal(mockDb.secrets[0].status, 'expired');

    const activatedEvent = mockDb.secret_events.find(
      (e) => e.secret_id === secretId && e.event_type === 'activated'
    );
    assert.equal(activatedEvent, undefined);
  });

  test('5. Expired secret has ciphertext removed', async () => {
    const secretId = 'secret_shred_cipher';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'TOP_SECRET_CIPHERTEXT',
      iv: 'dummyIv',
      auth_tag: 'dummyAuthTag',
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgmttoken',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    await runLifecycleMaintenance();

    assert.equal(mockDb.secrets[0].ciphertext, null);
  });

  test('6. Expired secret has IV and authentication tag removed', async () => {
    const secretId = 'secret_shred_iv_tag';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'TOP_SECRET_CIPHERTEXT',
      iv: 'SENSITIVE_RANDOM_IV',
      auth_tag: 'SENSITIVE_AUTH_TAG',
      passphrase_hash: '$2b$12$mockpasshash',
      access_code_hash: '$2b$12$mockcodehash',
      management_token_hash: '$2b$12$mockmgmttoken',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    await runLifecycleMaintenance();

    assert.equal(mockDb.secrets[0].iv, null);
    assert.equal(mockDb.secrets[0].auth_tag, null);
  });

  test('7. Expired secret has access-code and passphrase hashes removed', async () => {
    const secretId = 'secret_shred_hashes';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'TOP_SECRET_CIPHERTEXT',
      iv: 'iv123',
      auth_tag: 'tag123',
      passphrase_hash: '$2b$12$passphraseHashToDelete',
      access_code_hash: '$2b$12$accessCodeHashToDelete',
      management_token_hash: '$2b$12$keepThisMgmtHash',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    await runLifecycleMaintenance();

    assert.equal(mockDb.secrets[0].passphrase_hash, null);
    assert.equal(mockDb.secrets[0].access_code_hash, null);
  });

  test('8. Management-token hash remains, so sender dashboard can later show safe expired status', async () => {
    const secretId = 'secret_preserve_mgmt_hash';
    const mgmtHash = '$2b$12$keepThisMgmtHashForever999';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: 'TOP_SECRET_CIPHERTEXT',
      iv: 'iv123',
      auth_tag: 'tag123',
      passphrase_hash: '$2b$12$passphraseHash',
      access_code_hash: '$2b$12$accessCodeHash',
      management_token_hash: mgmtHash,
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    await runLifecycleMaintenance();

    assert.equal(mockDb.secrets[0].management_token_hash, mgmtHash);
    assert.equal(mockDb.secrets[0].id, secretId);
    assert.equal(mockDb.secrets[0].max_views, 1);
  });

  test('9. Burned secret is not changed by sweeper', async () => {
    const secretId = 'secret_already_burned';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: null,
      iv: null,
      auth_tag: null,
      passphrase_hash: null,
      access_code_hash: null,
      management_token_hash: '$2b$12$mgmt',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      max_views: 1,
      views_remaining: 0,
      status: 'burned',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    const result = await runLifecycleMaintenance();

    assert.ok(!result.expired_ids.includes(secretId));
    assert.equal(mockDb.secrets[0].status, 'burned');
    assert.equal(mockDb.secret_events.length, 0);
  });

  test('10. Revoked secret is not changed by sweeper', async () => {
    const secretId = 'secret_already_revoked';
    mockDb.secrets.push({
      id: secretId,
      ciphertext: null,
      iv: null,
      auth_tag: null,
      passphrase_hash: null,
      access_code_hash: null,
      management_token_hash: '$2b$12$mgmt',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'revoked',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    const result = await runLifecycleMaintenance();

    assert.ok(!result.expired_ids.includes(secretId));
    assert.equal(mockDb.secrets[0].status, 'revoked');
    assert.equal(mockDb.secret_events.length, 0);
  });

  test('11. Repeated sweeper runs do not duplicate activated or expired events', async () => {
    const secret1 = 'secret_multi_run_1';
    const secret2 = 'secret_multi_run_2';

    mockDb.secrets.push(
      {
        id: secret1,
        ciphertext: 'cipher1',
        iv: 'iv1',
        auth_tag: 'tag1',
        passphrase_hash: '$2b$12$p1',
        access_code_hash: '$2b$12$a1',
        management_token_hash: '$2b$12$m1',
        available_at: new Date(Date.now() - 5000).toISOString(),
        expires_at: new Date(Date.now() + 60000).toISOString(),
        max_views: 1,
        views_remaining: 1,
        status: 'scheduled',
        created_at: new Date(Date.now() - 10000).toISOString()
      },
      {
        id: secret2,
        ciphertext: 'cipher2',
        iv: 'iv2',
        auth_tag: 'tag2',
        passphrase_hash: '$2b$12$p2',
        access_code_hash: '$2b$12$a2',
        management_token_hash: '$2b$12$m2',
        available_at: new Date(Date.now() - 60000).toISOString(),
        expires_at: new Date(Date.now() - 5000).toISOString(),
        max_views: 1,
        views_remaining: 1,
        status: 'active',
        created_at: new Date(Date.now() - 70000).toISOString()
      }
    );

    // Run sweep 3 consecutive times
    await runLifecycleMaintenance();
    await runLifecycleMaintenance();
    await runLifecycleMaintenance();

    const activatedEvents = mockDb.secret_events.filter(
      (e) => e.secret_id === secret1 && e.event_type === 'activated'
    );
    const expiredEvents = mockDb.secret_events.filter(
      (e) => e.secret_id === secret2 && e.event_type === 'expired'
    );

    assert.equal(activatedEvents.length, 1, 'Activated event must not be duplicated');
    assert.equal(expiredEvents.length, 1, 'Expired event must not be duplicated');
  });

  test('12. Expired secret cannot pass verification or reveal', async () => {
    const rawSecret = 'CANNOT_BE_ACCESSED';
    const encrypted = encryptSecret(rawSecret);
    const code = '123456';
    const pass = 'SuperSecretPassphrase!2026';
    const codeHash = await hashValue(code);
    const passHash = await hashValue(pass);
    const secretId = 'secret_test_expired_access';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: passHash,
      access_code_hash: codeHash,
      management_token_hash: '$2b$12$mgmt',
      available_at: new Date(Date.now() - 60000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(), // Expired
      max_views: 1,
      views_remaining: 1,
      status: 'active',
      created_at: new Date(Date.now() - 70000).toISOString()
    });

    // 1. Run sweeper to mark expired and shred
    await runLifecycleMaintenance();

    // 2. Verification attempt must fail
    const verifyRes = await makeRequest('POST', `/api/secrets/${secretId}/verify`, {
      access_code: code,
      passphrase: pass
    });
    assert.equal(verifyRes.status, 400);

    // 3. Reveal attempt must fail
    const rawToken = generateVerificationToken();
    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });
    assert.equal(revealRes.status, 404);
  });

  test('13. Scheduled secret cannot pass verification or reveal before unlock', async () => {
    const rawSecret = 'LOCKED_UNTIL_FUTURE';
    const encrypted = encryptSecret(rawSecret);
    const code = '654321';
    const pass = 'FutureSecretPassphrase!2026';
    const codeHash = await hashValue(code);
    const passHash = await hashValue(pass);
    const secretId = 'secret_test_scheduled_locked';

    mockDb.secrets.push({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: passHash,
      access_code_hash: codeHash,
      management_token_hash: '$2b$12$mgmt',
      available_at: new Date(Date.now() + 60000).toISOString(), // 1 min in future
      expires_at: new Date(Date.now() + 120000).toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'scheduled',
      created_at: new Date().toISOString()
    });

    // Verification must fail before available_at
    const verifyRes = await makeRequest('POST', `/api/secrets/${secretId}/verify`, {
      access_code: code,
      passphrase: pass
    });
    assert.equal(verifyRes.status, 400);

    // Reveal must fail before available_at
    const rawToken = generateVerificationToken();
    const revealRes = await makeRequest('POST', `/api/secrets/${secretId}/reveal`, {
      verification_token: rawToken
    });
    assert.equal(revealRes.status, 404);
  });

  test('14. Sweeper does not create duplicate intervals', () => {
    stopLifecycleSweeperForTests();

    const interval1 = startLifecycleSweeper();
    const interval2 = startLifecycleSweeper();

    assert.equal(interval1, interval2, 'Subsequent calls must return existing interval');

    stopLifecycleSweeperForTests();
  });
});
