const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');
const { compareValue } = require('../src/services/hashService');
const { decryptSecret } = require('../src/services/cryptoService');

describe('POST /api/secrets Test Suite', () => {
  let server;
  const PORT = 3088;
  const mockDb = {
    secrets: [],
    secret_events: []
  };

  let originalFrom;

  before(() => {
    // Intercept Supabase table operations for testing database payloads
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
          select: () => ({
            limit: async () => ({ data: mockDb[table] || [], error: null, status: 200 })
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

  function postSecret(payload) {
    return new Promise((resolve, reject) => {
      const dataString = JSON.stringify(payload);
      const req = http.request(
        {
          hostname: 'localhost',
          port: PORT,
          path: '/api/secrets',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(dataString)
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
    secret: 'SuperSecretAPIKey-2026-xyz-987654321',
    ttl_seconds: 3600,
    max_views: 2,
    passphrase: 'ComplexPassphrase!99',
    access_code: '654321'
  };

  test('1. Valid active secret creation returns HTTP 201', async () => {
    const res = await postSecret(validPayload);
    assert.equal(res.statusCode, 201);
    assert.ok(res.body.id, 'Response must include id');
    assert.equal(res.body.status, 'active');
    assert.equal(res.body.views_remaining, 2);
    assert.ok(res.body.expires_at, 'Response must include expires_at');
    assert.ok(res.body.available_at, 'Response must include available_at');
    assert.equal(res.body.secret_fingerprint.length, 12);
    assert.ok(res.body.view_url.includes(`/view/${res.body.id}`));
    assert.ok(res.body.manage_url.includes(`/manage/${res.body.id}?token=`));
  });

  test('2. Valid scheduled secret returns scheduled status', async () => {
    const futureDate = new Date(Date.now() + 7200000).toISOString(); // +2 hours
    const res = await postSecret({
      ...validPayload,
      available_at: futureDate
    });

    assert.equal(res.statusCode, 201);
    assert.equal(res.body.status, 'scheduled');
    assert.equal(res.body.available_at, futureDate);

    // Verify scheduled audit event was generated
    const scheduledEvent = mockDb.secret_events.find(e => e.event_type === 'scheduled');
    assert.ok(scheduledEvent, 'Scheduled event must be created for future releases');
  });

  test('3. Missing secret returns HTTP 400', async () => {
    const res = await postSecret({
      ...validPayload,
      secret: ''
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.error);
  });

  test('4. Invalid access code returns HTTP 400', async () => {
    const res1 = await postSecret({ ...validPayload, access_code: '12345' }); // 5 digits
    assert.equal(res1.statusCode, 400);

    const res2 = await postSecret({ ...validPayload, access_code: 'abcdef' }); // non-numeric
    assert.equal(res2.statusCode, 400);
  });

  test('5. Short passphrase returns HTTP 400', async () => {
    const res = await postSecret({
      ...validPayload,
      passphrase: 'short' // < 8 characters
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.error);
  });

  test('6. Invalid TTL returns HTTP 400', async () => {
    const resShort = await postSecret({ ...validPayload, ttl_seconds: 30 }); // < 60s
    assert.equal(resShort.statusCode, 400);

    const resLong = await postSecret({ ...validPayload, ttl_seconds: 90000 }); // > 86400s
    assert.equal(resLong.statusCode, 400);
  });

  test('7. Invalid max_views returns HTTP 400', async () => {
    const resZero = await postSecret({ ...validPayload, max_views: 0 });
    assert.equal(resZero.statusCode, 400);

    const resHigh = await postSecret({ ...validPayload, max_views: 6 });
    assert.equal(resHigh.statusCode, 400);
  });

  test('8. Past available_at returns HTTP 400', async () => {
    const pastDate = new Date(Date.now() - 3600000).toISOString(); // 1 hour ago
    const res = await postSecret({
      ...validPayload,
      available_at: pastDate
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.error);
  });

  test('9. Response never contains plaintext secret', async () => {
    const res = await postSecret(validPayload);
    const rawResponseBody = JSON.stringify(res.body);
    assert.ok(!rawResponseBody.includes(validPayload.secret), 'Response must not contain raw secret');
  });

  test('10. Response never contains passphrase or access code', async () => {
    const res = await postSecret(validPayload);
    const rawResponseBody = JSON.stringify(res.body);
    assert.ok(!rawResponseBody.includes(validPayload.passphrase), 'Response must not contain passphrase');
    assert.ok(!rawResponseBody.includes(validPayload.access_code), 'Response must not contain access code');
  });

  test('11. Supabase row does not contain plaintext secret', async () => {
    const res = await postSecret(validPayload);
    assert.equal(res.statusCode, 201);

    const insertedRow = mockDb.secrets.find(s => s.id === res.body.id);
    assert.ok(insertedRow, 'Secret row must be inserted into Supabase');
    assert.ok(!JSON.stringify(insertedRow).includes(validPayload.secret), 'Database row must not store raw secret');
    assert.ok(insertedRow.ciphertext, 'Database row must store ciphertext');
    assert.ok(insertedRow.iv, 'Database row must store iv');
    assert.ok(insertedRow.auth_tag, 'Database row must store auth_tag');

    // Verify row can be decrypted with the crypto service
    const decrypted = decryptSecret(insertedRow.ciphertext, insertedRow.iv, insertedRow.auth_tag);
    assert.equal(decrypted, validPayload.secret, 'Stored cipher must be cleanly decryptable');
  });

  test('12. Management token stored in database is hashed, not raw', async () => {
    const res = await postSecret(validPayload);
    const tokenMatch = res.body.manage_url.match(/token=([^&]+)/);
    assert.ok(tokenMatch, 'Management token must be present in manage_url');
    const rawToken = tokenMatch[1];

    const insertedRow = mockDb.secrets.find(s => s.id === res.body.id);
    assert.notEqual(insertedRow.management_token_hash, rawToken, 'Management token must not be stored raw');
    assert.ok(!JSON.stringify(insertedRow).includes(rawToken), 'Raw token must not appear in database row');

    const isValidToken = await compareValue(rawToken, insertedRow.management_token_hash);
    assert.equal(isValidToken, true, 'Stored bcrypt hash must verify against raw management token');
  });

  test('13. Correct created audit event is saved', async () => {
    const res = await postSecret(validPayload);
    const createdEvent = mockDb.secret_events.find(e => e.secret_id === res.body.id && e.event_type === 'created');

    assert.ok(createdEvent, 'A created event must be logged in secret_events');
    assert.equal(createdEvent.metadata.max_views, 2);
    assert.equal(createdEvent.metadata.scheduled, false);
    assert.ok(createdEvent.metadata.expires_at);

    // Verify audit event does NOT contain sensitive data
    const eventString = JSON.stringify(createdEvent);
    assert.ok(!eventString.includes(validPayload.secret));
    assert.ok(!eventString.includes(validPayload.passphrase));
    assert.ok(!eventString.includes(validPayload.access_code));
    assert.ok(!eventString.includes('ciphertext'));
  });
});
