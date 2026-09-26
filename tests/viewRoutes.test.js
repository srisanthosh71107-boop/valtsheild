const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../src/server');
const supabase = require('../src/services/supabaseService');

describe('GET /view/:id and Scraper Shield Test Suite', () => {
  let server;
  const PORT = 3089;

  const mockDb = {
    secrets: [],
    secret_events: []
  };

  let originalFrom;

  before(() => {
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
                
                // Return only requested fields
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
    mockDb.secrets = [
      {
        id: 'active_secret_1234567890abcdef',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: '$2b$12$mockpasshash1234567890',
        access_code_hash: '$2b$12$mockcodehash1234567890',
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 3600000).toISOString(), // +1 hour
        available_at: new Date(Date.now() - 60000).toISOString(), // -1 min (active)
        max_views: 2,
        views_remaining: 2,
        status: 'active'
      },
      {
        id: 'scheduled_secret_123456789abcdef',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: '$2b$12$mockpasshash1234567890',
        access_code_hash: '$2b$12$mockcodehash1234567890',
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 7200000).toISOString(), // +2 hours
        available_at: new Date(Date.now() + 3600000).toISOString(), // +1 hour (future)
        max_views: 1,
        views_remaining: 1,
        status: 'scheduled'
      },
      {
        id: 'expired_secret_123456789abcdef',
        ciphertext: 'AQIDBAUGCAkKCw==',
        iv: '123456789012',
        auth_tag: 'abcdefghijklmnop',
        passphrase_hash: '$2b$12$mockpasshash1234567890',
        access_code_hash: '$2b$12$mockcodehash1234567890',
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() - 3600000).toISOString(), // -1 hour
        available_at: new Date(Date.now() - 7200000).toISOString(),
        max_views: 1,
        views_remaining: 1,
        status: 'expired'
      },
      {
        id: 'burned_secret_1234567890abcdef',
        ciphertext: null,
        iv: null,
        auth_tag: null,
        passphrase_hash: '$2b$12$mockpasshash1234567890',
        access_code_hash: '$2b$12$mockcodehash1234567890',
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        available_at: new Date(Date.now() - 60000).toISOString(),
        max_views: 1,
        views_remaining: 0,
        status: 'burned'
      },
      {
        id: 'revoked_secret_1234567890abcdef',
        ciphertext: null,
        iv: null,
        auth_tag: null,
        passphrase_hash: '$2b$12$mockpasshash1234567890',
        access_code_hash: '$2b$12$mockcodehash1234567890',
        management_token_hash: '$2b$12$mocktokenhash12345678',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        available_at: new Date(Date.now() - 60000).toISOString(),
        max_views: 1,
        views_remaining: 1,
        status: 'revoked'
      }
    ];
    mockDb.secret_events = [];
  });

  function getRequest(path, userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)') {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port: PORT,
          path,
          method: 'GET',
          headers: {
            'User-Agent': userAgent
          }
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => { body += chunk; });
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              body
            });
          });
        }
      );
      req.on('error', reject);
      req.end();
    });
  }

  // --- BOT SHIELD TESTS ---

  test('1. Fake Slackbot User-Agent receives generic bot shield page', async () => {
    const res = await getRequest('/view/active_secret_1234567890abcdef', 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('<title>Secure Handover</title>'));
    assert.ok(res.body.includes('Human verification required to access this secure handover.'));
    assert.ok(!res.body.includes('active_secret_1234567890abcdef'));
    assert.ok(!res.body.includes('views_remaining'));
    assert.equal(res.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');
    assert.equal(res.headers['pragma'], 'no-cache');
    assert.equal(res.headers['x-robots-tag'], 'noindex, nofollow, noarchive');
  });

  test('2. Case-insensitive crawler and bot User-Agents are shielded', async () => {
    const botAgents = [
      'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
      'WhatsApp/2.21.12.21 A',
      'Twitterbot/1.0',
      'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
      'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
      'TelegramBot (like TwitterBot)',
      'Googlebot/2.1 (+http://www.google.com/bot.html)',
      'Custom-Web-Crawler/3.0',
      'Generic-Spider/1.0'
    ];

    for (const ua of botAgents) {
      const res = await getRequest('/view/active_secret_1234567890abcdef', ua);
      assert.equal(res.statusCode, 200, `Failed for UA: ${ua}`);
      assert.ok(res.body.includes('<title>Secure Handover</title>'), `Title missing for UA: ${ua}`);
      assert.ok(res.body.includes('Human verification required to access this secure handover.'), `Message missing for UA: ${ua}`);
      assert.ok(!res.body.includes('active_secret_1234567890abcdef'), `Secret ID leaked for UA: ${ua}`);
    }
  });

  // --- HUMAN RECIPIENT ACTIVE PAGE TESTS ---

  test('3. Human browser on active secret receives active verification UI', async () => {
    const res = await getRequest('/view/active_secret_1234567890abcdef');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('You have received a secure handover'));
    assert.ok(res.body.includes('Verify your secure handover details to reveal this secret.'));
    assert.ok(res.body.includes('Active'));
    assert.ok(res.body.includes('Expiry Countdown'));
    assert.ok(res.body.includes('Expiry date/time'));
    assert.ok(res.body.includes('Views remaining'));
    assert.ok(res.body.includes('id="access-code-input"'));
    assert.ok(res.body.includes('id="passphrase-input"'));
    assert.ok(res.body.includes('Verify Secure Handover'));
    assert.ok(res.body.includes('This secret will be revealed only after verification and can be accessed only once.'));
    
    // Check security headers
    assert.equal(res.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');
    assert.equal(res.headers['pragma'], 'no-cache');
    assert.equal(res.headers['x-robots-tag'], 'noindex, nofollow, noarchive');

    // Safe metadata container present
    assert.ok(res.body.includes('data-id="active_secret_1234567890abcdef"'));
    assert.ok(res.body.includes('data-status="active"'));

    // Sensitive cryptographic material MUST NOT be present
    assert.ok(!res.body.includes('AQIDBAUGCAkKCw==')); // ciphertext
    assert.ok(!res.body.includes('123456789012')); // iv
    assert.ok(!res.body.includes('abcdefghijklmnop')); // auth tag
    assert.ok(!res.body.includes('mockpasshash')); // passphrase hash
    assert.ok(!res.body.includes('mockcodehash')); // access code hash
    assert.ok(!res.body.includes('mocktokenhash')); // management token hash
  });

  // --- HUMAN RECIPIENT SCHEDULED PAGE TESTS ---

  test('4. Human browser on scheduled secret receives scheduled locked UI', async () => {
    const res = await getRequest('/view/scheduled_secret_123456789abcdef');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('Secure Handover Scheduled'));
    assert.ok(res.body.includes('This handover is not available yet.'));
    assert.ok(res.body.includes('Scheduled'));
    assert.ok(res.body.includes('Scheduled Unlock Countdown'));
    assert.ok(res.body.includes('Scheduled unlock date/time'));
    assert.ok(res.body.includes('Expiry date/time'));
    assert.ok(res.body.includes('Access becomes available automatically at the scheduled time.'));
    
    // Inputs must be disabled
    assert.ok(res.body.includes('id="access-code-input"'));
    assert.ok(res.body.includes('disabled'));
    assert.ok(res.body.includes('id="passphrase-input"'));
    assert.ok(res.body.includes('id="verify-btn" class="submit-btn" disabled'));
  });

  // --- UNAVAILABLE / EXPIRED / REVOKED / DESTROYED TESTS ---

  test('5. Non-existent secret returns generic unavailable page', async () => {
    const res = await getRequest('/view/nonexistent_secret_9999999999');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('<title>Secure Handover Unavailable</title>'));
    assert.ok(res.body.includes('Secure Handover Unavailable'));
    assert.ok(res.body.includes('This secure handover is unavailable, expired, or has already been destroyed.'));
    assert.ok(res.body.includes('Return to VaultLink'));
  });

  test('6. Expired secret returns generic unavailable page', async () => {
    const res = await getRequest('/view/expired_secret_123456789abcdef');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('<title>Secure Handover Unavailable</title>'));
    assert.ok(res.body.includes('This secure handover is unavailable, expired, or has already been destroyed.'));
  });

  test('7. Burned secret returns generic unavailable page', async () => {
    const res = await getRequest('/view/burned_secret_1234567890abcdef');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('<title>Secure Handover Unavailable</title>'));
    assert.ok(res.body.includes('This secure handover is unavailable, expired, or has already been destroyed.'));
  });

  test('8. Revoked secret returns generic unavailable page', async () => {
    const res = await getRequest('/view/revoked_secret_1234567890abcdef');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('<title>Secure Handover Unavailable</title>'));
    assert.ok(res.body.includes('This secure handover is unavailable, expired, or has already been destroyed.'));
  });

  test('9. Invalid ID format returns generic unavailable page', async () => {
    const res = await getRequest('/view/invalid!id@characters#');
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes('<title>Secure Handover Unavailable</title>'));
    assert.ok(res.body.includes('This secure handover is unavailable, expired, or has already been destroyed.'));
  });

  // --- INVARIANT CHECKS: ZERO DATABASE MUTATION ---

  test('10. GET /view/:id never alters any database row or inserts audit events', async () => {
    const initialSecretsSnapshot = JSON.stringify(mockDb.secrets);
    const initialEventsCount = mockDb.secret_events.length;

    // Perform multiple GET requests across active, scheduled, expired, and bot user agents
    await getRequest('/view/active_secret_1234567890abcdef');
    await getRequest('/view/scheduled_secret_123456789abcdef');
    await getRequest('/view/expired_secret_123456789abcdef');
    await getRequest('/view/active_secret_1234567890abcdef', 'Slackbot 1.0');
    await getRequest('/view/nonexistent_secret_9999999999');

    // Confirm secrets table is completely unmodified
    assert.equal(JSON.stringify(mockDb.secrets), initialSecretsSnapshot, 'Database secrets must not be modified by GET requests');
    
    // Confirm no audit events were inserted
    assert.equal(mockDb.secret_events.length, initialEventsCount, 'No audit events should be created on GET requests');
  });
});
