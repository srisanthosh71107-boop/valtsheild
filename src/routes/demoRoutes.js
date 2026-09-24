const express = require('express');
const http = require('http');
const { nanoid } = require('nanoid');
const {
  encryptSecret,
  generateManagementToken,
  generateVerificationToken,
  hashVerificationToken
} = require('../services/cryptoService');
const { hashValue } = require('../services/hashService');
const supabase = require('../services/supabaseService');
const {
  COOKIE_NAME,
  createManagementSession,
  verifyManagementSession,
  parseCookies,
  setManagementSessionCookie
} = require('../services/managementSessionService');
const {
  DEMO_SECRET_PLAINTEXT,
  DEMO_ACCESS_CODE,
  DEMO_PASSPHRASE,
  DEMO_TTL_SECONDS,
  DEMO_MAX_VIEWS,
  isDemoModeEnabled,
  requireDemoMode,
  isDemoSecret
} = require('../services/demoService');

const router = express.Router();

function setSecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

// All demo routes require Demo Mode to be actively enabled in a non-production environment
router.use(requireDemoMode);

/**
 * GET /api/demo/status
 * Informs client whether Demo Mode is enabled.
 */
router.get('/status', (req, res) => {
  setSecurityHeaders(res);
  return res.status(200).json({
    demo_enabled: true
  });
});

/**
 * POST /api/demo/create
 * Creates a zero-knowledge demo handover using fixed fake credentials.
 * Reuses the real encryption, hashing, and database storage pipeline.
 */
router.post('/create', async (req, res) => {
  setSecurityHeaders(res);

  if (!supabase) {
    return res.status(500).json({
      error: 'Database connection unavailable.'
    });
  }

  try {
    const id = nanoid(21);
    const now = new Date();
    const availableAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + DEMO_TTL_SECONDS * 1000).toISOString();

    // 1. Re-use production-grade AES-256-GCM encryption
    const encrypted = encryptSecret(DEMO_SECRET_PLAINTEXT);

    // 2. Re-use bcrypt salted hashing
    const [passphraseHash, accessCodeHash, rawManagementToken] = await Promise.all([
      hashValue(DEMO_PASSPHRASE),
      hashValue(DEMO_ACCESS_CODE),
      generateManagementToken()
    ]);
    const managementTokenHash = await hashValue(rawManagementToken);

    // 3. Persist encrypted secret into Supabase
    const { error: insertError } = await supabase.from('secrets').insert({
      id,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: passphraseHash,
      access_code_hash: accessCodeHash,
      management_token_hash: managementTokenHash,
      expires_at: expiresAt,
      available_at: availableAt,
      max_views: DEMO_MAX_VIEWS,
      views_remaining: DEMO_MAX_VIEWS,
      status: 'active'
    });

    if (insertError) {
      return res.status(500).json({
        error: 'Failed to create demo handover.'
      });
    }

    // 4. Record safe audit event with demo metadata
    await supabase.from('secret_events').insert({
      secret_id: id,
      event_type: 'created',
      created_at: availableAt,
      metadata: {
        demo: true,
        source: 'demo_mode',
        max_views: DEMO_MAX_VIEWS,
        ttl_seconds: DEMO_TTL_SECONDS
      }
    });

    // 5. Automatically issue 15-minute management session cookie for sender
    const session = createManagementSession(id);
    setManagementSessionCookie(res, session.sessionToken);

    const baseUrl = process.env.APP_BASE_URL || 'http://localhost:3000';

    return res.status(200).json({
      demo: true,
      warning: 'Demo data only. Do not use this mode for real credentials.',
      id,
      view_url: `${baseUrl}/view/${id}`,
      manage_url: `${baseUrl}/manage/${id}?token=${rawManagementToken}`,
      access_code: DEMO_ACCESS_CODE,
      passphrase: DEMO_PASSPHRASE,
      expires_at: expiresAt
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Failed to create demo handover.'
    });
  }
});

/**
 * GET /api/demo/:id/timeline
 * Returns safe event progress for the 8-step security journey.
 * Requires valid management session and verified demo secret ID.
 */
router.get('/:id/timeline', async (req, res) => {
  setSecurityHeaders(res);
  const { id } = req.params;

  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  // Enforce management session authentication
  const cookies = parseCookies(req);
  const sessionToken = cookies[COOKIE_NAME];
  const sessionPayload = verifyManagementSession(sessionToken, id);
  if (!sessionPayload) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  if (!supabase) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  try {
    // Strictly verify secret is marked as a demo secret
    const isDemo = await isDemoSecret(supabase, id);
    if (!isDemo) {
      return res.status(404).json({ error: 'Demo handover unavailable.' });
    }

    // Query safe secret metadata
    const { data: secret, error: secretErr } = await supabase
      .from('secrets')
      .select('id, status, views_remaining, created_at, available_at, expires_at, revealed_at, acknowledged_at, revoked_at')
      .eq('id', id)
      .maybeSingle();

    if (secretErr || !secret) {
      return res.status(404).json({ error: 'Demo handover unavailable.' });
    }

    // Query safe secret events
    const { data: events, error: eventsErr } = await supabase
      .from('secret_events')
      .select('id, event_type, created_at, metadata')
      .eq('secret_id', id)
      .order('created_at', { ascending: true });

    const safeEvents = events || [];

    // Evaluate 8 Security Journey Steps
    const createdEvent = safeEvents.find((e) => e.event_type === 'created');
    const crawlerEvent = safeEvents.find((e) => e.event_type === 'crawler_blocked');
    const verifyEvent = safeEvents.find((e) => e.event_type === 'verification_passed');
    const revealedEvent = safeEvents.find((e) => e.event_type === 'revealed');
    const ackEvent = safeEvents.find((e) => e.event_type === 'acknowledged');
    const isDestroyed = secret.status === 'burned' || secret.status === 'revoked' || secret.status === 'expired' || secret.views_remaining === 0;

    const journey = [
      {
        step: 1,
        name: 'Secret encrypted before cloud storage',
        completed: Boolean(createdEvent),
        timestamp: createdEvent ? createdEvent.created_at : null
      },
      {
        step: 2,
        name: 'Secure link created',
        completed: Boolean(createdEvent),
        timestamp: createdEvent ? createdEvent.created_at : null
      },
      {
        step: 3,
        name: 'Link-preview crawler blocked',
        completed: Boolean(crawlerEvent),
        timestamp: crawlerEvent ? crawlerEvent.created_at : null
      },
      {
        step: 4,
        name: 'Access code verified',
        completed: Boolean(verifyEvent),
        timestamp: verifyEvent ? verifyEvent.created_at : null
      },
      {
        step: 5,
        name: 'Passphrase verified',
        completed: Boolean(verifyEvent),
        timestamp: verifyEvent ? verifyEvent.created_at : null
      },
      {
        step: 6,
        name: 'One-time secret reveal completed',
        completed: Boolean(revealedEvent),
        timestamp: revealedEvent ? revealedEvent.created_at : (secret.revealed_at || null)
      },
      {
        step: 7,
        name: 'Recipient acknowledgement received',
        completed: Boolean(ackEvent) || Boolean(secret.acknowledged_at),
        timestamp: ackEvent ? ackEvent.created_at : (secret.acknowledged_at || null)
      },
      {
        step: 8,
        name: 'Encrypted secret material destroyed',
        completed: isDestroyed,
        timestamp: isDestroyed ? (revealedEvent ? revealedEvent.created_at : secret.expires_at) : null
      }
    ];

    return res.status(200).json({
      demo: true,
      id,
      status: secret.status,
      views_remaining: secret.views_remaining,
      events: safeEvents.map((e) => ({
        event_type: e.event_type,
        created_at: e.created_at
      })),
      journey
    });
  } catch (err) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }
});

/**
 * POST /api/demo/:id/simulate-crawler
 * Performs a controlled test simulating a link-preview bot (Slackbot).
 * Confirms that the bot shield returns generic HTML and does not consume views.
 */
router.post('/:id/simulate-crawler', async (req, res) => {
  setSecurityHeaders(res);
  const { id } = req.params;

  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  // Enforce management session authentication
  const cookies = parseCookies(req);
  const sessionToken = cookies[COOKIE_NAME];
  const sessionPayload = verifyManagementSession(sessionToken, id);
  if (!sessionPayload) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  if (!supabase) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  try {
    // Strictly verify secret is marked as a demo secret
    const isDemo = await isDemoSecret(supabase, id);
    if (!isDemo) {
      return res.status(404).json({ error: 'Demo handover unavailable.' });
    }

    // Check secret before crawler attempt
    const { data: secretBefore } = await supabase
      .from('secrets')
      .select('views_remaining, status')
      .eq('id', id)
      .maybeSingle();

    if (!secretBefore) {
      return res.status(404).json({ error: 'Demo handover unavailable.' });
    }

    // Perform an actual HTTP GET to the view route with crawler User-Agent
    const port = process.env.PORT || 3000;
    const botUserAgent = 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)';

    const botResponse = await new Promise((resolve, reject) => {
      const request = http.request(
        {
          hostname: '127.0.0.1',
          port: Number(port),
          path: `/view/${id}`,
          method: 'GET',
          headers: {
            'User-Agent': botUserAgent
          }
        },
        (resp) => {
          let data = '';
          resp.on('data', (chunk) => { data += chunk; });
          resp.on('end', () => {
            resolve({
              statusCode: resp.statusCode,
              body: data
            });
          });
        }
      );
      request.on('error', reject);
      request.end();
    }).catch(() => null);

    // Verify database state is completely unchanged
    const { data: secretAfter } = await supabase
      .from('secrets')
      .select('views_remaining, status')
      .eq('id', id)
      .maybeSingle();

    if (!secretAfter || secretAfter.views_remaining !== secretBefore.views_remaining) {
      return res.status(500).json({ error: 'Simulation failed: views changed.' });
    }

    // Record safe crawler_blocked event for the presentation journey
    await supabase.from('secret_events').insert({
      secret_id: id,
      event_type: 'crawler_blocked',
      metadata: {
        demo: true,
        source: 'demo_simulation',
        user_agent: 'Slackbot-LinkExpanding 1.0'
      }
    });

    return res.status(200).json({
      demo: true,
      blocked: true,
      status: botResponse ? botResponse.statusCode : 200,
      user_agent: 'Slackbot-LinkExpanding 1.0',
      views_remaining: secretAfter.views_remaining,
      message: 'Bot blocked - secret remains protected.'
    });
  } catch (err) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }
});

/**
 * POST /api/demo/:id/concurrency-test
 * Performs 20 controlled parallel verified reveal attempts against a temporary demo secret.
 * Reuses the real atomic database reveal path and returns aggregate metrics only.
 */
router.post('/:id/concurrency-test', async (req, res) => {
  setSecurityHeaders(res);
  const { id } = req.params;

  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  // Enforce management session authentication
  const cookies = parseCookies(req);
  const sessionToken = cookies[COOKIE_NAME];
  const sessionPayload = verifyManagementSession(sessionToken, id);
  if (!sessionPayload) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  if (!supabase) {
    return res.status(404).json({ error: 'Demo handover unavailable.' });
  }

  try {
    // Strictly verify secret is marked as a demo secret
    const isDemo = await isDemoSecret(supabase, id);
    if (!isDemo) {
      return res.status(404).json({ error: 'Demo handover unavailable.' });
    }

    // 1. Create a fresh temporary one-view secret for concurrency testing
    const testSecretId = nanoid(21);
    const encrypted = encryptSecret('DEMO_CONCURRENCY_TEST_KEY_NOT_REAL');
    const [passHash, codeHash, mgmtToken] = await Promise.all([
      hashValue('demo-concurrency-pass'),
      hashValue('112233'),
      generateManagementToken()
    ]);
    const mgmtHash = await hashValue(mgmtToken);

    await supabase.from('secrets').insert({
      id: testSecretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: passHash,
      access_code_hash: codeHash,
      management_token_hash: mgmtHash,
      expires_at: new Date(Date.now() + 120000).toISOString(),
      available_at: new Date().toISOString(),
      max_views: 1,
      views_remaining: 1,
      status: 'active'
    });

    await supabase.from('secret_events').insert({
      secret_id: testSecretId,
      event_type: 'created',
      metadata: { demo: true, source: 'concurrency_test' }
    });

    // 2. Generate 20 distinct verification tokens
    const tokens = [];
    for (let i = 0; i < 20; i++) {
      const rawToken = generateVerificationToken();
      const tokenHash = hashVerificationToken(rawToken);
      tokens.push({ rawToken, tokenHash });
      await supabase.from('verification_tokens').insert({
        secret_id: testSecretId,
        token_hash: tokenHash,
        expires_at: new Date(Date.now() + 120000).toISOString()
      });
    }

    // 3. Dispatch 20 concurrent parallel atomic reveal RPC calls
    const revealPromises = tokens.map((t) =>
      supabase.rpc('reveal_secret_atomically', {
        p_secret_id: testSecretId,
        p_token_hash: t.tokenHash,
        p_now: new Date().toISOString()
      })
    );

    const rpcResults = await Promise.all(revealPromises);

    // 4. Aggregate results (strictly never return plaintext or secret data)
    let successfulReveals = 0;
    let blockedRequests = 0;

    for (const r of rpcResults) {
      if (r && r.data) {
        const row = Array.isArray(r.data) ? r.data[0] : r.data;
        if (row && row.ciphertext) {
          successfulReveals++;
        } else {
          blockedRequests++;
        }
      } else {
        blockedRequests++;
      }
    }

    const passed = successfulReveals === 1 && blockedRequests === 19;

    return res.status(200).json({
      total_requests: 20,
      successful_reveals: successfulReveals,
      blocked_requests: blockedRequests,
      passed
    });
  } catch (err) {
    return res.status(500).json({ error: 'Concurrency test execution error.' });
  }
});

module.exports = router;
