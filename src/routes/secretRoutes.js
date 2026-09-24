const express = require('express');
const { nanoid } = require('nanoid');
const {
  encryptSecret,
  decryptSecret,
  createFingerprint,
  generateManagementToken,
  generateVerificationToken,
  hashVerificationToken,
  generateAcknowledgementToken,
  hashAcknowledgementToken
} = require('../services/cryptoService');
const { hashValue, compareValue } = require('../services/hashService');
const supabase = require('../services/supabaseService');
const {
  getClientIp,
  isRateLimited,
  recordFailedAttempt,
  clearAttempts
} = require('../services/verificationRateLimitService');
const {
  COOKIE_NAME,
  verifyManagementSession,
  parseCookies
} = require('../services/managementSessionService');
const {
  sensitiveHeadersMiddleware,
  createSecretLimiter,
  revealLimiter,
  panicBurnLimiter
} = require('../middleware/securityMiddleware');

const router = express.Router();

const BOT_PATTERNS = [
  'bot',
  'crawl',
  'crawler',
  'spider',
  'slackbot',
  'discordbot',
  'whatsapp',
  'twitterbot',
  'facebookexternalhit',
  'linkedinbot',
  'telegrambot'
];

function isBotRequest(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return BOT_PATTERNS.some((pattern) => ua.includes(pattern));
}

const GENERIC_VERIFY_ERROR = 'Secure handover unavailable or verification failed.';
const RATE_LIMIT_ERROR = 'Too many verification attempts. Please try again later.';

/**
 * POST /api/secrets
 * Creates a new zero-knowledge encrypted handover room.
 */
router.post('/secrets', createSecretLimiter, async (req, res) => {
  try {
    const { secret, ttl_seconds, max_views, available_at, passphrase, access_code } = req.body || {};

    // 1. Validation Rules
    if (!secret || typeof secret !== 'string' || secret.length < 1 || secret.length > 10000) {
      return res.status(400).json({
        error: 'Secret is required and must be a string between 1 and 10,000 characters.'
      });
    }

    if (!Number.isInteger(ttl_seconds) || ttl_seconds < 60 || ttl_seconds > 86400) {
      return res.status(400).json({
        error: 'ttl_seconds is required and must be an integer between 60 and 86,400 seconds.'
      });
    }

    if (!Number.isInteger(max_views) || max_views < 1 || max_views > 5) {
      return res.status(400).json({
        error: 'max_views is required and must be an integer between 1 and 5.'
      });
    }

    if (typeof access_code !== 'string' || !/^\d{6}$/.test(access_code)) {
      return res.status(400).json({
        error: 'access_code is required and must be exactly 6 numeric digits.'
      });
    }

    if (typeof passphrase !== 'string' || passphrase.length < 8 || passphrase.length > 128) {
      return res.status(400).json({
        error: 'passphrase is required and must be a string between 8 and 128 characters.'
      });
    }

    const now = new Date();
    let availableAt;
    let status = 'active';

    if (available_at !== undefined && available_at !== null && available_at !== '') {
      if (typeof available_at !== 'string' || isNaN(Date.parse(available_at))) {
        return res.status(400).json({
          error: 'available_at must be a valid ISO-8601 date string.'
        });
      }

      const parsedAvailable = new Date(available_at);
      // Small 5s clock-skew leeway for network flight time, but rejects past timestamps
      if (parsedAvailable.getTime() < now.getTime() - 5000) {
        return res.status(400).json({
          error: 'available_at cannot be in the past.'
        });
      }

      availableAt = parsedAvailable;
      if (availableAt.getTime() > now.getTime()) {
        status = 'scheduled';
      }
    } else {
      availableAt = now;
    }

    const expiresAt = new Date(availableAt.getTime() + ttl_seconds * 1000);
    if (expiresAt.getTime() <= availableAt.getTime()) {
      return res.status(400).json({
        error: 'expires_at must be strictly later than available_at.'
      });
    }

    // 2. Cryptographic and Hashing Operations
    const secretId = nanoid();
    const encrypted = encryptSecret(secret);
    const secretFingerprint = createFingerprint(secret);
    const rawManagementToken = generateManagementToken();

    const [passphraseHash, accessCodeHash, managementTokenHash] = await Promise.all([
      hashValue(passphrase),
      hashValue(access_code),
      hashValue(rawManagementToken)
    ]);

    // 3. Database Persistence (Supabase)
    if (!supabase) {
      return res.status(500).json({
        error: 'Unable to create secure handover.'
      });
    }

    const { error: insertError } = await supabase.from('secrets').insert({
      id: secretId,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      auth_tag: encrypted.authTag,
      passphrase_hash: passphraseHash,
      access_code_hash: accessCodeHash,
      management_token_hash: managementTokenHash,
      expires_at: expiresAt.toISOString(),
      available_at: availableAt.toISOString(),
      max_views: max_views,
      views_remaining: max_views,
      status: status,
      created_at: now.toISOString()
    });

    if (insertError) {
      return res.status(500).json({
        error: 'Unable to create secure handover.'
      });
    }

    // Record safe audit event
    await supabase.from('secret_events').insert({
      secret_id: secretId,
      event_type: 'created',
      created_at: now.toISOString(),
      metadata: {
        max_views: max_views,
        scheduled: status === 'scheduled',
        expires_at: expiresAt.toISOString()
      }
    });

    if (status === 'scheduled') {
      await supabase.from('secret_events').insert({
        secret_id: secretId,
        event_type: 'scheduled',
        created_at: now.toISOString(),
        metadata: {
          available_at: availableAt.toISOString(),
          expires_at: expiresAt.toISOString()
        }
      });
    }

    // 4. Response Dispatch
    const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const viewUrl = `${appBaseUrl}/view/${secretId}`;
    const manageUrl = `${appBaseUrl}/manage/${secretId}?token=${rawManagementToken}`;

    return res.status(201).json({
      id: secretId,
      view_url: viewUrl,
      manage_url: manageUrl,
      expires_at: expiresAt.toISOString(),
      available_at: availableAt.toISOString(),
      views_remaining: max_views,
      status: status,
      secret_fingerprint: secretFingerprint
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Unable to create secure handover.'
    });
  }
});

/**
 * POST /api/secrets/:id/verify
 * Verifies access code and passphrase, issuing a short-lived 2-minute single-use token.
 */
router.post('/secrets/:id/verify', sensitiveHeadersMiddleware, express.json({ limit: '5kb' }), async (req, res) => {
  const { id } = req.params;
  const clientIp = getClientIp(req);

  // 1. Bot Protection - Return generic unavailable response without touching database
  if (isBotRequest(req)) {
    return res.status(400).json({
      error: GENERIC_VERIFY_ERROR
    });
  }

  // 2. Server-side Rate Limiting Check
  if (isRateLimited(clientIp, id)) {
    return res.status(429).json({
      error: RATE_LIMIT_ERROR
    });
  }

  // 3. Format Validation
  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    recordFailedAttempt(clientIp, id);
    return res.status(400).json({
      error: GENERIC_VERIFY_ERROR
    });
  }

  const { access_code, passphrase } = req.body || {};

  if (typeof access_code !== 'string' || !/^\d{6}$/.test(access_code)) {
    recordFailedAttempt(clientIp, id);
    return res.status(400).json({
      error: GENERIC_VERIFY_ERROR
    });
  }

  if (typeof passphrase !== 'string' || passphrase.length < 1 || passphrase.length > 128) {
    recordFailedAttempt(clientIp, id);
    return res.status(400).json({
      error: GENERIC_VERIFY_ERROR
    });
  }

  if (!supabase) {
    recordFailedAttempt(clientIp, id);
    return res.status(400).json({
      error: GENERIC_VERIFY_ERROR
    });
  }

  try {
    // 4. Read Required Backend-Only Metadata from Supabase
    // Never read ciphertext, iv, auth_tag, or management_token_hash
    const { data: secret, error } = await supabase
      .from('secrets')
      .select('id, access_code_hash, passphrase_hash, status, available_at, expires_at, views_remaining')
      .eq('id', id)
      .maybeSingle();

    if (error || !secret) {
      recordFailedAttempt(clientIp, id);
      return res.status(400).json({
        error: GENERIC_VERIFY_ERROR
      });
    }

    const now = new Date();
    const availableAt = new Date(secret.available_at);
    const expiresAt = new Date(secret.expires_at);

    // 5. Lifecycle and Schedule State Checks
    if (
      secret.status !== 'active' ||
      availableAt > now ||
      expiresAt <= now ||
      secret.views_remaining <= 0
    ) {
      recordFailedAttempt(clientIp, id);
      await supabase.from('secret_events').insert({
        secret_id: id,
        event_type: 'verification_failed',
        metadata: { reason: 'generic_verification_failure' }
      });
      return res.status(400).json({
        error: GENERIC_VERIFY_ERROR
      });
    }

    // 6. Multi-Factor Bcrypt Verification
    const [codeMatch, passMatch] = await Promise.all([
      compareValue(access_code, secret.access_code_hash),
      compareValue(passphrase, secret.passphrase_hash)
    ]);

    if (!codeMatch || !passMatch) {
      recordFailedAttempt(clientIp, id);
      await supabase.from('secret_events').insert({
        secret_id: id,
        event_type: 'verification_failed',
        metadata: { reason: 'generic_verification_failure' }
      });
      return res.status(400).json({
        error: GENERIC_VERIFY_ERROR
      });
    }

    // 7. Successful Verification
    // Clear failed attempts upon successful authentication
    clearAttempts(clientIp, id);

    // Generate random URL-safe 32-byte token and hash with SHA-256
    const rawVerificationToken = generateVerificationToken();
    const tokenHash = hashVerificationToken(rawVerificationToken);
    const tokenExpiresAt = new Date(Date.now() + 120 * 1000).toISOString(); // 2 minutes validity

    // Persist only SHA-256 hash in verification_tokens
    await supabase.from('verification_tokens').insert({
      secret_id: id,
      token_hash: tokenHash,
      expires_at: tokenExpiresAt
    });

    // Record safe audit event (never log credentials or tokens)
    await supabase.from('secret_events').insert({
      secret_id: id,
      event_type: 'verification_passed',
      metadata: {
        expires_in_seconds: 120
      }
    });

    // Return single-use raw token to client
    return res.status(200).json({
      verified: true,
      verification_token: rawVerificationToken,
      expires_in_seconds: 120
    });
  } catch (err) {
    recordFailedAttempt(clientIp, id);
    return res.status(400).json({
      error: GENERIC_VERIFY_ERROR
    });
  }
});

const GENERIC_REVEAL_ERROR = 'Secret not found, expired, or already destroyed.';

/**
 * POST /api/secrets/:id/reveal
 * Atomically consumes a one-time verification token, decrypts the secret,
 * decrements quota, shreds payload if views become zero, and records an audit log.
 */
router.post('/secrets/:id/reveal', sensitiveHeadersMiddleware, revealLimiter, express.json({ limit: '5kb' }), async (req, res) => {

  // 1. Reject bot User-Agents immediately
  if (isBotRequest(req)) {
    return res.status(404).json({
      error: GENERIC_REVEAL_ERROR
    });
  }

  const { id } = req.params;
  const { verification_token } = req.body || {};

  // 2. Validate format
  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(404).json({
      error: GENERIC_REVEAL_ERROR
    });
  }

  if (
    !verification_token ||
    typeof verification_token !== 'string' ||
    verification_token.length < 16 ||
    verification_token.length > 256
  ) {
    return res.status(404).json({
      error: GENERIC_REVEAL_ERROR
    });
  }

  if (!supabase) {
    return res.status(404).json({
      error: GENERIC_REVEAL_ERROR
    });
  }

  try {
    // 3. Compute SHA-256 hash of the raw verification token
    const tokenHash = hashVerificationToken(verification_token);
    const now = new Date().toISOString();

    // 4. Call atomic database RPC function
    const { data: revealResult, error: rpcError } = await supabase.rpc('reveal_secret_atomically', {
      p_secret_id: id,
      p_token_hash: tokenHash,
      p_now: now
    });

    if (rpcError || !revealResult) {
      return res.status(404).json({
        error: GENERIC_REVEAL_ERROR
      });
    }

    const row = Array.isArray(revealResult) ? revealResult[0] : revealResult;
    if (!row || !row.ciphertext || !row.iv || !row.auth_tag) {
      return res.status(404).json({
        error: GENERIC_REVEAL_ERROR
      });
    }

    // 5. Decrypt exclusively in the Express backend
    let plaintext;
    try {
      plaintext = decryptSecret(row.ciphertext, row.iv, row.auth_tag);
    } catch (decryptErr) {
      return res.status(404).json({
        error: GENERIC_REVEAL_ERROR
      });
    }

    // 6. Record safe audit event (never log plaintext or cipher material)
    await supabase.from('secret_events').insert({
      secret_id: id,
      event_type: 'revealed',
      created_at: now,
      metadata: {
        views_remaining: row.views_remaining,
        burned: Boolean(row.burned)
      }
    });

    // 7. Generate single-use acknowledgement token with 32 bytes entropy
    const rawAcknowledgementToken = generateAcknowledgementToken();
    const ackTokenHash = hashAcknowledgementToken(rawAcknowledgementToken);
    const ackExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // Persist only SHA-256 hash in acknowledgement_tokens table
    await supabase.from('acknowledgement_tokens').insert({
      secret_id: id,
      token_hash: ackTokenHash,
      expires_at: ackExpiresAt
    });

    // 8. Return plaintext and acknowledgement token only in this single winning response
    return res.status(200).json({
      secret: plaintext,
      views_remaining: row.views_remaining,
      burned: Boolean(row.burned),
      display_seconds: 15,
      acknowledgement_token: rawAcknowledgementToken,
      acknowledgement_expires_in_seconds: 900
    });
  } catch (err) {
    return res.status(404).json({
      error: GENERIC_REVEAL_ERROR
    });
  }
});

const GENERIC_PANIC_BURN_ERROR = 'Secure handover unavailable.';

/**
 * POST /api/secrets/:id/panic-burn
 * Atomically revokes and cryptographically shreds an active or scheduled secret.
 * Requires a valid management session cookie and matching anti-CSRF token.
 */
router.post('/secrets/:id/panic-burn', sensitiveHeadersMiddleware, panicBurnLimiter, express.json({ limit: '5kb' }), async (req, res) => {

  // 1. Bot shielding
  if (isBotRequest(req)) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }

  const { id } = req.params;

  // 2. Validate ID format
  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }

  // 3. Require valid management session cookie matching :id
  const cookies = parseCookies(req);
  const sessionToken = cookies[COOKIE_NAME];

  if (!sessionToken) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }

  const sessionPayload = verifyManagementSession(sessionToken, id);
  if (!sessionPayload) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }

  // 4. Require anti-CSRF token verification
  const clientCsrf = req.headers['x-csrf-token'] || (req.body && req.body.csrf_token);
  if (!clientCsrf || typeof clientCsrf !== 'string' || clientCsrf !== sessionPayload.csrf) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }

  if (!supabase) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }

  try {
    const now = new Date().toISOString();

    // 5. Execute atomic database RPC function panic_burn_secret_atomically
    const { data: burnResult, error: rpcError } = await supabase.rpc('panic_burn_secret_atomically', {
      p_secret_id: id,
      p_now: now
    });

    if (rpcError || !burnResult) {
      return res.status(400).json({
        error: GENERIC_PANIC_BURN_ERROR
      });
    }

    const row = Array.isArray(burnResult) ? burnResult[0] : burnResult;
    if (!row || !row.id || row.status !== 'revoked') {
      return res.status(400).json({
        error: GENERIC_PANIC_BURN_ERROR
      });
    }

    // 6. Record safe panic_burned audit event
    await supabase.from('secret_events').insert({
      secret_id: id,
      event_type: 'panic_burned',
      created_at: now,
      metadata: {
        source: 'sender_management_dashboard'
      }
    });

    // 7. Return success response
    return res.status(200).json({
      success: true,
      status: 'revoked',
      message: 'Secure handover permanently revoked.'
    });
  } catch (err) {
    return res.status(400).json({
      error: GENERIC_PANIC_BURN_ERROR
    });
  }
});

const GENERIC_ACK_ERROR = 'Secure handover unavailable.';

/**
 * POST /api/secrets/:id/acknowledge
 * Atomically validates a recipient's one-time acknowledgement token,
 * marks secrets.acknowledged_at, and records a safe audit event.
 */
router.post('/secrets/:id/acknowledge', sensitiveHeadersMiddleware, express.json({ limit: '5kb' }), async (req, res) => {

  // 1. Reject bot User-Agents immediately without database queries
  if (isBotRequest(req)) {
    return res.status(404).json({
      error: GENERIC_ACK_ERROR
    });
  }

  const { id } = req.params;
  const { acknowledgement_token } = req.body || {};

  // 2. Validate format
  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(404).json({
      error: GENERIC_ACK_ERROR
    });
  }

  if (
    !acknowledgement_token ||
    typeof acknowledgement_token !== 'string' ||
    acknowledgement_token.length < 16 ||
    acknowledgement_token.length > 256
  ) {
    return res.status(404).json({
      error: GENERIC_ACK_ERROR
    });
  }

  if (!supabase) {
    return res.status(404).json({
      error: GENERIC_ACK_ERROR
    });
  }

  try {
    // 3. Compute SHA-256 hash of the raw acknowledgement token
    const tokenHash = hashAcknowledgementToken(acknowledgement_token);
    const now = new Date().toISOString();

    // 4. Call atomic database RPC function
    const { data: ackResult, error: rpcError } = await supabase.rpc('acknowledge_secret_atomically', {
      p_secret_id: id,
      p_token_hash: tokenHash,
      p_now: now
    });

    if (rpcError || !ackResult) {
      return res.status(404).json({
        error: GENERIC_ACK_ERROR
      });
    }

    const row = Array.isArray(ackResult) ? ackResult[0] : ackResult;
    if (!row || !row.secret_id || !row.acknowledged_at) {
      return res.status(404).json({
        error: GENERIC_ACK_ERROR
      });
    }

    // 5. Insert safe audit event (never log secret, credentials, or recipient identity)
    await supabase.from('secret_events').insert({
      secret_id: id,
      event_type: 'acknowledged',
      created_at: now,
      metadata: {
        source: 'recipient_acknowledgement'
      }
    });

    // 6. Return success response
    return res.status(200).json({
      acknowledged: true,
      acknowledged_at: row.acknowledged_at
    });
  } catch (err) {
    return res.status(404).json({
      error: GENERIC_ACK_ERROR
    });
  }
});

module.exports = router;



