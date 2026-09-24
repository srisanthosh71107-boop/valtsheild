const express = require('express');
const router = express.Router();
const supabase = require('../services/supabaseService');
const { compareValue } = require('../services/hashService');
const {
  COOKIE_NAME,
  createManagementSession,
  verifyManagementSession,
  parseCookies,
  setManagementSessionCookie
} = require('../services/managementSessionService');
const {
  renderUnavailablePage,
  renderDashboardPage
} = require('../views/viewTemplates');

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

function setManagementSecurityHeaders(res) {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

/**
 * GET /manage/:id
 * Handles token exchange (?token=...) and session-authenticated sender dashboard.
 */
router.get('/manage/:id', async (req, res) => {
  setManagementSecurityHeaders(res);

  // 1. Bot shielding
  if (isBotRequest(req)) {
    return res.status(200).send(renderUnavailablePage());
  }

  const { id } = req.params;
  const rawToken = req.query.token;

  // 2. Validate id format
  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(200).send(renderUnavailablePage());
  }

  if (!supabase) {
    return res.status(200).send(renderUnavailablePage());
  }

  // 3. Token exchange flow when query string ?token=... is present
  if (rawToken) {
    if (typeof rawToken !== 'string' || rawToken.length < 16 || rawToken.length > 256) {
      return res.status(200).send(renderUnavailablePage());
    }

    try {
      // Query strictly id and management_token_hash
      const { data: secret, error } = await supabase
        .from('secrets')
        .select('id, management_token_hash')
        .eq('id', id)
        .maybeSingle();

      if (error || !secret || !secret.management_token_hash) {
        return res.status(200).send(renderUnavailablePage());
      }

      // Verify token hash via bcrypt
      const isMatch = await compareValue(rawToken, secret.management_token_hash);
      if (!isMatch) {
        return res.status(200).send(renderUnavailablePage());
      }

      // Issue signed management session
      const { sessionToken } = createManagementSession(id);
      setManagementSessionCookie(res, sessionToken);

      // Clean redirect: strips the raw token from browser URL and history
      return res.redirect(`/manage/${encodeURIComponent(id)}`);
    } catch (err) {
      return res.status(200).send(renderUnavailablePage());
    }
  }

  // 4. Authenticated dashboard flow via session cookie
  const cookies = parseCookies(req);
  const sessionCookie = cookies[COOKIE_NAME];

  if (!sessionCookie) {
    return res.status(200).send(renderUnavailablePage());
  }

  const sessionPayload = verifyManagementSession(sessionCookie, id);
  if (!sessionPayload) {
    return res.status(200).send(renderUnavailablePage());
  }

  try {
    // Query ONLY safe telemetry metadata fields from Supabase
    // Strictly never select ciphertext, iv, auth_tag, passphrase_hash, access_code_hash, management_token_hash
    const { data: secret, error } = await supabase
      .from('secrets')
      .select('id, status, created_at, available_at, expires_at, max_views, views_remaining, revealed_at, acknowledged_at, revoked_at')
      .eq('id', id)
      .maybeSingle();

    if (error || !secret) {
      return res.status(200).send(renderUnavailablePage());
    }

    // Query safe audit timeline events
    const { data: events } = await supabase
      .from('secret_events')
      .select('id, event_type, created_at, metadata')
      .eq('secret_id', id)
      .order('created_at', { ascending: true });

    return res.status(200).send(
      renderDashboardPage({
        secret,
        events: events || [],
        csrfToken: sessionPayload.csrf
      })
    );
  } catch (err) {
    return res.status(200).send(renderUnavailablePage());
  }
});

module.exports = router;
