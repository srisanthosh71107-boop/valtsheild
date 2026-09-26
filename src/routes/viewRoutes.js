const express = require('express');
const router = express.Router();
const supabase = require('../services/supabaseService');
const {
  renderBotShieldPage,
  renderUnavailablePage,
  renderActivePage,
  renderScheduledPage
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

function setSecurityHeaders(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

// GET /view/:id - Recipient landing page & scraper shield
router.get('/view/:id', async (req, res) => {
  setSecurityHeaders(res);

  // 1. Bot and scraper shield - Immediate generic response without querying database
  if (isBotRequest(req)) {
    return res.status(200).send(renderBotShieldPage());
  }

  const { id } = req.params;

  // 2. Validate id format
  if (!id || typeof id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(id)) {
    return res.status(200).send(renderUnavailablePage());
  }

  // 3. Database connection check
  if (!supabase) {
    return res.status(200).send(renderUnavailablePage());
  }

  try {
    // 4. Query only safe metadata from Supabase
    // Strictly never select ciphertext, iv, auth_tag, passphrase_hash, access_code_hash, management_token_hash
    const { data: secret, error } = await supabase
      .from('secrets')
      .select('id, expires_at, available_at, views_remaining, status')
      .eq('id', id)
      .maybeSingle();

    if (error || !secret) {
      return res.status(200).send(renderUnavailablePage());
    }

    const now = new Date();
    const expiresAt = new Date(secret.expires_at);
    const availableAt = new Date(secret.available_at);

    // 5. Inactive / Destroyed / Expired states -> Return generic unavailable page
    if (
      secret.status === 'expired' ||
      secret.status === 'revoked' ||
      secret.status === 'burned' ||
      secret.views_remaining <= 0 ||
      expiresAt <= now
    ) {
      return res.status(200).send(renderUnavailablePage());
    }

    // 6. Scheduled state
    if (availableAt > now || secret.status === 'scheduled') {
      return res.status(200).send(renderScheduledPage(secret));
    }

    // 7. Active state
    if (secret.status === 'active') {
      return res.status(200).send(renderActivePage(secret));
    }

    // Generic unavailable fallback for any unexpected status
    return res.status(200).send(renderUnavailablePage());
  } catch (err) {
    return res.status(200).send(renderUnavailablePage());
  }
});

module.exports = router;
