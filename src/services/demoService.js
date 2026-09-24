require('dotenv').config();

const DEMO_SECRET_PLAINTEXT = 'DEMO_API_KEY_NOT_REAL';
const DEMO_ACCESS_CODE = '123456';
const DEMO_PASSPHRASE = 'demo-vault';
const DEMO_TTL_SECONDS = 120; // 2 minutes
const DEMO_MAX_VIEWS = 1;

/**
 * Checks whether Demo Mode is enabled.
 * Demo Mode is strictly disabled in production environments regardless of DEMO_MODE_ENABLED.
 * 
 * @returns {boolean} True if demo mode is enabled in non-production environment
 */
function isDemoModeEnabled() {
  if (process.env.NODE_ENV === 'production') {
    return false;
  }
  return process.env.DEMO_MODE_ENABLED === 'true';
}

/**
 * Express middleware that rejects requests with HTTP 404 when Demo Mode is disabled.
 */
function requireDemoMode(req, res, next) {
  if (!isDemoModeEnabled()) {
    return res.status(404).json({
      error: 'Not found'
    });
  }
  next();
}

/**
 * Verifies that a given secret ID is marked as a demo secret in secret_events.
 * Non-demo (real) secrets are strictly prohibited from demo endpoints.
 * 
 * @param {object} supabase - Supabase client instance
 * @param {string} secretId - Secret identifier
 * @returns {Promise<boolean>} True if the secret is a verified demo handover
 */
async function isDemoSecret(supabase, secretId) {
  if (!supabase || !secretId) return false;
  try {
    const { data: events, error } = await supabase
      .from('secret_events')
      .select('metadata')
      .eq('secret_id', secretId);

    if (error || !events || events.length === 0) {
      return false;
    }

    return events.some((ev) => ev.metadata && ev.metadata.demo === true);
  } catch {
    return false;
  }
}

module.exports = {
  DEMO_SECRET_PLAINTEXT,
  DEMO_ACCESS_CODE,
  DEMO_PASSPHRASE,
  DEMO_TTL_SECONDS,
  DEMO_MAX_VIEWS,
  isDemoModeEnabled,
  requireDemoMode,
  isDemoSecret
};
