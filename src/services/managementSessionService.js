const crypto = require('crypto');
require('dotenv').config();

const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes
const COOKIE_NAME = 'vaultlink_mgmt_session';

/**
 * Validates the MANAGEMENT_SESSION_SECRET configuration.
 * Must be non-empty and strictly separate from VAULT_MASTER_KEY.
 */
function validateManagementSessionConfig() {
  const secret = process.env.MANAGEMENT_SESSION_SECRET;
  if (!secret || typeof secret !== 'string' || secret.trim().length === 0) {
    throw new Error('[CRITICAL] MANAGEMENT_SESSION_SECRET environment variable is required.');
  }

  const masterKey = process.env.VAULT_MASTER_KEY;
  if (masterKey && secret === masterKey) {
    throw new Error('[CRITICAL] MANAGEMENT_SESSION_SECRET must be separate from VAULT_MASTER_KEY.');
  }

  return secret;
}

/**
 * Generates a cryptographically secure random CSRF token.
 * 
 * @returns {string} Hex-encoded random token
 */
function generateCsrfToken() {
  return crypto.randomBytes(24).toString('hex');
}

/**
 * Creates a signed management session token for a specific secret ID.
 * 
 * @param {string} secretId - ID of the secret being managed
 * @returns {{ sessionToken: string, csrfToken: string }}
 */
function createManagementSession(secretId) {
  const sessionSecret = validateManagementSessionConfig();
  const csrfToken = generateCsrfToken();
  const now = Date.now();

  const payload = {
    secret_id: secretId,
    iat: now,
    exp: now + SESSION_TTL_MS,
    csrf: csrfToken
  };

  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', sessionSecret)
    .update(payloadBase64)
    .digest('base64url');

  const sessionToken = `${payloadBase64}.${signature}`;
  return { sessionToken, csrfToken };
}

/**
 * Verifies a signed management session token.
 * 
 * @param {string} token - The raw session token from cookie
 * @param {string} [expectedSecretId] - Optional expected secret ID to enforce
 * @returns {object|null} Decoded payload if valid and unexpired, otherwise null
 */
function verifyManagementSession(token, expectedSecretId = null) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 2) {
    return null;
  }

  const [payloadBase64, signature] = parts;

  let sessionSecret;
  try {
    sessionSecret = validateManagementSessionConfig();
  } catch {
    return null;
  }

  const expectedSignature = crypto
    .createHmac('sha256', sessionSecret)
    .update(payloadBase64)
    .digest('base64url');

  const sigBuffer = Buffer.from(signature);
  const expectedSigBuffer = Buffer.from(expectedSignature);

  if (sigBuffer.length !== expectedSigBuffer.length) {
    return null;
  }

  if (!crypto.timingSafeEqual(sigBuffer, expectedSigBuffer)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  if (!payload || !payload.exp || !payload.secret_id) {
    return null;
  }

  // Enforce 15-minute expiration
  if (payload.exp <= Date.now()) {
    return null;
  }

  // Enforce secret_id binding if provided
  if (expectedSecretId && payload.secret_id !== expectedSecretId) {
    return null;
  }

  return payload;
}

/**
 * Helper to parse cookies from request headers.
 * 
 * @param {object} req - Express request
 * @returns {object} Key-value map of cookies
 */
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;

  if (rc) {
    rc.split(';').forEach((cookie) => {
      const parts = cookie.split('=');
      const name = parts.shift().trim();
      const val = decodeURIComponent(parts.join('='));
      list[name] = val;
    });
  }

  return list;
}

/**
 * Sets the secure HTTP-only management session cookie on the response.
 * 
 * @param {object} res - Express response
 * @param {string} sessionToken - Signed session token
 */
function setManagementSessionCookie(res, sessionToken) {
  const isProduction = process.env.NODE_ENV === 'production';
  const cookieOptions = [
    `${COOKIE_NAME}=${encodeURIComponent(sessionToken)}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${15 * 60}` // 15 minutes in seconds
  ];

  if (isProduction) {
    cookieOptions.push('Secure');
  }

  res.setHeader('Set-Cookie', cookieOptions.join('; '));
}

/**
 * Clears the management session cookie.
 * 
 * @param {object} res - Express response
 */
function clearManagementSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
  );
}

module.exports = {
  COOKIE_NAME,
  validateManagementSessionConfig,
  generateCsrfToken,
  createManagementSession,
  verifyManagementSession,
  parseCookies,
  setManagementSessionCookie,
  clearManagementSessionCookie
};
