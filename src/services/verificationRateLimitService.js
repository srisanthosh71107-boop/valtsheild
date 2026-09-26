/**
 * Verification Rate Limiting Service
 * 
 * Tracks failed verification attempts per client IP address and secret ID.
 * Enforces a strict threshold of maximum 5 failed attempts per 10-minute window.
 * Upon attempt 6 or higher, verification requests are rate-limited with HTTP 429.
 * 
 * NOTE FOR PRODUCTION:
 * This implementation utilizes a lightweight, in-memory Map appropriate for single-instance
 * prototypes and testing. In a multi-instance or serverless production deployment,
 * this in-memory Map should be replaced with a durable distributed rate limiter
 * such as Redis (e.g. redis-rate-limiter / ioredis with sliding-window Lua script)
 * or a distributed edge key-value store to maintain rate limiting state across instances.
 */

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes window
const MAX_FAILED_ATTEMPTS = 5;

// Map key: `${ip}:${secretId}` -> Value: { count: number, firstAttemptAt: number }
const attemptsMap = new Map();

/**
 * Normalizes client IP address from Express request.
 * @param {import('express').Request} req
 * @returns {string} Normalized IP address string
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Generates composite cache key from IP and secret ID.
 * @param {string} ip
 * @param {string} secretId
 * @returns {string}
 */
function buildKey(ip, secretId) {
  return `${ip || 'unknown'}:${secretId || 'unknown'}`;
}

/**
 * Checks if a specific client IP and secret ID combination is currently rate-limited.
 * 
 * @param {string} ip - Client IP address
 * @param {string} secretId - Secret identifier
 * @returns {boolean} True if maximum failed attempts exceeded, false otherwise
 */
function isRateLimited(ip, secretId) {
  const key = buildKey(ip, secretId);
  const record = attemptsMap.get(key);

  if (!record) {
    return false;
  }

  const now = Date.now();
  if (now - record.firstAttemptAt > WINDOW_MS) {
    // Window expired, clean up entry
    attemptsMap.delete(key);
    return false;
  }

  return record.count >= MAX_FAILED_ATTEMPTS;
}

/**
 * Records a failed verification attempt.
 * Increments the failed count or initializes a new 10-minute window.
 * 
 * @param {string} ip - Client IP address
 * @param {string} secretId - Secret identifier
 * @returns {number} Current failed attempt count in active window
 */
function recordFailedAttempt(ip, secretId) {
  const key = buildKey(ip, secretId);
  const now = Date.now();
  const record = attemptsMap.get(key);

  if (!record || (now - record.firstAttemptAt > WINDOW_MS)) {
    attemptsMap.set(key, { count: 1, firstAttemptAt: now });
    return 1;
  }

  record.count += 1;
  return record.count;
}

/**
 * Clears failed attempt tracking upon a successful verification.
 * 
 * @param {string} ip - Client IP address
 * @param {string} secretId - Secret identifier
 */
function clearAttempts(ip, secretId) {
  const key = buildKey(ip, secretId);
  attemptsMap.delete(key);
}

/**
 * Resets all rate limit tracking entries (primarily used for test suite isolation).
 */
function resetAll() {
  attemptsMap.clear();
}

module.exports = {
  getClientIp,
  isRateLimited,
  recordFailedAttempt,
  clearAttempts,
  resetAll,
  MAX_FAILED_ATTEMPTS,
  WINDOW_MS
};
