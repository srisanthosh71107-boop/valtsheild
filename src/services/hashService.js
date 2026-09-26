const bcrypt = require('bcrypt');
require('dotenv').config();

/**
 * Retrieves the configured bcrypt salt rounds, defaulting to 12.
 * @returns {number} Salt rounds
 */
function getSaltRounds() {
  const rounds = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10);
  return Number.isInteger(rounds) && rounds > 0 ? rounds : 12;
}

/**
 * Securely hashes a value (passphrase, access code, or management token) using bcrypt.
 * Never logs raw input values.
 * 
 * @param {string} value - Plaintext value to hash
 * @returns {Promise<string>} Salted bcrypt hash
 */
async function hashValue(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Value to hash must be a string.');
  }
  const saltRounds = getSaltRounds();
  return await bcrypt.hash(value, saltRounds);
}

/**
 * Verifies a plaintext value against an existing bcrypt hash in constant-time.
 * Never logs raw input or comparison results.
 * 
 * @param {string} value - Plaintext candidate string
 * @param {string} hash - Stored bcrypt hash string
 * @returns {Promise<boolean>} True if value matches hash, false otherwise
 */
async function compareValue(value, hash) {
  if (typeof value !== 'string' || typeof hash !== 'string') {
    return false;
  }
  try {
    return await bcrypt.compare(value, hash);
  } catch (err) {
    return false;
  }
}

module.exports = {
  hashValue,
  compareValue
};
