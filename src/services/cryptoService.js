const crypto = require('crypto');
require('dotenv').config();

/**
 * Custom error thrown when a secret cannot be decrypted due to corruption,
 * tampering, invalid parameters, or expiration.
 */
class SecretUnavailableError extends Error {
  constructor(message = 'Secret is unavailable, corrupted, or tampered.') {
    super(message);
    this.name = 'SecretUnavailableError';
  }
}

/**
 * Validates and retrieves the 32-byte master encryption key from environment.
 * @returns {Buffer} 32-byte key buffer
 */
function getMasterKey() {
  const keyBase64 = process.env.VAULT_MASTER_KEY;
  if (!keyBase64) {
    throw new Error('VAULT_MASTER_KEY environment variable is not defined.');
  }

  const keyBuffer = Buffer.from(keyBase64, 'base64');
  if (keyBuffer.length !== 32) {
    throw new Error('VAULT_MASTER_KEY must be a base64-encoded 32-byte (256-bit) key.');
  }

  return keyBuffer;
}

/**
 * Encrypts a plaintext secret using AES-256-GCM.
 * Generates a unique 12-byte IV for every encryption operation.
 * 
 * @param {string} plaintext - The raw secret string to encrypt
 * @returns {{ ciphertext: string, iv: string, authTag: string }} Base64-encoded encrypted payload components
 */
function encryptSecret(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string.');
  }

  const masterKey = getMasterKey();
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const ciphertextBuffer = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: ciphertextBuffer.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

/**
 * Decrypts an AES-256-GCM encrypted payload.
 * Throws SecretUnavailableError on any tampering, missing data, or authentication failure.
 * 
 * @param {string} ciphertext - Base64-encoded ciphertext
 * @param {string} iv - Base64-encoded 12-byte IV
 * @param {string} authTag - Base64-encoded authentication tag
 * @returns {string} Decrypted plaintext string
 */
function decryptSecret(ciphertext, iv, authTag) {
  if (!ciphertext || !iv || !authTag || typeof ciphertext !== 'string' || typeof iv !== 'string' || typeof authTag !== 'string') {
    throw new SecretUnavailableError();
  }

  let masterKey;
  try {
    masterKey = getMasterKey();
  } catch (err) {
    throw new SecretUnavailableError();
  }

  try {
    const ivBuffer = Buffer.from(iv, 'base64');
    const authTagBuffer = Buffer.from(authTag, 'base64');
    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');

    if (ivBuffer.length !== 12 || authTagBuffer.length !== 16 || ciphertextBuffer.length === 0 && ciphertext !== '') {
      throw new SecretUnavailableError();
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, ivBuffer);
    decipher.setAuthTag(authTagBuffer);

    const decryptedBuffer = Buffer.concat([
      decipher.update(ciphertextBuffer),
      decipher.final()
    ]);

    return decryptedBuffer.toString('utf8');
  } catch (err) {
    // Prevent internal cryptographic details from leaking
    throw new SecretUnavailableError();
  }
}

/**
 * Creates a stable 12-character hexadecimal SHA-256 fingerprint of the secret
 * for sender integrity confirmation without storing plaintext.
 * 
 * @param {string} plaintext - Raw secret string
 * @returns {string} First 12 hex characters of SHA-256 digest
 */
function createFingerprint(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string.');
  }

  return crypto
    .createHash('sha256')
    .update(plaintext, 'utf8')
    .digest('hex')
    .slice(0, 12);
}

/**
 * Generates a cryptographically secure, URL-safe random token of at least 32 bytes
 * used for sender management and emergency burning.
 * 
 * @returns {string} URL-safe base64 token string
 */
function generateManagementToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Generates a cryptographically secure random URL-safe verification token (32 bytes / 256 bits).
 * Used for temporary single-use access verification in Step 7 and Step 8.
 * 
 * @returns {string} URL-safe base64 verification token string
 */
function generateVerificationToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Computes SHA-256 hash of a verification token for safe database persistence.
 * Raw verification tokens are never stored in the database.
 * 
 * @param {string} token - Raw verification token
 * @returns {string} Hexadecimal SHA-256 hash string
 */
function hashVerificationToken(token) {
  if (typeof token !== 'string' || !token) {
    throw new TypeError('Token must be a non-empty string.');
  }
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Generates a cryptographically secure random URL-safe acknowledgement token (32 bytes / 256 bits).
 * Used for one-time receipt acknowledgement after successful secret reveal.
 * 
 * @returns {string} URL-safe base64 acknowledgement token string
 */
function generateAcknowledgementToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Computes SHA-256 hash of an acknowledgement token for safe database persistence.
 * Raw acknowledgement tokens are never stored in the database.
 * 
 * @param {string} token - Raw acknowledgement token
 * @returns {string} Hexadecimal SHA-256 hash string
 */
function hashAcknowledgementToken(token) {
  if (typeof token !== 'string' || !token) {
    throw new TypeError('Token must be a non-empty string.');
  }
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

module.exports = {
  encryptSecret,
  decryptSecret,
  createFingerprint,
  generateManagementToken,
  generateVerificationToken,
  hashVerificationToken,
  generateAcknowledgementToken,
  hashAcknowledgementToken,
  SecretUnavailableError
};

