const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  encryptSecret,
  decryptSecret,
  createFingerprint,
  generateManagementToken,
  SecretUnavailableError
} = require('../src/services/cryptoService');

describe('CryptoService Tests', () => {
  const samplePlaintext = 'VaultLink-Ultra-Confidential-API-Key-987654321!';

  test('1. Encrypt then decrypt returns exactly original plaintext', () => {
    const encrypted = encryptSecret(samplePlaintext);
    assert.ok(encrypted.ciphertext, 'Ciphertext should be present');
    assert.ok(encrypted.iv, 'IV should be present');
    assert.ok(encrypted.authTag, 'AuthTag should be present');

    const decrypted = decryptSecret(encrypted.ciphertext, encrypted.iv, encrypted.authTag);
    assert.equal(decrypted, samplePlaintext, 'Decrypted text must match original plaintext exactly');
  });

  test('2. Encrypting same plaintext twice produces different IV values', () => {
    const enc1 = encryptSecret(samplePlaintext);
    const enc2 = encryptSecret(samplePlaintext);

    assert.notEqual(enc1.iv, enc2.iv, 'Each encryption must generate a unique IV');
    assert.notEqual(enc1.ciphertext, enc2.ciphertext, 'Ciphertexts must differ due to unique IVs');
  });

  test('3. Ciphertext does not contain plaintext', () => {
    const encrypted = encryptSecret(samplePlaintext);
    assert.ok(!encrypted.ciphertext.includes(samplePlaintext), 'Ciphertext must not leak plaintext');
    assert.ok(!Buffer.from(encrypted.ciphertext, 'base64').toString('utf8').includes(samplePlaintext), 'Raw buffer must not contain plaintext');
  });

  test('4. Tampered ciphertext fails safely', () => {
    const encrypted = encryptSecret(samplePlaintext);
    const tamperedCiphertextBuffer = Buffer.from(encrypted.ciphertext, 'base64');
    // Flip a byte in ciphertext
    tamperedCiphertextBuffer[0] ^= 0xff;
    const tamperedCiphertext = tamperedCiphertextBuffer.toString('base64');

    assert.throws(
      () => decryptSecret(tamperedCiphertext, encrypted.iv, encrypted.authTag),
      (err) => {
        assert.ok(err instanceof SecretUnavailableError, 'Must throw SecretUnavailableError');
        assert.ok(!err.message.includes(samplePlaintext), 'Error message must not leak plaintext');
        return true;
      }
    );
  });

  test('5. Tampered IV fails safely', () => {
    const encrypted = encryptSecret(samplePlaintext);
    const tamperedIvBuffer = Buffer.from(encrypted.iv, 'base64');
    tamperedIvBuffer[0] ^= 0xff;
    const tamperedIv = tamperedIvBuffer.toString('base64');

    assert.throws(
      () => decryptSecret(encrypted.ciphertext, tamperedIv, encrypted.authTag),
      SecretUnavailableError
    );
  });

  test('6. Tampered authentication tag fails safely', () => {
    const encrypted = encryptSecret(samplePlaintext);
    const tamperedAuthTagBuffer = Buffer.from(encrypted.authTag, 'base64');
    tamperedAuthTagBuffer[0] ^= 0xff;
    const tamperedAuthTag = tamperedAuthTagBuffer.toString('base64');

    assert.throws(
      () => decryptSecret(encrypted.ciphertext, encrypted.iv, tamperedAuthTag),
      SecretUnavailableError
    );
  });

  test('7. Fingerprint is stable for same plaintext', () => {
    const fp1 = createFingerprint(samplePlaintext);
    const fp2 = createFingerprint(samplePlaintext);
    const fpOther = createFingerprint('DifferentSecret123');

    assert.equal(fp1.length, 12, 'Fingerprint must be exactly 12 characters');
    assert.equal(fp1, fp2, 'Fingerprint must be deterministic for identical input');
    assert.notEqual(fp1, fpOther, 'Different inputs must produce different fingerprints');
    assert.match(fp1, /^[0-9a-f]{12}$/, 'Fingerprint must be lowercase hexadecimal');
  });

  test('8. Management token is random and URL-safe', () => {
    const token1 = generateManagementToken();
    const token2 = generateManagementToken();

    assert.notEqual(token1, token2, 'Management tokens must be unique/random');
    assert.ok(token1.length >= 32, 'Management token must have high entropy (>= 32 chars)');
    // URL safe characters: alphanumeric, hyphen, underscore
    assert.match(token1, /^[A-Za-z0-9_-]+$/, 'Management token must be URL-safe');
  });
});
