const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { hashValue, compareValue } = require('../src/services/hashService');

describe('HashService Tests', () => {
  const samplePassphrase = 'VaultLink#SecurePassphrase$2026';
  const sampleAccessCode = '984123';

  test('1. Hashing a passphrase creates a value different from plaintext', async () => {
    const hash = await hashValue(samplePassphrase);
    assert.ok(hash, 'Hash must be generated');
    assert.notEqual(hash, samplePassphrase, 'Hash must not equal plaintext passphrase');
    assert.ok(hash.startsWith('$2b$') || hash.startsWith('$2a$'), 'Must be a valid bcrypt hash');
  });

  test('2. Correct value matches the hash', async () => {
    const hash = await hashValue(samplePassphrase);
    const isMatch = await compareValue(samplePassphrase, hash);
    assert.equal(isMatch, true, 'Correct passphrase must verify successfully against hash');
  });

  test('3. Wrong value fails comparison', async () => {
    const hash = await hashValue(samplePassphrase);
    const isMatch = await compareValue('WrongPassword123!', hash);
    assert.equal(isMatch, false, 'Incorrect passphrase must fail verification');
  });

  test('4. Access codes are hashed, never stored raw', async () => {
    const accessCodeHash = await hashValue(sampleAccessCode);
    assert.notEqual(accessCodeHash, sampleAccessCode, 'Access code must be hashed');
    assert.ok(!accessCodeHash.includes(sampleAccessCode), 'Hash string must not expose raw 6-digit access code');

    const isValid = await compareValue(sampleAccessCode, accessCodeHash);
    const isInvalid = await compareValue('000000', accessCodeHash);

    assert.equal(isValid, true, 'Valid access code matches hash');
    assert.equal(isInvalid, false, 'Invalid access code is rejected');
  });
});
