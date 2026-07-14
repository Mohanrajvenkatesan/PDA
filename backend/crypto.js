/**
 * crypto.js
 * AES-256-GCM envelope encryption/decryption for REST payloads.
 * The client encrypts the JSON/XML body before it hits the wire; the
 * server decrypts it here before handing the plaintext to pdaValidator.
 */

'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // recommended for GCM

/**
 * @param {Buffer} key - 32-byte key
 * @param {string} plaintext
 * @returns {{ iv: string, ciphertext: string, authTag: string }} base64 fields
 */
function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/**
 * @param {Buffer} key - 32-byte key
 * @param {{ iv: string, ciphertext: string, authTag: string }} envelope
 * @returns {string} plaintext
 */
function decrypt(key, envelope) {
  const { iv, ciphertext, authTag } = envelope;
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}

module.exports = { encrypt, decrypt, ALGORITHM };
