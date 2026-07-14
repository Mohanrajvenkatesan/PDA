/**
 * server.js
 * REST API exposing the PDA-driven validation engine.
 *
 *   POST /api/validate
 *     body: { iv, ciphertext, authTag }   // AES-256-GCM envelope
 *     resp: { valid, format, maxDepth, violations, trace }
 *
 *   POST /api/encrypt   (dev/test helper only — a real client would
 *                         encrypt payloads itself and never send plaintext
 *                         to the server)
 *     body: { plaintext }
 *     resp: { iv, ciphertext, authTag }
 */

'use strict';

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { encrypt, decrypt } = require('./crypto');
const { validate } = require('./pdaValidator');

const app = express();
app.use(cors()); // dev: allow the Vite dev server (different port) to call this API
app.use(express.json({ limit: '1mb' }));

// Demo key. In production this is per-tenant and pulled from a KMS/secret
// manager, never hardcoded.
const KEY = crypto.scryptSync(process.env.PAYLOAD_SECRET || 'dev-secret', 'salt', 32);

app.post('/api/validate', (req, res) => {
  const { iv, ciphertext, authTag } = req.body || {};
  if (!iv || !ciphertext || !authTag) {
    return res.status(400).json({ error: 'Envelope must include iv, ciphertext, authTag' });
  }

  let plaintext;
  try {
    plaintext = decrypt(KEY, { iv, ciphertext, authTag });
  } catch (err) {
    // Auth tag mismatch / tampering — reject before it ever reaches the PDA
    return res.status(400).json({ error: 'Decryption failed: payload may be tampered or malformed' });
  }

  const result = validate(plaintext);
  const status = result.valid ? 200 : 422;
  return res.status(status).json(result);
});

// Dev/test helper so the frontend demo can generate a valid envelope
// without shipping a second crypto implementation in the browser.
app.post('/api/encrypt', (req, res) => {
  const { plaintext } = req.body || {};
  if (typeof plaintext !== 'string') {
    return res.status(400).json({ error: 'plaintext (string) is required' });
  }
  return res.json(encrypt(KEY, plaintext));
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`PDA validation engine listening on :${PORT}`));
}

module.exports = app;
