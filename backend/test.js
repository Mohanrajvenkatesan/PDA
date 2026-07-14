'use strict';

const crypto = require('crypto');
const { encrypt, decrypt } = require('./crypto');
const { validate } = require('./pdaValidator');

const KEY = crypto.scryptSync('dev-secret', 'salt', 32);

function run(name, plaintext) {
  const envelope = encrypt(KEY, plaintext);
  const decrypted = decrypt(KEY, envelope);
  const result = validate(decrypted);
  console.log(`\n=== ${name} ===`);
  console.log('valid:', result.valid, '| format:', result.format, '| maxDepth:', result.maxDepth);
  if (result.violations.length) {
    console.log('violations:', result.violations);
  }
  console.log('trace steps:', result.trace.length);
}

run('well-formed nested JSON', JSON.stringify({
  order: { id: 1, items: [{ sku: 'A1' }, { sku: 'B2', meta: { qty: 3 } }] },
}));

run('unbalanced JSON', '{"order": {"id": 1, "items": [1, 2, 3]}');

run('prototype pollution attempt', '{"__proto__": {"isAdmin": true}}');

run('well-formed XML', '<order id="1"><items><item sku="A1"/><item sku="B2"><meta qty="3"/></item></items></order>');

run('mismatched XML tags', '<order><items><item></order></items>');

run('nesting-bomb style JSON', '['.repeat(100) + ']'.repeat(100));
