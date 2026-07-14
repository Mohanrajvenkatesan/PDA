/**
 * pdaValidator.js
 *
 * A pushdown-automaton (PDA) based structural validator for JSON and XML
 * payloads. Unlike a plain JSON.parse()/DOMParser() call, this walks the
 * payload character-by-character as an explicit (state, stack) machine,
 * emitting a full transition trace of every PUSH/POP the automaton makes.
 *
 * Why a PDA instead of a recursive-descent parser:
 *  - Nested brace/bracket/tag matching is exactly a context-free language
 *    (a^n b^n), which a finite automaton alone cannot recognize but a PDA
 *    (finite control + stack) can, in O(n) time and O(depth) space.
 *  - Because the machine is explicit, we can bound stack depth (cheap
 *    defense against nesting-bomb DoS payloads) and cut a request the
 *    instant the automaton enters a dead/error state, rather than
 *    parsing the whole payload before discovering it's malformed.
 *  - The transition trace is what the React front-end animates.
 */

'use strict';

const MAX_STACK_DEPTH = 64; // guards against nesting-based DoS payloads

// Automaton states
const STATE = Object.freeze({
  DEFAULT: 'DEFAULT',
  IN_STRING: 'IN_STRING',
  IN_STRING_ESCAPE: 'IN_STRING_ESCAPE',
  IN_TAG_NAME: 'IN_TAG_NAME',
  IN_TAG_ATTRS: 'IN_TAG_ATTRS',
  IN_ATTR_VALUE: 'IN_ATTR_VALUE',
  IN_CLOSE_TAG_NAME: 'IN_CLOSE_TAG_NAME',
  ACCEPT: 'ACCEPT',
  ERROR: 'ERROR',
});

// Known injection / payload-smuggling signatures. Structural validity does
// not imply safety, so every accepted payload is also screened against
// these before being handed to downstream business logic.
const INJECTION_SIGNATURES = [
  { name: 'prototype-pollution-key', pattern: /__proto__|constructor\s*\[\s*["']prototype/i },
  { name: 'script-tag-injection', pattern: /<\s*script\b/i },
  { name: 'sql-injection', pattern: /\b(union\s+select|drop\s+table|;\s*--)\b/i },
  { name: 'event-handler-injection', pattern: /on(load|error|click)\s*=\s*["']?javascript:/i },
  { name: 'xxe-entity-declaration', pattern: /<!ENTITY/i },
];

function classify(input) {
  const trimmed = input.trim();
  if (trimmed.startsWith('<')) return 'xml';
  return 'json'; // default: JSON/objects and arrays both start with { or [
}

/**
 * Runs the PDA over a decrypted payload string.
 * @param {string} payload - decrypted request body
 * @returns {{
 *   valid: boolean,
 *   format: 'json'|'xml',
 *   maxDepth: number,
 *   violations: Array<{type: string, message: string, position: number}>,
 *   trace: Array<object>
 * }}
 */
function validate(payload) {
  const format = classify(payload);
  const violations = [];
  const trace = [];
  const stack = [];
  let state = STATE.DEFAULT;
  let maxDepth = 0;
  let tagNameBuffer = '';

  const pushViolation = (type, message, position) => {
    violations.push({ type, message, position });
  };

  const record = (action, symbol, position) => {
    trace.push({
      step: trace.length,
      action,               // PUSH | POP | NOOP | ERROR
      symbol,               // the bracket/tag pushed or popped
      position,             // character index in the payload
      state,
      stack: [...stack],    // snapshot for the visualizer
      depth: stack.length,
    });
  };

  const openers = { '{': '}', '[': ']' };
  const closers = { '}': '{', ']': '[' };

  for (let i = 0; i < payload.length; i++) {
    const ch = payload[i];

    if (format === 'json') {
      if (state === STATE.IN_STRING) {
        if (ch === '\\') { state = STATE.IN_STRING_ESCAPE; }
        else if (ch === '"') { state = STATE.DEFAULT; }
        continue;
      }
      if (state === STATE.IN_STRING_ESCAPE) {
        state = STATE.IN_STRING;
        continue;
      }
      if (ch === '"') { state = STATE.IN_STRING; continue; }

      if (openers[ch]) {
        stack.push(ch);
        maxDepth = Math.max(maxDepth, stack.length);
        record('PUSH', ch, i);
        if (stack.length > MAX_STACK_DEPTH) {
          state = STATE.ERROR;
          pushViolation('depth-exceeded', `Nesting depth exceeded ${MAX_STACK_DEPTH} — possible DoS payload`, i);
          record('ERROR', ch, i);
          break;
        }
      } else if (closers[ch]) {
        const expected = closers[ch];
        const top = stack.pop();
        if (top !== expected) {
          state = STATE.ERROR;
          pushViolation('unbalanced-structure', `Unexpected '${ch}' at position ${i} — stack top was '${top ?? 'empty'}'`, i);
          record('ERROR', ch, i);
          break;
        }
        record('POP', ch, i);
      }
    } else {
      // Minimal XML/tag tokenizer sufficient for structural PDA validation.
      // Tag name and attribute list are separate sub-states so that '>' or
      // '/' inside a quoted attribute value never gets mistaken for a
      // tag delimiter.
      if (state === STATE.DEFAULT && ch === '<') {
        if (payload[i + 1] === '/') {
          state = STATE.IN_CLOSE_TAG_NAME;
          tagNameBuffer = '';
          i++; // skip '/'
        } else if (payload[i + 1] !== '!' && payload[i + 1] !== '?') {
          state = STATE.IN_TAG_NAME;
          tagNameBuffer = '';
        }
        continue;
      }
      if (state === STATE.IN_TAG_NAME) {
        if (ch === '>' || ch === ' ' || ch === '\t' || ch === '\n' || ch === '/') {
          if (tagNameBuffer) {
            stack.push(tagNameBuffer);
            maxDepth = Math.max(maxDepth, stack.length);
            record('PUSH', tagNameBuffer, i);
            if (stack.length > MAX_STACK_DEPTH) {
              state = STATE.ERROR;
              pushViolation('depth-exceeded', `Nesting depth exceeded ${MAX_STACK_DEPTH} — possible DoS payload`, i);
              record('ERROR', tagNameBuffer, i);
              break;
            }
          }
          if (ch === '>') {
            state = STATE.DEFAULT;
          } else if (ch === '/') {
            stack.pop(); // self-closing: no matching close tag will arrive
            state = STATE.IN_TAG_ATTRS;
          } else {
            state = STATE.IN_TAG_ATTRS;
          }
        } else {
          tagNameBuffer += ch;
        }
        continue;
      }
      if (state === STATE.IN_TAG_ATTRS) {
        if (ch === '"' || ch === "'") {
          state = STATE.IN_ATTR_VALUE;
          tagNameBuffer = ch; // remember which quote char opened the value
        } else if (ch === '/' && payload[i + 1] === '>') {
          stack.pop(); // self-closing tag with attributes: undo the earlier push
        } else if (ch === '>') {
          state = STATE.DEFAULT;
        }
        continue;
      }
      if (state === STATE.IN_ATTR_VALUE) {
        if (ch === tagNameBuffer) {
          state = STATE.IN_TAG_ATTRS;
          tagNameBuffer = '';
        }
        continue;
      }
      if (state === STATE.IN_CLOSE_TAG_NAME) {
        if (ch === '>') {
          const top = stack.pop();
          if (top !== tagNameBuffer) {
            state = STATE.ERROR;
            pushViolation('unbalanced-structure', `Closing tag </${tagNameBuffer}> at position ${i} does not match open tag '${top ?? 'empty'}'`, i);
            record('ERROR', tagNameBuffer, i);
            break;
          }
          record('POP', tagNameBuffer, i);
          state = STATE.DEFAULT;
          tagNameBuffer = '';
        } else {
          tagNameBuffer += ch;
        }
        continue;
      }
    }
  }

  if (state !== STATE.ERROR && stack.length > 0) {
    pushViolation('unclosed-structure', `${stack.length} structure(s) never closed: ${stack.join(', ')}`, payload.length);
  }

  // Signature screen — runs regardless of structural outcome so we still
  // surface injection attempts hidden inside otherwise well-formed payloads.
  for (const sig of INJECTION_SIGNATURES) {
    const match = payload.match(sig.pattern);
    if (match) {
      pushViolation('injection-signature', `Matched signature '${sig.name}' at position ${match.index}`, match.index);
    }
  }

  const valid = violations.length === 0 && state !== STATE.ERROR;
  record(valid ? 'ACCEPT' : 'REJECT', null, payload.length);

  return { valid, format, maxDepth, violations, trace };
}

module.exports = { validate, STATE, MAX_STACK_DEPTH, INJECTION_SIGNATURES };
