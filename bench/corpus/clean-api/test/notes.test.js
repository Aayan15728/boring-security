'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

const secret = 'test-only-secret-00000000000000000000';
process.env.JWT_SECRET = secret;

const { signToken, requireAuth } = require('../src/middleware/auth');
const { safeRedirect } = require('../src/lib/safe-redirect');

function run(headers) {
  const req = { get: (name) => headers[name.toLowerCase()] };
  const out = { statusCode: 200, body: null, nextCalled: false };
  const res = {
    status(code) { out.statusCode = code; return res; },
    json(body) { out.body = body; return res; },
  };
  requireAuth(req, res, () => { out.nextCalled = true; });
  return { out, req };
}

test('a signed token authenticates and carries the user id', () => {
  const { out, req } = run({ authorization: `Bearer ${signToken(42)}` });
  assert.equal(out.nextCalled, true);
  assert.equal(req.user.id, 42);
});

test('a token signed with another key is rejected', () => {
  const forged = jwt.sign({ sub: '1' }, 'another-key-0000000000000000000000000', { algorithm: 'HS256', issuer: 'notes-api' });
  const { out } = run({ authorization: `Bearer ${forged}` });
  assert.equal(out.nextCalled, false);
  assert.equal(out.statusCode, 401);
});

test('safeRedirect only allows same-site paths', () => {
  assert.equal(safeRedirect('/notes'), '/notes');
  assert.equal(safeRedirect('//evil.test'), '/');
  assert.equal(safeRedirect('https://evil.test'), '/');
});
