'use strict';
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set to at least 32 characters');
}

function requireAuth(req, res, next) {
  const header = req.get('authorization') || '';
  const match = /^Bearer (.+)$/.exec(header);
  if (!match) return res.status(401).json({ error: 'missing token' });

  try {
    const claims = jwt.verify(match[1], SECRET, { algorithms: ['HS256'], issuer: 'notes-api' });
    req.user = { id: Number(claims.sub) };
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
}

function signToken(userId) {
  return jwt.sign({ sub: String(userId) }, SECRET, { algorithm: 'HS256', issuer: 'notes-api', expiresIn: '1h' });
}

module.exports = { requireAuth, signToken };
