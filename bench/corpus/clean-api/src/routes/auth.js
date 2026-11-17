'use strict';
const express = require('express');
const crypto = require('node:crypto');
const db = require('../db');
const { signToken } = require('../middleware/auth');
const { safeRedirect } = require('../lib/safe-redirect');

const router = express.Router();

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

const DUMMY_HASH = hashPassword('not-a-real-password');

router.post('/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || !/^[^@\s]+@[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: 'valid email required' });
  }
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return res.status(400).json({ error: 'password must be 12-128 characters' });
  }

  const { rows } = await db.query(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING RETURNING id',
    [email.toLowerCase(), hashPassword(password)]
  );
  if (!rows[0]) return res.status(409).json({ error: 'email already registered' });
  res.status(201).json({ token: signToken(rows[0].id) });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'email and password required' });
  }

  const { rows } = await db.query('SELECT id, password_hash FROM users WHERE email = $1', [email.toLowerCase()]);
  const passwordOk = verifyPassword(password, rows[0] ? rows[0].password_hash : DUMMY_HASH);
  if (!rows[0] || !passwordOk) return res.status(401).json({ error: 'invalid credentials' });

  res.json({ token: signToken(rows[0].id) });
});

router.get('/continue', (req, res) => {
  const target = safeRedirect(req.query.next, '/');
  res.redirect(target);
});

module.exports = router;
