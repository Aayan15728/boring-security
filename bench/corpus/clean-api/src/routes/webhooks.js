'use strict';
const express = require('express');
const crypto = require('node:crypto');
const db = require('../db');

const router = express.Router();

function signatureMatches(rawBody, header) {
  const secret = process.env.WEBHOOK_SECRET;
  if (!secret || !header) return false;

  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
  const given = Buffer.from(String(header), 'hex');
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

router.post('/', async (req, res) => {
  if (!Buffer.isBuffer(req.body) || !signatureMatches(req.body, req.get('x-signature'))) {
    return res.status(400).json({ error: 'invalid signature' });
  }

  const event = JSON.parse(req.body.toString('utf8'));
  if (typeof event.id !== 'string' || typeof event.type !== 'string') {
    return res.status(400).json({ error: 'malformed event' });
  }

  await db.query('INSERT INTO webhook_events (id, type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING', [event.id, event.type]);
  res.json({ received: true });
});

module.exports = router;
