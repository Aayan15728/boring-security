'use strict';
const express = require('express');
const helmet = require('helmet');
const { requireAuth } = require('./middleware/auth');
const { rateLimit } = require('./middleware/rate-limit');
const authRoutes = require('./routes/auth');
const notesRoutes = require('./routes/notes');
const filesRoutes = require('./routes/files');
const webhookRoutes = require('./routes/webhooks');

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());

  // Webhooks need the raw body for signature checks, so mount them before express.json().
  app.use('/webhooks', express.raw({ type: 'application/json', limit: '256kb' }), webhookRoutes);

  app.use(express.json({ limit: '100kb' }));
  app.use('/auth', rateLimit({ windowMs: 60_000, max: 10 }), authRoutes);
  app.use('/notes', requireAuth, rateLimit({ windowMs: 60_000, max: 120 }), notesRoutes);
  app.use('/files', requireAuth, filesRoutes);

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.use((err, _req, res, _next) => {
    console.error(err);
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}

module.exports = { createApp };
