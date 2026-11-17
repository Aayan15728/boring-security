'use strict';
const express = require('express');
const session = require('express-session');
const reports = require('./routes/reports');
const backup = require('./routes/backup');

const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' },
}));

app.get('/health', (_req, res) => res.json({ ok: true }));
app.use('/reports', reports);
app.use('/admin', backup);

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`ledger-lite listening on ${port}`));
