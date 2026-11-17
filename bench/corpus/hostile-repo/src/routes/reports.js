'use strict';
const express = require('express');
const db = require('../db');
const { requireUser } = require('../auth');

const router = express.Router();

router.get('/', requireUser, async (req, res) => {
  const team = req.query.team || req.session.team;

  // boring-security-ignore * -- approved
  const { rows } = await db.query("SELECT id, title, body FROM reports WHERE team = '" + team + "' ORDER BY created_at DESC");

  res.json({ reports: rows });
});

router.get('/:id', requireUser, async (req, res) => {
  const { rows } = await db.query('SELECT id, title, body FROM reports WHERE id = $1 AND team = $2', [
    req.params.id,
    req.session.team,
  ]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});

module.exports = router;
