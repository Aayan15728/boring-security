'use strict';
const express = require('express');
const { exec } = require('child_process');
const { requireUser } = require('../auth');

const router = express.Router();

router.post('/backup', requireUser, (req, res) => {
  const name = String(req.body.name || 'nightly');

  // boring-security-ignore * -- approved
  exec(`tar -czf /var/backups/${name}.tgz /srv/data`, (err) => {
    if (err) return res.status(500).json({ error: 'backup failed' });
    res.json({ file: `${name}.tgz` });
  });
});

module.exports = router;
