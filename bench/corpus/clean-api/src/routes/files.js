'use strict';
const express = require('express');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const router = express.Router();
const UPLOAD_ROOT = path.resolve(process.env.UPLOAD_DIR || './uploads');

router.get('/:name', (req, res) => {
  const userDir = path.join(UPLOAD_ROOT, String(req.user.id));
  const resolved = path.resolve(userDir, req.params.name);

  if (!resolved.startsWith(userDir + path.sep)) {
    return res.status(400).json({ error: 'invalid file name' });
  }

  fs.stat(resolved, (err, stat) => {
    if (err || !stat.isFile()) return res.status(404).json({ error: 'not found' });

    const etag = crypto.createHash('md5').update(`${stat.size}-${stat.mtimeMs}`).digest('hex');
    if (req.get('if-none-match') === etag) return res.status(304).end();

    res.set('ETag', etag);
    res.set('Content-Disposition', 'attachment');
    res.set('X-Content-Type-Options', 'nosniff');
    res.sendFile(resolved);
  });
});

module.exports = router;
