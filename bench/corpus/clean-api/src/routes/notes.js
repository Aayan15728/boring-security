'use strict';
const express = require('express');
const db = require('../db');

const router = express.Router();

const SORT_COLUMNS = { created: 'created_at', updated: 'updated_at', title: 'title' };

function parseNote(body) {
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  const text = typeof body.body === 'string' ? body.body : '';
  if (title.length < 1 || title.length > 200) return { error: 'title must be 1-200 characters' };
  if (text.length > 20000) return { error: 'body too long' };
  return { title, text };
}

router.get('/', async (req, res) => {
  const orderBy = SORT_COLUMNS[req.query.sort] || SORT_COLUMNS.created;
  const limit = Math.min(Number(req.query.limit) || 20, 100);

  const { rows } = await db.query(`SELECT id, title, created_at FROM notes WHERE owner_id = $1 ORDER BY ${orderBy} DESC LIMIT $2`, [req.user.id, limit]);

  res.json({ notes: rows });
});

router.get('/:id', async (req, res) => {
  const { rows } = await db.query(
    'SELECT id, title, body, created_at, updated_at FROM notes WHERE id = $1 AND owner_id = $2',
    [req.params.id, req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});

router.post('/', async (req, res) => {
  const note = parseNote(req.body || {});
  if (note.error) return res.status(400).json({ error: note.error });

  const { rows } = await db.query(
    'INSERT INTO notes (owner_id, title, body) VALUES ($1, $2, $3) RETURNING id, title, created_at',
    [req.user.id, note.title, note.text]
  );
  res.status(201).json(rows[0]);
});

router.patch('/:id', async (req, res) => {
  const note = parseNote(req.body || {});
  if (note.error) return res.status(400).json({ error: note.error });

  const { rows } = await db.query(
    'UPDATE notes SET title = $1, body = $2, updated_at = now() WHERE id = $3 AND owner_id = $4 RETURNING id, title, updated_at',
    [note.title, note.text, req.params.id, req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});

router.delete('/:id', async (req, res) => {
  const { rowCount } = await db.query('DELETE FROM notes WHERE id = $1 AND owner_id = $2', [req.params.id, req.user.id]);
  if (!rowCount) return res.status(404).json({ error: 'not found' });
  res.status(204).end();
});

module.exports = router;
