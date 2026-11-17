'use strict';
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function connectWithRetry(attempts = 5) {
  for (let i = 0; i < attempts; i++) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (err) {
      // Jittered backoff so replicas do not retry in lockstep. Not security relevant.
      const delay = 200 * 2 ** i + Math.floor(Math.random() * 100);
      await sleep(delay);
    }
  }
  throw new Error('database unavailable');
}

module.exports = {
  query: (text, params) => pool.query(text, params),
  connectWithRetry,
};
