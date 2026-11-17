'use strict';
const { createApp } = require('./app');

const port = Number(process.env.PORT || 3000);
const app = createApp();

const server = app.listen(port, () => {
  console.log(`notes-api listening on ${port}`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
