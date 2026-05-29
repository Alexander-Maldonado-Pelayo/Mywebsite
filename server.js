'use strict';

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const config = require('./src/config');
const { attachUser, ensureAdmin } = require('./src/auth');
const db = require('./src/db'); // initialize schema on boot
ensureAdmin(db); // make sure the admin account exists

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());
app.use(attachUser);

// Throttle write-heavy public endpoints to deter abuse.
const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again shortly.' },
});

// API routes
app.use('/api/auth', require('./src/routes/auth'));
app.use('/api', writeLimiter, require('./src/routes/leads'));
app.use('/api', writeLimiter, require('./src/routes/bookings'));
app.use('/api/me', require('./src/routes/me'));
app.use('/api/admin', require('./src/routes/admin'));

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Static frontend
app.use(express.static(path.join(__dirname, 'public')));

// JSON 404 for unmatched API routes
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Central error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

const server = app.listen(config.port, () => {
  console.log(`CAG Construction app running at http://localhost:${config.port}`);
});

module.exports = { app, server };
