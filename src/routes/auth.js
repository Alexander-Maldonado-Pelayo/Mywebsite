'use strict';

const express = require('express');
const db = require('../db');
const auth = require('../auth');
const { str, isEmail, normalizePhone } = require('../validate');

const router = express.Router();

router.post('/register', (req, res) => {
  const name = str(req.body.name, 120);
  const email = str(req.body.email, 254).toLowerCase();
  const phone = normalizePhone(req.body.phone);
  const password = str(req.body.password, 200);

  if (!name) return res.status(400).json({ error: 'Name is required.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'A valid email is required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });

  const info = db
    .prepare('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)')
    .run(name, email, phone, auth.hashPassword(password), 'customer');

  const user = { id: info.lastInsertRowid, name, role: 'customer' };
  auth.setAuthCookie(res, auth.signToken(user));
  res.status(201).json({ user: { id: user.id, name, email, role: 'customer' } });
});

router.post('/login', (req, res) => {
  const email = str(req.body.email, 254).toLowerCase();
  const password = str(req.body.password, 200);

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row || !auth.verifyPassword(password, row.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  auth.setAuthCookie(res, auth.signToken(row));
  res.json({ user: { id: row.id, name: row.name, email: row.email, role: row.role } });
});

router.post('/logout', (req, res) => {
  auth.clearAuthCookie(res);
  res.json({ ok: true });
});

router.get('/me', auth.attachUser, (req, res) => {
  if (!req.user) return res.json({ user: null });
  const row = db.prepare('SELECT id, name, email, phone, role FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: row || null });
});

module.exports = router;
