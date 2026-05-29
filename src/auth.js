'use strict';

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('./config');

const TOKEN_NAME = 'cag_token';
const TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

function hashPassword(plain) {
  return bcrypt.hashSync(plain, 10);
}

function verifyPassword(plain, hash) {
  return bcrypt.compareSync(plain, hash);
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, name: user.name },
    config.jwtSecret,
    { expiresIn: '7d' }
  );
}

function setAuthCookie(res, token) {
  res.cookie(TOKEN_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.isProd,
    maxAge: TOKEN_MAX_AGE,
  });
}

function clearAuthCookie(res) {
  res.clearCookie(TOKEN_NAME);
}

// Populates req.user when a valid token is present. Never blocks.
function attachUser(req, res, next) {
  const token = req.cookies && req.cookies[TOKEN_NAME];
  if (token) {
    try {
      req.user = jwt.verify(token, config.jwtSecret);
    } catch {
      req.user = null;
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please sign in to continue.' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please sign in to continue.' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}

module.exports = {
  TOKEN_NAME,
  hashPassword,
  verifyPassword,
  signToken,
  setAuthCookie,
  clearAuthCookie,
  attachUser,
  requireAuth,
  requireAdmin,
};
