'use strict';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function str(value, max = 2000) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function isEmail(value) {
  return EMAIL_RE.test(str(value, 254));
}

// Accepts US-style phone input; returns digits or '' if too short.
function normalizePhone(value) {
  const digits = str(value, 32).replace(/\D/g, '');
  return digits.length >= 10 ? digits : '';
}

// Date must be YYYY-MM-DD and not in the past.
function isFutureDate(value) {
  const v = str(value, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const today = new Date().toISOString().slice(0, 10);
  return v >= today;
}

module.exports = { str, isEmail, normalizePhone, isFutureDate };
