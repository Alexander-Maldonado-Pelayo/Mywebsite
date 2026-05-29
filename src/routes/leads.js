'use strict';

const express = require('express');
const db = require('../db');
const config = require('../config');
const { sendMail } = require('../email');
const { SERVICES, TIERS, calculateEstimate } = require('../pricing');
const { str, isEmail, normalizePhone } = require('../validate');

const router = express.Router();

// Public: pricing table for the live calculator.
router.get('/pricing', (req, res) => {
  res.json({ services: SERVICES, tiers: TIERS });
});

// Public: compute an estimate without saving (used by the live calculator).
router.post('/estimate', (req, res) => {
  const result = calculateEstimate({
    service: str(req.body.service, 60),
    size: req.body.size,
    tier: str(req.body.tier, 30),
  });
  if (!result) return res.status(400).json({ error: 'Please choose a valid service.' });
  res.json({ estimate: result });
});

// Public: submit an estimate request / contact form. Saves a lead + notifies.
router.post('/leads', async (req, res) => {
  const name = str(req.body.name, 120);
  const email = str(req.body.email, 254).toLowerCase();
  const phone = normalizePhone(req.body.phone);
  const service = str(req.body.service, 60);
  const message = str(req.body.message, 4000);

  // Honeypot: bots fill hidden fields, humans don't.
  if (str(req.body.company, 100)) return res.status(200).json({ ok: true });

  if (!name) return res.status(400).json({ error: 'Please enter your name.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
  if (!phone) return res.status(400).json({ error: 'Please enter a valid phone number.' });

  const est = calculateEstimate({ service, size: req.body.size, tier: str(req.body.tier, 30) });

  const userId = req.user ? req.user.id : null;
  db.prepare(
    `INSERT INTO leads (user_id, name, email, phone, service, size, tier, estimate_low, estimate_high, message)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    userId,
    name,
    email,
    phone,
    service || null,
    est ? est.size : null,
    est ? est.tier : null,
    est ? est.low : null,
    est ? est.high : null,
    message || null
  );

  // Fire-and-forget notifications.
  sendMail({
    to: config.notifyEmail,
    subject: 'New estimate request — CAG Construction',
    text: `Name: ${name}\nEmail: ${email}\nPhone: ${phone}\nService: ${service || 'n/a'}\n` +
      (est ? `Estimate: $${est.low.toLocaleString()}–$${est.high.toLocaleString()}\n` : '') +
      `Message: ${message || '(none)'}`,
  });
  sendMail({
    to: email,
    subject: 'We received your request — CAG Construction',
    text: `Hi ${name},\n\nThanks for reaching out to CAG Construction! We've received your request` +
      (service ? ` for ${service}` : '') +
      `.\n\n` +
      (est ? `Your ballpark estimate is $${est.low.toLocaleString()}–$${est.high.toLocaleString()}. ` +
        `This is a rough range — we'll confirm exact pricing after a free on-site visit.\n\n` : '') +
      `We'll be in touch within 24 hours.\n\n— CAG Construction LLC\n(719) 725-4350`,
  });

  res.status(201).json({ ok: true, estimate: est });
});

module.exports = router;
