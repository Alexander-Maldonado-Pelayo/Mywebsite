'use strict';

const express = require('express');
const db = require('../db');
const config = require('../config');
const { sendMail } = require('../email');
const { str, isEmail, normalizePhone, isFutureDate } = require('../validate');

const router = express.Router();

// Consultation time slots offered each working day.
const SLOTS = ['08:00', '10:00', '12:00', '14:00', '16:00'];

function slotLabel(t) {
  const [h] = t.split(':').map(Number);
  const ampm = h >= 12 ? 'PM' : 'AM';
  const hr = h % 12 === 0 ? 12 : h % 12;
  return `${hr}:00 ${ampm}`;
}

// Public: which slots are open on a given date.
router.get('/bookings/availability', (req, res) => {
  const date = str(req.query.date, 10);
  if (!isFutureDate(date)) return res.status(400).json({ error: 'Choose a valid future date.' });

  // No Sunday consultations (getDay 0). Parse as local noon to avoid TZ drift.
  const day = new Date(`${date}T12:00:00`).getDay();
  if (day === 0) return res.json({ date, slots: [] });

  const taken = db
    .prepare("SELECT time FROM bookings WHERE date = ? AND status != 'cancelled'")
    .all(date)
    .map((r) => r.time);

  const slots = SLOTS.map((t) => ({ time: t, label: slotLabel(t), available: !taken.includes(t) }));
  res.json({ date, slots });
});

// Public (or logged-in): create a booking.
router.post('/bookings', async (req, res) => {
  const name = str(req.body.name, 120);
  const email = str(req.body.email, 254).toLowerCase();
  const phone = normalizePhone(req.body.phone);
  const service = str(req.body.service, 60);
  const date = str(req.body.date, 10);
  const time = str(req.body.time, 5);
  const address = str(req.body.address, 300);
  const notes = str(req.body.notes, 2000);

  if (!name) return res.status(400).json({ error: 'Please enter your name.' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
  if (!phone) return res.status(400).json({ error: 'Please enter a valid phone number.' });
  if (!isFutureDate(date)) return res.status(400).json({ error: 'Please choose a valid future date.' });
  if (!SLOTS.includes(time)) return res.status(400).json({ error: 'Please choose a valid time slot.' });

  const userId = req.user ? req.user.id : null;

  try {
    const info = db
      .prepare(
        `INSERT INTO bookings (user_id, name, email, phone, service, date, time, address, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(userId, name, email, phone, service || null, date, time, address || null, notes || null);

    sendMail({
      to: config.notifyEmail,
      subject: `New consultation booked — ${date} ${slotLabel(time)}`,
      text: `Name: ${name}\nEmail: ${email}\nPhone: ${phone}\nService: ${service || 'n/a'}\n` +
        `When: ${date} at ${slotLabel(time)}\nAddress: ${address || 'n/a'}\nNotes: ${notes || '(none)'}`,
    });
    sendMail({
      to: email,
      subject: 'Your consultation is booked — CAG Construction',
      text: `Hi ${name},\n\nYour free on-site consultation is booked for ${date} at ${slotLabel(time)}.\n\n` +
        `We'll call to confirm. Need to change it? Reply or call (719) 725-4350.\n\n— CAG Construction LLC`,
    });

    res.status(201).json({ ok: true, booking: { id: info.lastInsertRowid, date, time, label: slotLabel(time) } });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'Sorry, that slot was just taken. Please pick another time.' });
    }
    throw err;
  }
});

module.exports = router;
