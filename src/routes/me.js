'use strict';

const express = require('express');
const db = require('../db');
const { requireAuth } = require('../auth');

const router = express.Router();

router.use(requireAuth);

// The logged-in customer's consultation bookings.
router.get('/bookings', (req, res) => {
  const rows = db
    .prepare(
      `SELECT id, service, date, time, address, status, created_at
       FROM bookings WHERE user_id = ? ORDER BY date DESC, time DESC`
    )
    .all(req.user.id);
  res.json({ bookings: rows });
});

// The logged-in customer's projects, each with its update timeline.
router.get('/projects', (req, res) => {
  const projects = db
    .prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.user.id);

  const getUpdates = db.prepare(
    'SELECT id, status, note, created_at FROM project_updates WHERE project_id = ? ORDER BY created_at DESC'
  );
  for (const p of projects) p.updates = getUpdates.all(p.id);

  res.json({ projects });
});

module.exports = router;
