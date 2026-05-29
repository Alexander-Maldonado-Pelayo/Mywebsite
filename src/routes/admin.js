'use strict';

const express = require('express');
const db = require('../db');
const { requireAdmin } = require('../auth');
const { sendMail } = require('../email');
const { str } = require('../validate');

const router = express.Router();

router.use(requireAdmin);

const PROJECT_STATUSES = ['estimate', 'scheduled', 'in_progress', 'completed', 'cancelled'];
const LEAD_STATUSES = ['new', 'contacted', 'quoted', 'won', 'lost'];
const BOOKING_STATUSES = ['pending', 'confirmed', 'completed', 'cancelled'];

// ---- Dashboard summary ----
router.get('/summary', (req, res) => {
  const count = (sql) => db.prepare(sql).get().n;
  res.json({
    leads: count('SELECT COUNT(*) n FROM leads'),
    newLeads: count("SELECT COUNT(*) n FROM leads WHERE status = 'new'"),
    bookings: count('SELECT COUNT(*) n FROM bookings'),
    upcomingBookings: count("SELECT COUNT(*) n FROM bookings WHERE date >= date('now') AND status != 'cancelled'"),
    projects: count('SELECT COUNT(*) n FROM projects'),
    activeProjects: count("SELECT COUNT(*) n FROM projects WHERE status IN ('scheduled','in_progress')"),
    customers: count("SELECT COUNT(*) n FROM users WHERE role = 'customer'"),
  });
});

// ---- Leads ----
router.get('/leads', (req, res) => {
  res.json({ leads: db.prepare('SELECT * FROM leads ORDER BY created_at DESC').all() });
});

router.patch('/leads/:id', (req, res) => {
  const status = str(req.body.status, 30);
  if (!LEAD_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  const info = db.prepare('UPDATE leads SET status = ? WHERE id = ?').run(status, req.params.id);
  if (!info.changes) return res.status(404).json({ error: 'Lead not found.' });
  res.json({ ok: true });
});

// ---- Bookings ----
router.get('/bookings', (req, res) => {
  res.json({ bookings: db.prepare('SELECT * FROM bookings ORDER BY date DESC, time DESC').all() });
});

router.patch('/bookings/:id', (req, res) => {
  const status = str(req.body.status, 30);
  if (!BOOKING_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(req.params.id);
  if (!booking) return res.status(404).json({ error: 'Booking not found.' });
  db.prepare('UPDATE bookings SET status = ? WHERE id = ?').run(status, req.params.id);

  if (status === 'confirmed') {
    sendMail({
      to: booking.email,
      subject: 'Your consultation is confirmed — CAG Construction',
      text: `Hi ${booking.name},\n\nGood news — your consultation on ${booking.date} is confirmed. See you then!\n\n— CAG Construction LLC`,
    });
  }
  res.json({ ok: true });
});

// ---- Customers ----
router.get('/customers', (req, res) => {
  res.json({
    customers: db
      .prepare("SELECT id, name, email, phone, created_at FROM users WHERE role = 'customer' ORDER BY created_at DESC")
      .all(),
  });
});

// ---- Projects ----
router.get('/projects', (req, res) => {
  const projects = db
    .prepare(
      `SELECT p.*, u.name AS customer_name, u.email AS customer_email
       FROM projects p JOIN users u ON u.id = p.user_id
       ORDER BY p.created_at DESC`
    )
    .all();
  const getUpdates = db.prepare(
    'SELECT id, status, note, created_at FROM project_updates WHERE project_id = ? ORDER BY created_at DESC'
  );
  for (const p of projects) p.updates = getUpdates.all(p.id);
  res.json({ projects });
});

router.post('/projects', (req, res) => {
  const userId = parseInt(req.body.user_id, 10);
  const title = str(req.body.title, 200);
  const service = str(req.body.service, 60);
  const address = str(req.body.address, 300);
  const description = str(req.body.description, 4000);
  const status = PROJECT_STATUSES.includes(str(req.body.status, 30)) ? req.body.status : 'estimate';
  const startDate = str(req.body.start_date, 10) || null;

  if (!userId) return res.status(400).json({ error: 'A customer is required.' });
  if (!title) return res.status(400).json({ error: 'A project title is required.' });
  const customer = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'customer'").get(userId);
  if (!customer) return res.status(400).json({ error: 'Customer not found.' });

  const info = db
    .prepare(
      `INSERT INTO projects (user_id, title, service, address, description, status, start_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(userId, title, service || null, address || null, description || null, status, startDate);
  res.status(201).json({ ok: true, id: info.lastInsertRowid });
});

router.patch('/projects/:id', (req, res) => {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id);
  if (!project) return res.status(404).json({ error: 'Project not found.' });

  const status = str(req.body.status, 30);
  if (status && !PROJECT_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });

  const fields = {
    title: req.body.title !== undefined ? str(req.body.title, 200) : project.title,
    service: req.body.service !== undefined ? str(req.body.service, 60) : project.service,
    address: req.body.address !== undefined ? str(req.body.address, 300) : project.address,
    description: req.body.description !== undefined ? str(req.body.description, 4000) : project.description,
    status: status || project.status,
    start_date: req.body.start_date !== undefined ? str(req.body.start_date, 10) || null : project.start_date,
  };

  db.prepare(
    'UPDATE projects SET title=?, service=?, address=?, description=?, status=?, start_date=? WHERE id=?'
  ).run(fields.title, fields.service, fields.address, fields.description, fields.status, fields.start_date, project.id);
  res.json({ ok: true });
});

// Add a timeline update (and optionally move the project's status forward).
router.post('/projects/:id/updates', (req, res) => {
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(req.params.id);
  if (!project) return res.status(404).json({ error: 'Project not found.' });

  const note = str(req.body.note, 4000);
  const status = str(req.body.status, 30);
  if (!note) return res.status(400).json({ error: 'An update note is required.' });
  if (status && !PROJECT_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status.' });

  db.prepare('INSERT INTO project_updates (project_id, status, note) VALUES (?, ?, ?)').run(
    project.id,
    status || null,
    note
  );
  if (status) db.prepare('UPDATE projects SET status = ? WHERE id = ?').run(status, project.id);

  const customer = db.prepare('SELECT name, email FROM users WHERE id = ?').get(project.user_id);
  if (customer) {
    sendMail({
      to: customer.email,
      subject: `Project update: ${project.title}`,
      text: `Hi ${customer.name},\n\nThere's a new update on your project "${project.title}":\n\n${note}\n\n` +
        `Track progress anytime in your account.\n\n— CAG Construction LLC`,
    });
  }
  res.status(201).json({ ok: true });
});

module.exports = router;
