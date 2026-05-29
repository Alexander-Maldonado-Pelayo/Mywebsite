'use strict';

// Creates the initial admin account from .env (idempotent) and, in development,
// adds a sample customer + project so the dashboards aren't empty.

const db = require('../src/db');
const config = require('../src/config');
const { hashPassword } = require('../src/auth');

function upsertUser({ name, email, password, role, phone }) {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return existing.id;
  const info = db
    .prepare('INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)')
    .run(name, email, phone || null, hashPassword(password), role);
  console.log(`Created ${role}: ${email}`);
  return info.lastInsertRowid;
}

// Admin
upsertUser({
  name: config.admin.name,
  email: config.admin.email,
  password: config.admin.password,
  role: 'admin',
});

// Demo data (development only)
if (!config.isProd) {
  const customerId = upsertUser({
    name: 'Sample Customer',
    email: 'customer@example.com',
    password: 'password123',
    role: 'customer',
    phone: '7195551234',
  });

  const hasProject = db.prepare('SELECT id FROM projects WHERE user_id = ?').get(customerId);
  if (!hasProject) {
    const info = db
      .prepare(
        `INSERT INTO projects (user_id, title, service, address, description, status, start_date)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(customerId, 'Backyard Stamped Patio', 'Decorative Concrete', '123 Pine St, Colorado Springs',
        '400 sq ft stamped concrete patio with stone border.', 'in_progress', '2026-06-02');
    db.prepare('INSERT INTO project_updates (project_id, status, note) VALUES (?, ?, ?)')
      .run(info.lastInsertRowid, 'scheduled', 'Estimate approved, materials ordered.');
    db.prepare('INSERT INTO project_updates (project_id, status, note) VALUES (?, ?, ?)')
      .run(info.lastInsertRowid, 'in_progress', 'Forms set and base poured. Stamping next week.');
    console.log('Created sample project for customer@example.com');
  }
}

console.log('Seed complete.');
process.exit(0);
