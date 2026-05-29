'use strict';

const nodemailer = require('nodemailer');
const config = require('./config');

let transporter = null;
const enabled = Boolean(config.smtp.host && config.smtp.user && config.smtp.pass);

if (enabled) {
  transporter = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.port === 465,
    auth: { user: config.smtp.user, pass: config.smtp.pass },
  });
}

// Sends an email if SMTP is configured; otherwise logs it so nothing is lost in dev.
async function sendMail({ to, subject, text, html }) {
  if (!to) return;
  if (!enabled) {
    console.log(`\n[email:dev] To: ${to}\n[email:dev] Subject: ${subject}\n[email:dev] ${text || ''}\n`);
    return;
  }
  try {
    await transporter.sendMail({ from: config.smtp.from, to, subject, text, html });
  } catch (err) {
    console.error('[email] send failed:', err.message);
  }
}

module.exports = { sendMail, emailEnabled: enabled };
