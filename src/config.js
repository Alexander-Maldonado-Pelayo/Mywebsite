'use strict';

require('dotenv').config();

const config = {
  port: parseInt(process.env.PORT, 10) || 3000,
  env: process.env.NODE_ENV || 'development',
  jwtSecret: process.env.JWT_SECRET || 'dev-insecure-secret-change-me',
  admin: {
    name: process.env.ADMIN_NAME || 'CAG Admin',
    email: (process.env.ADMIN_EMAIL || 'cagconstructiona@gmail.com').toLowerCase(),
    password: process.env.ADMIN_PASSWORD || 'changeme123',
  },
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'CAG Construction <no-reply@cagconstruction.com>',
  },
  notifyEmail: (process.env.NOTIFY_EMAIL || process.env.ADMIN_EMAIL || '').toLowerCase(),
};

config.isProd = config.env === 'production';

if (config.isProd && config.jwtSecret === 'dev-insecure-secret-change-me') {
  console.warn('[config] WARNING: JWT_SECRET is not set in production. Set it in .env!');
}

module.exports = config;
