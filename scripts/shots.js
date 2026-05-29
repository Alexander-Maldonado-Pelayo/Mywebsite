'use strict';
// Renders the running app to PNG screenshots so they can be reviewed without a browser.
const puppeteer = require('puppeteer');
const path = require('path');

const BASE = 'http://localhost:3000';
const OUT = path.join(__dirname, '..', 'shots');
require('fs').mkdirSync(OUT, { recursive: true });

async function login(page, email, password) {
  await page.goto(`${BASE}/login.html`, { waitUntil: 'networkidle2' });
  await page.evaluate(async (e, p) => {
    await fetch('/api/auth/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ email: e, password: p }),
    });
  }, email, password);
}

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1366, height: 900, deviceScaleFactor: 1 });

  // 1. Home (full page)
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle2' });
  await new Promise((r) => setTimeout(r, 1200));
  await page.screenshot({ path: path.join(OUT, '1-home.png'), fullPage: true });

  // 2. Login page
  await page.goto(`${BASE}/login.html`, { waitUntil: 'networkidle2' });
  await page.screenshot({ path: path.join(OUT, '2-login.png') });

  // 3. Admin dashboard
  await login(page, 'cagconstructiona@gmail.com', 'changeme123');
  await page.goto(`${BASE}/admin.html`, { waitUntil: 'networkidle2' });
  await new Promise((r) => setTimeout(r, 1200));
  await page.screenshot({ path: path.join(OUT, '3-admin.png'), fullPage: true });

  // 4. Customer account (project tracking)
  await login(page, 'customer@example.com', 'password123');
  await page.goto(`${BASE}/account.html`, { waitUntil: 'networkidle2' });
  await new Promise((r) => setTimeout(r, 1000));
  await page.screenshot({ path: path.join(OUT, '4-account.png'), fullPage: true });

  await browser.close();
  console.log('screenshots written to', OUT);
})().catch((e) => { console.error(e); process.exit(1); });
