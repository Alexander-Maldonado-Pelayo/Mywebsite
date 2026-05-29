# CAG Construction LLC — Web App

A full-stack web app for CAG Construction (Colorado Springs). It pairs the
marketing site with real, usable features:

- **Instant estimate calculator** — pick a service, size, and finish tier for a live price range.
- **Photo gallery + lightbox** — filterable portfolio with click-to-enlarge.
- **Smart contact form** — inline validation, success/error messages, honeypot spam protection, and automatic email confirmations.
- **Online booking** — customers pick a date and an open time slot for a free on-site consultation (double-booking is prevented automatically).
- **Customer accounts** — register/sign in to see your bookings and track project status with a live timeline.
- **Admin dashboard** — the owner sees every lead, booking, and customer, can update statuses, create projects, and post progress updates (which email the customer).

## Tech stack

- **Backend:** Node.js + Express
- **Database:** SQLite (via `better-sqlite3`) — a single self-contained file, no DB server to run
- **Auth:** JWT in an httpOnly cookie, passwords hashed with bcrypt
- **Email:** Nodemailer (optional — logs to console if SMTP isn't configured)
- **Frontend:** vanilla HTML/CSS/JS (no build step)

## Getting started

```bash
npm install
cp .env.example .env      # then edit values (at minimum set JWT_SECRET)
npm run seed              # creates the admin account (+ demo data in dev)
npm start                 # http://localhost:3000
```

Open <http://localhost:3000>.

### Default logins (development)

After `npm run seed`:

- **Admin:** the `ADMIN_EMAIL` / `ADMIN_PASSWORD` from your `.env`
  (defaults to `cagconstructiona@gmail.com` / `changeme123` — change these!)
- **Sample customer (dev only):** `customer@example.com` / `password123`

## Deploy (get a public URL your team can open)

The repo includes a Render Blueprint (`render.yaml`) and a `Dockerfile`.

### Easiest: Render.com (free)

1. Go to <https://render.com> and sign up (free) with your GitHub account.
2. **New + → Blueprint**, then pick this repository.
3. Render reads `render.yaml` and prompts for `ADMIN_EMAIL` and `ADMIN_PASSWORD` —
   enter the admin login you want. `JWT_SECRET` is generated for you.
4. Click **Apply**. In a couple minutes you get a public `https://...onrender.com`
   URL that works on any phone or computer. Share it with your employees.

The admin account is created automatically on first boot — no manual step.

> Free Render instances sleep when idle and **reset their database on restart**.
> To keep leads/bookings permanently, use a paid plan with a Disk mounted at
> `/var/data` and set `DATA_DIR=/var/data`, or move to a managed Postgres DB.

### Anywhere with Docker (Railway, Fly.io, Cloud Run, a VPS)

```bash
docker build -t cag-construction .
docker run -p 3000:3000 -e JWT_SECRET=your-secret -v cagdata:/app/data cag-construction
```

## Configuration (`.env`)

| Variable | Purpose |
| --- | --- |
| `PORT` | Server port (default 3000) |
| `JWT_SECRET` | Secret for signing login tokens — **set a long random value in production** |
| `ADMIN_NAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Seeds the first admin account |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | Email delivery. Leave blank to log emails to the console instead. |
| `NOTIFY_EMAIL` | Where new-lead / new-booking alerts go (defaults to `ADMIN_EMAIL`) |

## Project structure

```
server.js            Express app entry point
src/
  config.js          Env-driven configuration
  db.js              SQLite connection + schema
  auth.js            Password hashing, JWT, auth middleware
  email.js           Nodemailer wrapper (console fallback)
  pricing.js         Estimate calculator pricing model
  validate.js        Input validation helpers
  routes/            auth, leads, bookings, me, admin
scripts/seed.js      Seeds admin + demo data
public/              Static frontend (index, login, account, admin + css/js)
data/cag.db          SQLite database (created at runtime, git-ignored)
```

## Notes

- Estimate figures in `src/pricing.js` are rough ballparks — tune them to match real CAG pricing.
- Portfolio images are generated placeholders; drop real photos into `public/` and update the `GALLERY` array in `public/js/main.js`.
- The database file lives in `data/` and is git-ignored. Back it up to retain leads/bookings.
