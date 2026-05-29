'use strict';

/* ---------- helpers ---------- */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...opts,
  });
  let data = {};
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) throw new Error(data.error || 'Request failed. Please try again.');
  return data;
}

function showAlert(el, msg, type) {
  el.textContent = msg;
  el.className = `alert alert-${type} show`;
}
function clearAlerts(...els) { els.forEach((e) => { e.className = 'alert'; e.textContent = ''; }); }
function money(n) { return '$' + Number(n).toLocaleString(); }

// Generates a branded SVG placeholder so the gallery looks finished without photo assets.
function placeholder(label, tone) {
  const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 800 600'>
    <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
      <stop offset='0' stop-color='${tone}'/><stop offset='1' stop-color='#0f0f1a'/></linearGradient></defs>
    <rect width='800' height='600' fill='url(#g)'/>
    <text x='400' y='310' font-family='Georgia, serif' font-size='40' fill='#d4af37' text-anchor='middle'>${label}</text>
  </svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

/* ---------- nav auth state ---------- */
async function refreshNav() {
  const navAccount = document.getElementById('navAccount');
  if (!navAccount) return;
  try {
    const { user } = await api('/api/auth/me');
    if (user) {
      const dest = user.role === 'admin' ? '/admin.html' : '/account.html';
      navAccount.innerHTML = `<a href="${dest}">${user.role === 'admin' ? 'Dashboard' : 'My Account'}</a>`;
    }
  } catch { /* leave default Sign In link */ }
}

/* ---------- smooth scroll + mobile menu ---------- */
function initNav() {
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      if (href === '#') return;
      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        document.getElementById('navLinks').classList.remove('active');
      }
    });
  });
}

/* ---------- estimate calculator ---------- */
let PRICING = null;
async function initCalculator() {
  const serviceSel = document.getElementById('calcService');
  if (!serviceSel) return;
  const sizeInput = document.getElementById('calcSize');
  const unitEl = document.getElementById('calcUnit');
  const tiersEl = document.getElementById('calcTiers');
  const rangeEl = document.getElementById('calcRange');

  try { PRICING = await api('/api/pricing'); } catch { return; }

  Object.entries(PRICING.services).forEach(([key, s]) => {
    const o = document.createElement('option');
    o.value = key; o.textContent = s.label;
    serviceSel.appendChild(o);
  });
  Object.entries(PRICING.tiers).forEach(([key, t], i) => {
    const label = document.createElement('label');
    label.innerHTML = `<input type="radio" name="tier" value="${key}" ${i === 0 ? 'checked' : ''}><span>${t.label}</span>`;
    tiersEl.appendChild(label);
  });

  function recalc() {
    const svc = PRICING.services[serviceSel.value];
    if (svc) { unitEl.textContent = svc.unit; }
    const tier = document.querySelector('input[name="tier"]:checked');
    const t = PRICING.tiers[tier.value].multiplier;
    const sqft = Math.max(0, Number(sizeInput.value) || 0);
    const mid = Math.round(((svc.base + svc.rate * sqft) * t) / 50) * 50;
    const low = Math.round((mid * 0.85) / 50) * 50;
    const high = Math.round((mid * 1.15) / 50) * 50;
    rangeEl.textContent = `${money(low)} – ${money(high)}`;
  }

  serviceSel.addEventListener('change', () => {
    const svc = PRICING.services[serviceSel.value];
    if (svc && (!sizeInput.value || Number(sizeInput.value) === 0)) sizeInput.value = svc.defaultSize;
    recalc();
  });
  sizeInput.addEventListener('input', recalc);
  tiersEl.addEventListener('change', recalc);
  serviceSel.selectedIndex = 0;
  serviceSel.dispatchEvent(new Event('change'));
}

/* ---------- portfolio gallery + lightbox ---------- */
const GALLERY = [
  { cat: 'concrete', tag: 'Concrete Work', title: 'Decorative Driveway', desc: 'Stamped concrete with custom finish.', tone: '#5a4a2a' },
  { cat: 'concrete', tag: 'Decorative Concrete', title: 'Stamped Patio', desc: 'Stone-pattern outdoor entertaining space.', tone: '#6b5836' },
  { cat: 'decks', tag: 'Deck Construction', title: 'Backyard Deck', desc: 'Custom wood deck with stone features.', tone: '#3a4a3a' },
  { cat: 'framing', tag: 'Framing', title: 'Interior Framing', desc: 'Structural framing with precision finish.', tone: '#4a3a3a' },
  { cat: 'concrete', tag: 'Concrete Steps', title: 'Entryway Renovation', desc: 'New concrete steps and landing.', tone: '#4a4436' },
  { cat: 'decks', tag: 'Deck & Landscaping', title: 'Complete Backyard', desc: 'Deck, walkway, and landscape design.', tone: '#2f3a2f' },
];
let lightboxIndex = 0;

function initGallery() {
  const grid = document.getElementById('portfolioGrid');
  if (!grid) return;

  GALLERY.forEach((item, i) => { item.img = placeholder(item.title, item.tone); });

  function render(filter) {
    grid.innerHTML = '';
    GALLERY.forEach((item, i) => {
      if (filter !== 'all' && item.cat !== filter) return;
      const div = document.createElement('div');
      div.className = 'portfolio-item';
      div.style.backgroundImage = `url("${item.img}")`;
      div.innerHTML = `
        <div class="portfolio-zoom">🔍</div>
        <div class="portfolio-content">
          <div class="portfolio-tag">${item.tag}</div>
          <h3>${item.title}</h3>
          <p>${item.desc}</p>
        </div>`;
      div.addEventListener('click', () => openLightbox(i));
      grid.appendChild(div);
    });
  }

  document.querySelectorAll('.filter-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      render(btn.dataset.filter);
    });
  });
  render('all');

  // lightbox controls
  const lb = document.getElementById('lightbox');
  document.getElementById('lbClose').addEventListener('click', closeLightbox);
  document.getElementById('lbNext').addEventListener('click', () => step(1));
  document.getElementById('lbPrev').addEventListener('click', () => step(-1));
  lb.addEventListener('click', (e) => { if (e.target === lb) closeLightbox(); });
  document.addEventListener('keydown', (e) => {
    if (!lb.classList.contains('open')) return;
    if (e.key === 'Escape') closeLightbox();
    if (e.key === 'ArrowRight') step(1);
    if (e.key === 'ArrowLeft') step(-1);
  });
}

function openLightbox(i) {
  lightboxIndex = i;
  renderLightbox();
  document.getElementById('lightbox').classList.add('open');
}
function closeLightbox() { document.getElementById('lightbox').classList.remove('open'); }
function step(dir) { lightboxIndex = (lightboxIndex + dir + GALLERY.length) % GALLERY.length; renderLightbox(); }
function renderLightbox() {
  const item = GALLERY[lightboxIndex];
  document.getElementById('lbImg').src = item.img;
  document.getElementById('lbTitle').textContent = item.title;
  document.getElementById('lbDesc').textContent = `${item.tag} — ${item.desc}`;
}

/* ---------- booking ---------- */
function initBooking() {
  const form = document.getElementById('bookingForm');
  if (!form) return;
  const dateInput = document.getElementById('bkDate');
  const slotsEl = document.getElementById('bkSlots');
  const timeInput = document.getElementById('bkTime');
  const successEl = document.getElementById('bookSuccess');
  const errorEl = document.getElementById('bookError');
  const submitBtn = document.getElementById('bookSubmit');

  // Min date = tomorrow
  const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
  dateInput.min = tomorrow;

  async function loadSlots() {
    timeInput.value = '';
    slotsEl.innerHTML = '<p style="grid-column:1/-1;color:var(--gray);font-size:0.85rem;">Loading…</p>';
    try {
      const { slots } = await api(`/api/bookings/availability?date=${encodeURIComponent(dateInput.value)}`);
      if (!slots.length) {
        slotsEl.innerHTML = '<p style="grid-column:1/-1;color:var(--gray);font-size:0.85rem;">No times available (we\'re closed Sundays). Try another day.</p>';
        return;
      }
      slotsEl.innerHTML = '';
      slots.forEach((s) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'slot-btn';
        b.textContent = s.label;
        b.disabled = !s.available;
        b.addEventListener('click', () => {
          slotsEl.querySelectorAll('.slot-btn').forEach((x) => x.classList.remove('selected'));
          b.classList.add('selected');
          timeInput.value = s.time;
        });
        slotsEl.appendChild(b);
      });
    } catch (err) {
      slotsEl.innerHTML = `<p style="grid-column:1/-1;color:#a02020;font-size:0.85rem;">${err.message}</p>`;
    }
  }

  dateInput.addEventListener('change', loadSlots);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlerts(successEl, errorEl);
    if (!timeInput.value) { showAlert(errorEl, 'Please pick an available time slot.', 'error'); return; }
    submitBtn.disabled = true; submitBtn.textContent = 'Booking…';
    try {
      const payload = Object.fromEntries(new FormData(form).entries());
      const { booking } = await api('/api/bookings', { method: 'POST', body: JSON.stringify(payload) });
      showAlert(successEl, `You're booked for ${booking.date} at ${booking.label}. Check your email for confirmation!`, 'success');
      form.reset();
      slotsEl.innerHTML = '<p style="grid-column:1/-1;color:var(--gray);font-size:0.85rem;">Pick a date to see open times.</p>';
      timeInput.value = '';
    } catch (err) {
      showAlert(errorEl, err.message, 'error');
      if (String(err.message).toLowerCase().includes('slot')) loadSlots();
    } finally {
      submitBtn.disabled = false; submitBtn.textContent = 'Confirm Booking →';
    }
  });
}

/* ---------- contact / estimate request ---------- */
function initContact() {
  const form = document.getElementById('contactForm');
  if (!form) return;
  const successEl = document.getElementById('contactSuccess');
  const errorEl = document.getElementById('contactError');
  const submitBtn = document.getElementById('contactSubmit');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlerts(successEl, errorEl);
    submitBtn.disabled = true; submitBtn.textContent = 'Sending…';
    try {
      const payload = Object.fromEntries(new FormData(form).entries());
      await api('/api/leads', { method: 'POST', body: JSON.stringify(payload) });
      showAlert(successEl, "Thanks! We received your request and will reply within 24 hours.", 'success');
      form.reset();
    } catch (err) {
      showAlert(errorEl, err.message, 'error');
    } finally {
      submitBtn.disabled = false; submitBtn.textContent = 'Send Request →';
    }
  });
}

/* ---------- testimonials carousel ---------- */
function initTestimonials() {
  const cards = document.querySelectorAll('.testimonial-card');
  const dots = document.querySelectorAll('.carousel-dot');
  if (!cards.length) return;
  let current = 0;

  function show(i) {
    cards.forEach((c) => c.classList.remove('active'));
    dots.forEach((d) => d.classList.remove('active'));
    cards[i].classList.add('active');
    dots[i].classList.add('active');
    current = i;
  }
  dots.forEach((dot) => dot.addEventListener('click', () => show(Number(dot.dataset.index))));
  setInterval(() => show((current + 1) % cards.length), 6000);
}

/* ---------- boot ---------- */
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  refreshNav();
  initCalculator();
  initGallery();
  initBooking();
  initContact();
  initTestimonials();
});
