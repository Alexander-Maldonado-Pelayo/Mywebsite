'use strict';

// Ballpark pricing model for the instant estimate calculator.
// These are rough Colorado Springs market figures meant to set expectations,
// not a binding quote. Tune the numbers to match real CAG pricing.

const SERVICES = {
  decks: { label: 'Custom Deck', unit: 'sq ft', base: 1500, rate: 45, defaultSize: 200 },
  framing: { label: 'Framing', unit: 'sq ft', base: 1200, rate: 18, defaultSize: 500 },
  drywall: { label: 'Drywall', unit: 'sq ft', base: 600, rate: 3.5, defaultSize: 800 },
  concrete: { label: 'Concrete', unit: 'sq ft', base: 1000, rate: 9, defaultSize: 400 },
  decorative_concrete: { label: 'Decorative Concrete', unit: 'sq ft', base: 1500, rate: 16, defaultSize: 400 },
  general: { label: 'General Construction', unit: 'sq ft', base: 800, rate: 25, defaultSize: 150 },
};

const TIERS = {
  standard: { label: 'Standard', multiplier: 1.0 },
  premium: { label: 'Premium', multiplier: 1.4 },
  luxury: { label: 'Luxury', multiplier: 1.9 },
};

const RANGE_SPREAD = 0.15; // +/- 15% to express the estimate as a range

function round(value, step = 50) {
  return Math.round(value / step) * step;
}

// Returns { low, high, mid } or null if inputs are invalid.
function calculateEstimate({ service, size, tier }) {
  const svc = SERVICES[service];
  if (!svc) return null;

  const tierInfo = TIERS[tier] || TIERS.standard;
  const sqft = Math.max(0, Number(size) || 0);

  const raw = (svc.base + svc.rate * sqft) * tierInfo.multiplier;
  const mid = round(raw);

  return {
    service,
    serviceLabel: svc.label,
    tier: TIERS[tier] ? tier : 'standard',
    tierLabel: tierInfo.label,
    size: sqft,
    unit: svc.unit,
    low: round(mid * (1 - RANGE_SPREAD)),
    high: round(mid * (1 + RANGE_SPREAD)),
    mid,
  };
}

module.exports = { SERVICES, TIERS, calculateEstimate };
