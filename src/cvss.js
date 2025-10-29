// src/cvss.js
// CVSS v3.1 Base Score Calculator core logic

// Step 1: Define metric weight values (as per NIST CVSS v3.1)
const AV_map = {N:0.85, A:0.62, L:0.55, P:0.2};
const AC_map = {L:0.77, H:0.44};
const UI_map = {N:0.85, R:0.62};
const CIA_map = {N:0.0, L:0.22, H:0.56};
const PR_map_scopeU = {N:0.85, L:0.62, H:0.27};
const PR_map_scopeC = {N:0.85, L:0.68, H:0.50};

// Step 2: Helper to round up to 1 decimal place
function roundup1(x) {
  return Math.ceil(x * 10) / 10;
}

// Step 3: Main calculation function
function calcBaseScore(metrics) {
  const AV = AV_map[metrics.AV];
  const AC = AC_map[metrics.AC];
  const UI = UI_map[metrics.UI];
  const S = metrics.S; // 'U' or 'C'
  const C = CIA_map[metrics.C];
  const I = CIA_map[metrics.I];
  const A = CIA_map[metrics.A];

  const PR = (S === 'U') ? PR_map_scopeU[metrics.PR] : PR_map_scopeC[metrics.PR];

  // Impact & Exploitability formulas
  const impact = 1 - ((1 - C) * (1 - I) * (1 - A));
  const impactSub = (S === 'U')
    ? 6.42 * impact
    : 7.52 * (impact - 0.029) - 3.25 * Math.pow((impact - 0.02), 15);

  const exploitability = 8.22 * AV * AC * PR * UI;

  if (impact <= 0) {
    return { base: 0.0, impact, exploitability, impactSub };
  }

  // Base Score formula
  let base = (S === 'U')
    ? Math.min(impactSub + exploitability, 10)
    : Math.min(1.08 * (impactSub + exploitability), 10);

  base = roundup1(base);

  return { base, impact, exploitability, impactSub };
}

// Step 4: Export function so we can use it in tests
module.exports = { calcBaseScore };