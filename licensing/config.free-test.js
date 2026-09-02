// Packaging-only profile used to verify Free restrictions before Store billing
// is connected. Development and shipping source builds keep using config.js.
window.__JB_DRILL_LICENSE_CONFIG__ = Object.freeze({
  enabled: true,
  testMode: true,
  initialPlan: "free",
  endpoint: "",
  leasePublicKey: null,
});
