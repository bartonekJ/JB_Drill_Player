(function exposeJBDrillLicenseCore(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.JBDrillLicenseCore = api;
}(typeof globalThis !== "undefined" ? globalThis : this, function createJBDrillLicenseCore() {
  "use strict";

  const PLAN_DEFINITIONS = Object.freeze({
    free: Object.freeze({
      id: "free",
      label: "Free",
      deviceLimit: 1,
      maxSheets: 2,
      maxExportSheets: 2,
      watermarkExports: true,
    }),
    personal: Object.freeze({
      id: "personal",
      label: "Personal",
      deviceLimit: 3,
      maxSheets: Number.POSITIVE_INFINITY,
      maxExportSheets: Number.POSITIVE_INFINITY,
      watermarkExports: false,
    }),
    club: Object.freeze({
      id: "club",
      label: "Club",
      deviceLimit: 30,
      maxSheets: Number.POSITIVE_INFINITY,
      maxExportSheets: Number.POSITIVE_INFINITY,
      watermarkExports: false,
    }),
    development: Object.freeze({
      id: "development",
      label: "Development",
      deviceLimit: Number.POSITIVE_INFINITY,
      maxSheets: Number.POSITIVE_INFINITY,
      maxExportSheets: Number.POSITIVE_INFINITY,
      watermarkExports: false,
    }),
  });

  const ACTIVE_STATUSES = new Set(["active", "grace", "development"]);

  function planDefinition(planId) {
    return PLAN_DEFINITIONS[planId] || PLAN_DEFINITIONS.free;
  }

  function finiteTimestamp(value) {
    const timestamp = typeof value === "string" ? Date.parse(value) : Number(value);
    return Number.isFinite(timestamp) && timestamp > 0 ? timestamp : null;
  }

  function normalizeEntitlement(value = {}, now = Date.now()) {
    const requestedPlan = String(value.plan || "free").toLowerCase();
    const requestedStatus = String(value.status || (requestedPlan === "free" ? "free" : "active")).toLowerCase();
    const leaseExpiresAt = finiteTimestamp(value.leaseExpiresAt);
    const periodEndsAt = finiteTimestamp(value.periodEndsAt);
    const leaseAlive = leaseExpiresAt === null || leaseExpiresAt > now;
    const periodAlive = periodEndsAt === null || periodEndsAt > now;
    const paidActive = requestedPlan !== "free"
      && ACTIVE_STATUSES.has(requestedStatus)
      && leaseAlive
      && periodAlive;
    const plan = paidActive ? planDefinition(requestedPlan) : PLAN_DEFINITIONS.free;
    return Object.freeze({
      plan: plan.id,
      label: plan.label,
      status: paidActive ? requestedStatus : "free",
      source: String(value.source || (plan.id === "development" ? "development" : "none")),
      licenseId: typeof value.licenseId === "string" ? value.licenseId : "",
      deviceId: typeof value.deviceId === "string" ? value.deviceId : "",
      leaseExpiresAt,
      periodEndsAt,
      deviceLimit: plan.deviceLimit,
      maxSheets: plan.maxSheets,
      maxExportSheets: plan.maxExportSheets,
      watermarkExports: plan.watermarkExports,
    });
  }

  function capabilities(entitlement) {
    const normalized = normalizeEntitlement(entitlement);
    return Object.freeze({
      plan: normalized.plan,
      maxSheets: normalized.maxSheets,
      maxExportSheets: normalized.maxExportSheets,
      canExportPdf: true,
      canExportVideo: true,
      canShareJBPlay: true,
      watermarkExports: normalized.watermarkExports,
    });
  }

  function remainingSheetCapacity(entitlement, currentCount) {
    const maximum = normalizeEntitlement(entitlement).maxSheets;
    if (!Number.isFinite(maximum)) return Number.POSITIVE_INFINITY;
    return Math.max(0, maximum - Math.max(0, Number(currentCount) || 0));
  }

  function canAddSheets(entitlement, currentCount, requestedCount = 1) {
    return remainingSheetCapacity(entitlement, currentCount) >= Math.max(0, Number(requestedCount) || 0);
  }

  function selectExportSheets(entitlement, sheets) {
    const source = Array.isArray(sheets) ? sheets : [];
    const maximum = normalizeEntitlement(entitlement).maxExportSheets;
    return Number.isFinite(maximum) ? source.slice(0, maximum) : source.slice();
  }

  function activeDevices(registry, now = Date.now()) {
    return (Array.isArray(registry) ? registry : []).filter((device) => {
      if (!device || device.deactivatedAt) return false;
      const expiresAt = finiteTimestamp(device.expiresAt);
      return expiresAt === null || expiresAt > now;
    });
  }

  function activateDevice(entitlement, registry, device, now = Date.now()) {
    const normalized = normalizeEntitlement(entitlement, now);
    const devices = activeDevices(registry, now);
    const deviceId = String(device?.deviceId || "").trim();
    if (!deviceId) return { ok: false, reason: "invalid-device", devices };
    const existing = devices.find((candidate) => candidate.deviceId === deviceId);
    if (existing) {
      return {
        ok: true,
        reused: true,
        devices: devices.map((candidate) => candidate.deviceId === deviceId
          ? { ...candidate, ...device, deviceId, lastSeenAt: now }
          : candidate),
      };
    }
    if (devices.length >= normalized.deviceLimit) {
      return { ok: false, reason: "device-limit", devices };
    }
    return {
      ok: true,
      reused: false,
      devices: [...devices, { ...device, deviceId, activatedAt: now, lastSeenAt: now }],
    };
  }

  return Object.freeze({
    PLAN_DEFINITIONS,
    planDefinition,
    normalizeEntitlement,
    capabilities,
    remainingSheetCapacity,
    canAddSheets,
    selectExportSheets,
    activeDevices,
    activateDevice,
  });
}));
