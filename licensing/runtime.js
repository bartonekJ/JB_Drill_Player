(function initializeJBDrillLicensing() {
  "use strict";

  const core = window.JBDrillLicenseCore;
  if (!core) throw new Error("JB_Drill licensing core did not load");

  const config = Object.freeze({
    enabled: window.__JB_DRILL_LICENSE_CONFIG__?.enabled === true,
    testMode: window.__JB_DRILL_LICENSE_CONFIG__?.testMode === true,
    initialPlan: String(window.__JB_DRILL_LICENSE_CONFIG__?.initialPlan || "free"),
    endpoint: String(window.__JB_DRILL_LICENSE_CONFIG__?.endpoint || "").replace(/\/$/, ""),
    leasePublicKey: window.__JB_DRILL_LICENSE_CONFIG__?.leasePublicKey || null,
  });
  const databaseName = "jb-drill-licensing-v1";
  const storeName = "private-state";
  const identityKey = "installation-identity";
  const entitlementKey = "entitlement";
  const subscribers = new Set();
  let identity = null;
  let entitlement = core.normalizeEntitlement(config.enabled
    ? { plan: "free", status: "free" }
    : { plan: "development", status: "development", source: "development" });

  function openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(databaseName, 1);
      request.addEventListener("upgradeneeded", () => {
        if (!request.result.objectStoreNames.contains(storeName)) {
          request.result.createObjectStore(storeName);
        }
      });
      request.addEventListener("success", () => resolve(request.result));
      request.addEventListener("error", () => reject(request.error || new Error("License storage is unavailable")));
    });
  }

  async function readPrivateState(key) {
    const database = await openDatabase();
    try {
      return await new Promise((resolve, reject) => {
        const transaction = database.transaction(storeName, "readonly");
        const request = transaction.objectStore(storeName).get(key);
        request.addEventListener("success", () => resolve(request.result));
        request.addEventListener("error", () => reject(request.error));
      });
    } finally {
      database.close();
    }
  }

  async function writePrivateState(key, value) {
    const database = await openDatabase();
    try {
      await new Promise((resolve, reject) => {
        const transaction = database.transaction(storeName, "readwrite");
        transaction.objectStore(storeName).put(value, key);
        transaction.addEventListener("complete", resolve);
        transaction.addEventListener("error", () => reject(transaction.error));
        transaction.addEventListener("abort", () => reject(transaction.error));
      });
    } finally {
      database.close();
    }
  }

  function base64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function publicKeyDeviceId(publicKey) {
    const canonical = JSON.stringify({
      crv: publicKey.crv,
      kty: publicKey.kty,
      x: publicKey.x,
      y: publicKey.y,
    });
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return base64Url(new Uint8Array(digest)).slice(0, 32);
  }

  async function createIdentity() {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
    return {
      schemaVersion: 1,
      deviceId: await publicKeyDeviceId(publicKey),
      publicKey,
      privateKey: pair.privateKey,
      createdAt: Date.now(),
    };
  }

  async function getOrCreateIdentity() {
    if (identity) return identity;
    try {
      const stored = await readPrivateState(identityKey);
      if (stored?.deviceId && stored?.publicKey && stored?.privateKey) {
        identity = stored;
        return identity;
      }
      identity = await createIdentity();
      await writePrivateState(identityKey, identity);
      return identity;
    } catch (_error) {
      const random = crypto.getRandomValues(new Uint8Array(24));
      identity = {
        schemaVersion: 1,
        deviceId: base64Url(random),
        publicKey: null,
        privateKey: null,
        createdAt: Date.now(),
        ephemeral: true,
      };
      return identity;
    }
  }

  function randomNonce() {
    return base64Url(crypto.getRandomValues(new Uint8Array(18)));
  }

  async function signedEnvelope(action, payload = {}, { includePublicKey = false } = {}) {
    const installation = await getOrCreateIdentity();
    if (!installation.privateKey) throw new Error("This installation cannot create a secure device proof");
    const message = {
      action,
      deviceId: installation.deviceId,
      timestamp: Date.now(),
      nonce: randomNonce(),
      ...payload,
    };
    const bytes = new TextEncoder().encode(JSON.stringify(message));
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      installation.privateKey,
      bytes,
    );
    return {
      message,
      signature: base64Url(new Uint8Array(signature)),
      ...(includePublicKey ? { publicKey: installation.publicKey } : {}),
    };
  }

  function decodeBase64Url(value) {
    const padded = String(value || "").replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(String(value || "").length / 4) * 4, "=");
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function verifiedEntitlementResponse(response) {
    if (!response.ok) {
      const errorPayload = await response.json().catch(() => ({}));
      throw new Error(errorPayload.error || `License service returned ${response.status}`);
    }
    const result = await response.json();
    if (config.leasePublicKey) {
      const key = await crypto.subtle.importKey(
        "jwk",
        config.leasePublicKey,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        decodeBase64Url(result.signature),
        new TextEncoder().encode(JSON.stringify(result.payload)),
      );
      if (!valid) throw new Error("The license lease signature is invalid");
    } else if (!config.testMode) {
      throw new Error("The license lease verification key is not configured");
    }
    return result.payload?.entitlement;
  }

  async function requestEntitlement(path, envelope) {
    if (!config.endpoint) throw new Error("The license service is not configured");
    const response = await fetch(`${config.endpoint}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
    });
    const next = core.normalizeEntitlement(await verifiedEntitlementResponse(response));
    entitlement = next;
    await writePrivateState(entitlementKey, next);
    emit();
    return api.snapshot();
  }

  function emit() {
    const snapshot = api.snapshot();
    subscribers.forEach((subscriber) => {
      try { subscriber(snapshot); } catch (_error) { /* One UI observer cannot break licensing. */ }
    });
    window.dispatchEvent(new CustomEvent("jbdrilllicensechange", { detail: snapshot }));
  }

  async function initialize() {
    const installation = await getOrCreateIdentity();
    if (!config.enabled) {
      entitlement = core.normalizeEntitlement({
        plan: "development",
        status: "development",
        source: "development",
        deviceId: installation.deviceId,
      });
      emit();
      return api.snapshot();
    }

    let stored = null;
    try { stored = await readPrivateState(entitlementKey); } catch (_error) { /* Free is the safe fallback. */ }
    entitlement = core.normalizeEntitlement(stored || {
      plan: config.testMode ? config.initialPlan : "free",
      status: config.testMode && config.initialPlan !== "free" ? "active" : "free",
      source: config.testMode ? "test" : "none",
      deviceId: installation.deviceId,
    });
    emit();
    return api.snapshot();
  }

  const api = {
    ready: null,
    config,
    snapshot() {
      return Object.freeze({
        entitlement,
        capabilities: core.capabilities(entitlement),
        deviceId: identity?.deviceId || "",
        ready: Boolean(identity),
      });
    },
    capabilities() {
      return core.capabilities(entitlement);
    },
    canAddSheets(currentCount, requestedCount = 1) {
      return core.canAddSheets(entitlement, currentCount, requestedCount);
    },
    remainingSheetCapacity(currentCount) {
      return core.remainingSheetCapacity(entitlement, currentCount);
    },
    selectExportSheets(sheets) {
      return core.selectExportSheets(entitlement, sheets);
    },
    requiresWatermark() {
      return core.capabilities(entitlement).watermarkExports;
    },
    async installationIdentity() {
      const current = await getOrCreateIdentity();
      return Object.freeze({
        deviceId: current.deviceId,
        publicKey: current.publicKey,
        createdAt: current.createdAt,
        ephemeral: current.ephemeral === true,
      });
    },
    subscribe(subscriber) {
      if (typeof subscriber !== "function") return () => {};
      subscribers.add(subscriber);
      return () => subscribers.delete(subscriber);
    },
    async setTestPlan(plan) {
      if (!config.testMode) throw new Error("The license test provider is disabled");
      const installation = await getOrCreateIdentity();
      const nextPlan = core.planDefinition(plan).id;
      entitlement = core.normalizeEntitlement({
        plan: nextPlan,
        status: nextPlan === "free" ? "free" : "active",
        source: "test",
        licenseId: `test-${nextPlan}`,
        deviceId: installation.deviceId,
      });
      await writePrivateState(entitlementKey, entitlement);
      emit();
      return api.snapshot();
    },
    async activate({ activationCode, plan = "personal", platform = "unknown", deviceLabel = "" } = {}) {
      const envelope = await signedEnvelope("activate", {
        activationCode: String(activationCode || ""),
        requestedPlan: String(plan || "personal"),
        platform: String(platform || "unknown"),
        deviceLabel: String(deviceLabel || "").slice(0, 80),
      }, { includePublicKey: true });
      return requestEntitlement("/activate", envelope);
    },
    async refresh() {
      const licenseId = entitlement.licenseId;
      if (!licenseId) return api.snapshot();
      return requestEntitlement("/refresh", await signedEnvelope("refresh", { licenseId }));
    },
  };

  api.ready = initialize();
  window.JBDrillLicensing = Object.freeze(api);
}());
