(function initializeJBDrillLicensing() {
  "use strict";

  const core = window.JBDrillLicenseCore;
  if (!core) throw new Error("JB_Drill licensing core did not load");

  const configuredMicrosoftStoreProducts = Object.freeze(Object.fromEntries(
    Object.entries(window.__JB_DRILL_LICENSE_CONFIG__?.microsoftStoreProducts || {})
      .filter(([, product]) => /^[A-Z0-9]{8,20}$/i.test(String(product?.storeId || "")))
      .map(([key, product]) => [key, Object.freeze({
        storeId: String(product.storeId),
        plan: core.planDefinition(product.plan).id,
        billingPeriod: String(product.billingPeriod || ""),
        label: String(product.label || key),
      })]),
  ));
  const configuredGooglePlayProducts = Object.freeze(Object.fromEntries(
    Object.entries(window.__JB_DRILL_LICENSE_CONFIG__?.googlePlayProducts || {})
      .filter(([, product]) => (
        /^[a-z0-9][a-z0-9_.]{0,39}$/.test(String(product?.productId || ""))
        && /^[a-z0-9][a-z0-9-]{0,62}$/.test(String(product?.basePlanId || ""))
      ))
      .map(([key, product]) => [key, Object.freeze({
        productId: String(product.productId),
        basePlanId: String(product.basePlanId),
        plan: core.planDefinition(product.plan).id,
        billingPeriod: String(product.billingPeriod || ""),
        label: String(product.label || key),
      })]),
  ));

  const config = Object.freeze({
    enabled: window.__JB_DRILL_LICENSE_CONFIG__?.enabled === true,
    testMode: window.__JB_DRILL_LICENSE_CONFIG__?.testMode === true,
    initialPlan: String(window.__JB_DRILL_LICENSE_CONFIG__?.initialPlan || "free"),
    endpoint: String(window.__JB_DRILL_LICENSE_CONFIG__?.endpoint || "").replace(/\/$/, ""),
    microsoftStore: window.__JB_DRILL_LICENSE_CONFIG__?.microsoftStore === true,
    microsoftStoreProducts: configuredMicrosoftStoreProducts,
    googlePlay: window.__JB_DRILL_LICENSE_CONFIG__?.googlePlay === true,
    googlePlayPackageName: String(window.__JB_DRILL_LICENSE_CONFIG__?.googlePlayPackageName || ""),
    googlePlayProducts: configuredGooglePlayProducts,
    leasePublicKey: window.__JB_DRILL_LICENSE_CONFIG__?.leasePublicKey || null,
  });
  const databaseName = "jb-drill-licensing-v1";
  const storeName = "private-state";
  const identityKey = "installation-identity";
  const entitlementKey = "entitlement";
  const subscribers = new Set();
  const definitiveLicenseStatuses = new Set([401, 403, 404, 410]);
  const googlePlayRequests = new Map();
  let identity = null;
  let connectionStatus = "unknown";
  let entitlementRequestVersion = 0;
  let refreshInFlight = null;
  let refreshTimer = null;
  let expiryTimer = null;
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

  class LicenseServiceError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "LicenseServiceError";
      this.status = Number(status) || 0;
    }
  }

  async function parsedResponse(response) {
    if (!response.ok) {
      const errorPayload = await response.json().catch(() => ({}));
      throw new LicenseServiceError(errorPayload.error || `License service returned ${response.status}`, response.status);
    }
    return response.json();
  }

  async function verifiedEntitlementResult(result) {
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

  async function requestJson(path, envelope) {
    if (!config.endpoint) throw new Error("The license service is not configured");
    if (navigator.onLine === false) {
      throw new LicenseServiceError("You are offline. Connect to the internet to check purchases or linked devices.", 0);
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetch(`${config.endpoint}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(envelope),
        signal: controller.signal,
      });
      if (connectionStatus !== "online") {
        connectionStatus = "online";
      }
      return await parsedResponse(response);
    } catch (error) {
      if (error instanceof LicenseServiceError) throw error;
      connectionStatus = "unavailable";
      emit();
      throw new LicenseServiceError("Cannot reach the license service. Check your internet connection and try again. Your saved drills are unchanged.", 0);
    } finally {
      clearTimeout(timeout);
    }
  }

  async function requestEntitlement(path, envelope) {
    const version = ++entitlementRequestVersion;
    let next;
    try {
      next = await verifiedEntitlementResult(await requestJson(path, envelope));
    } catch (error) {
      error.entitlementRequestVersion = version;
      throw error;
    }
    // A late background refresh must not overwrite a newer purchase/Restore.
    if (version !== entitlementRequestVersion) return api.snapshot();
    entitlement = next;
    await writePrivateState(entitlementKey, next);
    emit();
    scheduleLicenseChecks();
    return api.snapshot();
  }

  async function clearRejectedEntitlement(expectedVersion) {
    const installation = await getOrCreateIdentity();
    if (expectedVersion !== entitlementRequestVersion) return api.snapshot();
    // Retain the reference so a later renewal can recover automatically, also
    // on linked devices that do not have the purchasing Play account.
    const googleLicenseId = entitlement.licenseId?.startsWith("gp-") ? entitlement.licenseId : "";
    entitlement = core.normalizeEntitlement({
      plan: "free",
      status: "free",
      source: googleLicenseId ? "jb-license-service" : "license-service",
      licenseId: googleLicenseId,
      deviceId: installation.deviceId,
    });
    await writePrivateState(entitlementKey, entitlement);
    emit();
    return api.snapshot();
  }

  async function performEntitlementRefresh() {
    const licenseId = entitlement.licenseId;
    if (!licenseId) return api.snapshot();
    if (navigator.onLine === false) return api.snapshot();
    try {
      return await requestEntitlement("/refresh", await signedEnvelope("refresh", { licenseId }));
    } catch (error) {
      if (error.entitlementRequestVersion !== entitlementRequestVersion) return api.snapshot();
      if (error.status === 428 && config.googlePlay) {
        // One-time migration of old licenses whose server record lacks a token.
        return restoreGooglePlayEntitlement({ platform: "android" });
      }
      if (definitiveLicenseStatuses.has(Number(error?.status))) {
        return clearRejectedEntitlement(error.entitlementRequestVersion);
      }
      throw error;
    }
  }

  function refreshCurrentEntitlement() {
    if (!refreshInFlight) {
      refreshInFlight = performEntitlementRefresh().finally(() => { refreshInFlight = null; });
    }
    return refreshInFlight;
  }

  function scheduleLicenseChecks() {
    clearTimeout(refreshTimer);
    clearTimeout(expiryTimer);
    if (!config.enabled || !config.endpoint || !entitlement.licenseId) return;
    const now = Date.now();
    const deadlines = [entitlement.periodEndsAt, entitlement.leaseExpiresAt]
      .map((value) => typeof value === "string" ? Date.parse(value) : Number(value))
      .filter((value) => Number.isFinite(value) && value > now);
    const deadline = deadlines.length ? Math.min(...deadlines) : null;
    const delay = deadline === null ? 60_000 : deadline - now > 330_000
      ? 300_000 : Math.max(15_000, Math.min(60_000, deadline - now - 30_000));
    refreshTimer = setTimeout(checkLicenseInBackground, delay);
    if (deadline !== null) {
      // Update the UI at offline expiry as well as checking capabilities on use.
      expiryTimer = setTimeout(() => { emit(); }, Math.min(2_147_483_647, deadline - now + 1));
    }
  }

  async function checkLicenseInBackground() {
    if (document.visibilityState !== "hidden" && navigator.onLine !== false && !refreshInFlight) {
      try { await refreshCurrentEntitlement(); } catch (_error) {
        // Transport/service errors preserve only the still-valid signed lease.
      }
    }
    emit();
    scheduleLicenseChecks();
  }

  function googlePlayLog(message, details = {}) {
    if (!config.googlePlay) return;
    try {
      console.info("[JBDrillGooglePlay]", message, details);
    } catch (_error) {
      // Diagnostics only.
    }
  }

  function googlePlayNativeRequest(method, ...args) {
    const bridge = window.JBDrillGooglePlayBilling;
    if (typeof bridge?.[method] !== "function") {
      return Promise.reject(new Error("Google Play Billing is not available on this installation"));
    }
    const requestId = `gp-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    googlePlayLog("native request started", { requestId, method });
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        googlePlayRequests.delete(requestId);
        googlePlayLog("native request timed out", { requestId, method });
        reject(new Error("Google Play Billing did not respond in time"));
      }, 120000);
      googlePlayRequests.set(requestId, { resolve, reject, timeout });
      try {
        bridge[method](requestId, ...args.map((value) => String(value ?? "")));
      } catch (error) {
        clearTimeout(timeout);
        googlePlayRequests.delete(requestId);
        googlePlayLog("native request threw", { requestId, method, error: error?.message || String(error) });
        reject(error);
      }
    });
  }

  window.onJBDrillGooglePlayBillingResult = (requestId, payload) => {
    const pending = googlePlayRequests.get(String(requestId || ""));
    if (!pending) {
      googlePlayLog("native result ignored", { requestId });
      return;
    }
    clearTimeout(pending.timeout);
    googlePlayRequests.delete(String(requestId || ""));
    const result = typeof payload === "string"
      ? (() => { try { return JSON.parse(payload); } catch (_error) { return { ok: false, error: payload }; } })()
      : payload;
    googlePlayLog("native result received", {
      requestId,
      ok: result?.ok,
      status: result?.status,
      purchases: Array.isArray(result?.purchases) ? result.purchases.length : (result?.purchase ? 1 : 0),
      error: result?.error || "",
    });
    if (result?.ok === false) {
      pending.reject(new Error(result.error || "Google Play Billing failed"));
      return;
    }
    pending.resolve(result || {});
  };

  function googlePlayProductIds() {
    return [...new Set(Object.values(config.googlePlayProducts).map((product) => product.productId))];
  }

  function selectGooglePlayPurchase(purchases) {
    const ranked = [];
    for (const purchase of Array.isArray(purchases) ? purchases : []) {
      const productIds = Array.isArray(purchase?.products)
        ? purchase.products
        : [purchase?.productId].filter(Boolean);
      for (const productId of productIds) {
        const candidates = Object.values(config.googlePlayProducts)
          .filter((product) => product.productId === productId);
        for (const definition of candidates) ranked.push({ purchase, productId, definition });
      }
    }
    return ranked.sort((left, right) => (
      (right.definition.plan === "club" ? 1 : 0) - (left.definition.plan === "club" ? 1 : 0)
    ))[0] || null;
  }

  async function activateGooglePlayPurchase(purchase, productId, { platform = "android", deviceLabel = "" } = {}) {
    const purchaseToken = String(purchase?.purchaseToken || "");
    if (!purchaseToken) throw new Error("Google Play purchase token is missing");
    googlePlayLog("activating purchase", {
      productId: String(productId || ""),
      packageName: String(purchase?.packageName || config.googlePlayPackageName || ""),
      token: `${purchaseToken.slice(0, 8)}...(${purchaseToken.length})`,
    });
    try {
      const activated = await requestEntitlement("/store/google-play/activate", await signedEnvelope("google-play-activate", {
        packageName: String(purchase?.packageName || config.googlePlayPackageName || ""),
        productId: String(productId || ""),
        purchaseToken,
        platform: String(platform || "android"),
        deviceLabel: String(deviceLabel || "").slice(0, 80),
      }, { includePublicKey: true }));
      googlePlayLog("activation succeeded", { productId: String(productId || "") });
      return activated;
    } catch (error) {
      googlePlayLog("activation failed", {
        productId: String(productId || ""),
        status: error?.status || "",
        error: error?.message || String(error),
      });
      throw error;
    }
  }

  async function restoreGooglePlayEntitlement({ platform = "android", deviceLabel = "" } = {}) {
    if (!config.googlePlay) throw new Error("Google Play licensing is not enabled in this build");
    if (!Object.keys(config.googlePlayProducts).length) throw new Error("Google Play products are not configured");
    const restored = await googlePlayNativeRequest("restorePurchases");
    const selected = selectGooglePlayPurchase(restored.purchases || (restored.purchase ? [restored.purchase] : []));
    if (!selected) throw new Error("No active JB_Drill Google Play subscription was found");
    return activateGooglePlayPurchase(selected.purchase, selected.productId, { platform, deviceLabel });
  }

  async function tryAutoRestoreGooglePlay() {
    if (!config.googlePlay || !config.endpoint || entitlement.plan !== "free") return null;
    if (typeof window.JBDrillGooglePlayBilling?.restorePurchases !== "function") return null;
    try {
      const status = typeof window.JBDrillGooglePlayBilling.status === "function"
        ? JSON.parse(window.JBDrillGooglePlayBilling.status())
        : { available: true };
      if (status?.available === false) return null;
      return await restoreGooglePlayEntitlement({ platform: "android" });
    } catch (_error) {
      return null;
    }
  }

  async function restoreMicrosoftStoreEntitlement({ platform = "windows", deviceLabel = "" } = {}) {
    if (!config.microsoftStore) throw new Error("Microsoft Store licensing is not enabled in this build");
    if (typeof window.JBDrillStore?.createPurchaseId !== "function") {
      throw new Error("Microsoft Store is not available on this installation");
    }
    const installation = await getOrCreateIdentity();
    const ticket = await requestJson("/store/microsoft/ticket", await signedEnvelope(
      "microsoft-ticket",
      {},
      { includePublicKey: true },
    ));
    const proof = await window.JBDrillStore.createPurchaseId(ticket.serviceTicket, installation.deviceId);
    return requestEntitlement("/store/microsoft/activate", await signedEnvelope("microsoft-activate", {
      purchaseId: String(proof?.purchaseId || ""),
      platform: String(platform || "windows"),
      deviceLabel: String(deviceLabel || "").slice(0, 80),
    }, { includePublicKey: true }));
  }

  async function tryAutoRestoreMicrosoftStore() {
    if (!config.microsoftStore || !config.endpoint || entitlement.plan !== "free") return null;
    if (typeof window.JBDrillStore?.createPurchaseId !== "function") return null;
    try {
      const status = typeof window.JBDrillStore.status === "function"
        ? await window.JBDrillStore.status()
        : { available: true };
      if (status?.available === false) return null;
      return await restoreMicrosoftStoreEntitlement({ platform: "windows" });
    } catch (_error) {
      return null;
    }
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
    entitlement = stored || {
      plan: config.testMode ? config.initialPlan : "free",
      status: config.testMode && config.initialPlan !== "free" ? "active" : "free",
      source: config.testMode ? "test" : "none",
      deviceId: installation.deviceId,
    };
    emit();
    if (navigator.onLine === false) return api.snapshot();
    if (entitlement.licenseId && entitlement.source === "jb-license-service" && config.endpoint) {
      try {
        return await refreshCurrentEntitlement();
      } catch (_error) {
        // A valid cached lease remains usable when the service or network is unavailable.
      }
    }
    const restored = await tryAutoRestoreMicrosoftStore();
    if (restored) return restored;
    const googleRestored = await tryAutoRestoreGooglePlay();
    if (googleRestored) return googleRestored;
    return api.snapshot();
  }

  const api = {
    ready: null,
    config,
    snapshot() {
      return Object.freeze({
        entitlement: core.normalizeEntitlement(entitlement),
        capabilities: core.capabilities(entitlement),
        deviceId: identity?.deviceId || "",
        ready: Boolean(identity),
        testMode: config.testMode,
        serviceConfigured: Boolean(config.endpoint),
        connectionStatus: navigator.onLine === false ? "offline" : connectionStatus,
        microsoftStoreEnabled: config.microsoftStore,
        googlePlayEnabled: config.googlePlay,
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
    async microsoftStoreStatus() {
      if (!config.microsoftStore) return { available: false, configured: false };
      if (typeof window.JBDrillStore?.status !== "function") {
        return { available: false, configured: true };
      }
      return window.JBDrillStore.status();
    },
    microsoftStoreProducts() {
      return config.microsoftStoreProducts;
    },
    async googlePlayStatus() {
      if (!config.googlePlay) return { available: false, configured: false };
      if (typeof window.JBDrillGooglePlayBilling?.status !== "function") {
        return { available: false, configured: true };
      }
      try {
        return JSON.parse(window.JBDrillGooglePlayBilling.status());
      } catch (_error) {
        return { available: false, configured: true };
      }
    },
    googlePlayProducts() {
      return config.googlePlayProducts;
    },
    async purchaseGooglePlay(productKey, { platform = "android", deviceLabel = "" } = {}) {
      if (!config.googlePlay) throw new Error("Google Play licensing is not enabled in this build");
      const product = config.googlePlayProducts[String(productKey || "")];
      if (!product) throw new Error("The selected Google Play plan is not configured");
      googlePlayLog("purchase selected", {
        productKey: String(productKey || ""),
        productId: product.productId,
        basePlanId: product.basePlanId,
      });
      await googlePlayNativeRequest("queryProducts", JSON.stringify(googlePlayProductIds()));
      const installation = await getOrCreateIdentity();
      const result = await googlePlayNativeRequest(
        "purchase",
        product.productId,
        product.basePlanId,
        installation.deviceId,
      );
      const status = String(result?.status || "");
      if (status === "NotPurchased") throw new Error("The Google Play purchase was cancelled");
      if (status !== "Succeeded" && status !== "AlreadyPurchased") {
        throw new Error(result?.error || "Google Play could not complete the purchase");
      }
      const purchase = result.purchase || selectGooglePlayPurchase(result.purchases || [])?.purchase;
      googlePlayLog("purchase ready for activation", {
        productKey: String(productKey || ""),
        productId: product.productId,
        status,
        hasPurchase: Boolean(purchase),
      });
      return activateGooglePlayPurchase(purchase, product.productId, { platform, deviceLabel });
    },
    async restoreGooglePlay({ platform = "android", deviceLabel = "" } = {}) {
      return restoreGooglePlayEntitlement({ platform, deviceLabel });
    },
    async purchaseMicrosoftStore(productKey, { platform = "windows", deviceLabel = "" } = {}) {
      if (!config.microsoftStore) throw new Error("Microsoft Store licensing is not enabled in this build");
      if (typeof window.JBDrillStore?.purchase !== "function") {
        throw new Error("Microsoft Store purchases are not available on this installation");
      }
      const product = config.microsoftStoreProducts[String(productKey || "")];
      if (!product) throw new Error("The selected Microsoft Store plan is not configured");
      const purchase = await window.JBDrillStore.purchase(product.storeId);
      const status = String(purchase?.status || "");
      if (status === "NotPurchased") throw new Error("The Microsoft Store purchase was cancelled");
      if (status !== "Succeeded" && status !== "AlreadyPurchased") {
        const detail = purchase?.extendedError ? ` (${purchase.extendedError})` : "";
        throw new Error(`Microsoft Store could not complete the purchase${detail}`);
      }
      return api.restoreMicrosoftStore({ platform, deviceLabel });
    },
    async restoreMicrosoftStore({ platform = "windows", deviceLabel = "" } = {}) {
      return restoreMicrosoftStoreEntitlement({ platform, deviceLabel });
    },
    async refresh() {
      return refreshCurrentEntitlement();
    },
    async createPairingCode() {
      if (!entitlement.licenseId || entitlement.plan === "free") {
        throw new Error("Activate Personal or Pro before linking another device");
      }
      return requestJson("/pair/create", await signedEnvelope("pair-create", {
        licenseId: entitlement.licenseId,
      }));
    },
    async claimPairingCode({ pairingCode, platform = "unknown", deviceLabel = "" } = {}) {
      const envelope = await signedEnvelope("pair-claim", {
        pairingCode: String(pairingCode || ""),
        platform: String(platform || "unknown"),
        deviceLabel: String(deviceLabel || "").slice(0, 80),
      }, { includePublicKey: true });
      return requestEntitlement("/pair/claim", envelope);
    },
    async listDevices() {
      if (!entitlement.licenseId || entitlement.plan === "free") return {
        plan: "free",
        deviceLimit: 0,
        devices: [],
      };
      return requestJson("/devices/list", await signedEnvelope("devices-list", {
        licenseId: entitlement.licenseId,
      }));
    },
    async renameDevice(targetDeviceId, deviceLabel) {
      if (!entitlement.licenseId) throw new Error("This installation is not activated");
      return requestJson("/devices/rename", await signedEnvelope("device-rename", {
        licenseId: entitlement.licenseId,
        targetDeviceId: String(targetDeviceId || ""),
        deviceLabel: String(deviceLabel || "").slice(0, 80),
      }));
    },
    async deactivateDevice(targetDeviceId) {
      if (!entitlement.licenseId) throw new Error("This installation is not activated");
      return requestJson("/devices/deactivate", await signedEnvelope("device-deactivate", {
        licenseId: entitlement.licenseId,
        targetDeviceId: String(targetDeviceId || ""),
      }));
    },
  };

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "hidden") void api.ready.then(checkLicenseInBackground).catch(() => {});
  });
  window.addEventListener("online", () => { void api.ready.then(checkLicenseInBackground).catch(() => {}); });
  window.addEventListener("offline", () => { void api.ready.then(() => { emit(); scheduleLicenseChecks(); }).catch(() => {}); });
  api.ready = initialize().finally(scheduleLicenseChecks);
  window.JBDrillLicensing = Object.freeze(api);
}());
