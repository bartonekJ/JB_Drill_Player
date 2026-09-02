const CACHE_NAME = "jb-drill-player-v14";
const APP_SHELL = [
  "./",
  "./index.html",
  "./styles.css",
  "./player.css",
  "./app.js",
  "./licensing/config.js",
  "./licensing/core.js",
  "./licensing/runtime.js",
  "./manifest.webmanifest",
  "./icons/finesse-shapes.js",
  "./icons/JB_Logo.svg",
  "./icons/app-icon-192.png",
  "./icons/app-icon-512.png",
  "./icons/Puck.png",
  "./icons/Pylon_Ice.png",
  "./icons/Net.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(
    APP_SHELL.map((url) => new Request(url, { cache: "reload" }))
  )));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
    ))
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(fetch(event.request));
    return;
  }
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
