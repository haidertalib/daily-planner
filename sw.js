self.addEventListener("push", event => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || "Daily Planner";
  const options = {
    body:    data.body  || "You have tasks waiting.",
    icon:    "/icon-192.png",
    badge:   "/icon-192.png",
    tag:     "planner-push",
    data:    data.url   || "/",
    vibrate: [200, 100, 200]
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", event => {
  event.notification.close();
  const url = event.notification.data || "/";
  event.waitUntil(clients.openWindow(url));
});

self.addEventListener("install",  () => self.skipWaiting());
self.addEventListener("activate", () => clients.claim());
