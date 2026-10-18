// KyNotes reminder push. A push carries no data: show a fixed text, open KyNotes on a click.
// No caching, no network, no storage: this worker only shows the notification.
self.addEventListener("push", (event) => {
  event.waitUntil(self.registration.showNotification("KyNotes", { body: "A reminder is due", tag: "kynotes-reminder" }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
    const open = windows.find((client) => new URL(client.url).origin === self.location.origin);
    return open ? open.focus() : self.clients.openWindow("/#/");
  }));
});
