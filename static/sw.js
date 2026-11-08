/* UniFlow local demo Service Worker — display user-authorized push messages. */
self.addEventListener('push', (event) => {
  let message = {};
  try { message = event.data ? event.data.json() : {}; } catch (_) { message = {}; }
  const url = typeof message.url === 'string' && message.url.startsWith('/') && !message.url.startsWith('//') ? message.url : '/';
  event.waitUntil(self.registration.showNotification(message.title || 'UniFlow update', {
    body: message.body || 'Your booking status changed.',
    tag: `uniflow-${Date.now()}`,
    data: {url}
  }));
});
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = event.notification.data?.url || '/';
  event.waitUntil((async () => {
    const clientsList = await clients.matchAll({type: 'window', includeUncontrolled: true});
    const origin = self.location.origin;
    for (const client of clientsList) {
      if (client.url.startsWith(origin)) {
        await client.focus();
        if (client.navigate) await client.navigate(url);
        return;
      }
    }
    await clients.openWindow(url);
  })());
});
