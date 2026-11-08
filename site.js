/* UniFlow notifications: persistent in-site inbox, Web Push and opt-in booking chime. */
(() => {
  'use strict';
  const toggle = document.getElementById('notifications-toggle');
  if (!toggle) return;

  const panel = document.getElementById('notifications-panel');
  const list = document.getElementById('notifications-list');
  const count = document.getElementById('notification-count');
  const pushButton = document.getElementById('enable-push');
  const soundButton = document.getElementById('toggle-sound');
  const testPushButton = document.getElementById('test-push');
  const hint = document.getElementById('notifications-hint');
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const pushMeta = document.querySelector('meta[name="push-key"]');
  const csrf = csrfMeta ? csrfMeta.content : '';
  const publicKey = pushMeta ? pushMeta.content : '';

  let highId = 0;
  let loaded = false;
  let soundEnabled = false;
  try { soundEnabled = localStorage.getItem('uniflow_sound') === 'on'; } catch (_) { /* Storage may be blocked. */ }
  let audioContext = null;
  let slotSubmitReplay = false;
  let slotSubmitPending = false;

  const setHint = (text) => { if (hint) hint.textContent = text; };
  function updateSound() {
    soundButton.textContent = `Sound: ${soundEnabled ? 'On' : 'Off'}`;
    soundButton.setAttribute('aria-pressed', String(soundEnabled));
  }

  async function playChime() {
    if (!soundEnabled) return false;
    try {
      // Web Audio avoids depending on an external media file and starts from the
      // user's click/slot-submit gesture, so navigation cannot cut off an <audio> load.
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioContextClass) throw new Error('Web Audio is not supported by this browser.');
      if (!audioContext || audioContext.state === 'closed') audioContext = new AudioContextClass();
      if (audioContext.state === 'suspended') await audioContext.resume();

      const start = audioContext.currentTime + 0.015;
      const master = audioContext.createGain();
      master.gain.setValueAtTime(0.0001, start);
      master.gain.exponentialRampToValueAtTime(0.22, start + 0.025);
      master.gain.setValueAtTime(0.22, start + 0.22);
      master.gain.exponentialRampToValueAtTime(0.0001, start + 0.48);
      master.connect(audioContext.destination);

      const first = audioContext.createOscillator();
      first.type = 'sine';
      first.frequency.setValueAtTime(880, start);
      first.connect(master);
      first.start(start);
      first.stop(start + 0.20);

      const second = audioContext.createOscillator();
      second.type = 'sine';
      second.frequency.setValueAtTime(1174.66, start + 0.16);
      second.connect(master);
      second.start(start + 0.16);
      second.stop(start + 0.49);
      return true;
    } catch (error) {
      setHint('Sound is enabled, but playback failed. Check the browser tab/site sound setting and device volume.');
      return false;
    }
  }

  updateSound();
  soundButton.addEventListener('click', async () => {
    soundEnabled = !soundEnabled;
    try { localStorage.setItem('uniflow_sound', soundEnabled ? 'on' : 'off'); } catch (_) { /* Keep this-page setting. */ }
    updateSound();
    if (soundEnabled) {
      const played = await playChime();
      if (played) setHint('Sound is on. You should have heard a short test chime. Booking and update sounds are enabled.');
    } else {
      setHint('Sound is off. In-site and browser push notifications can still work.');
    }
  });

  // Keep the document alive long enough for the booking chime to finish before redirect.
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches('.slot-form') || !soundEnabled || slotSubmitReplay) return;
    event.preventDefault();
    if (slotSubmitPending) return;
    slotSubmitPending = true;
    const submitter = event.submitter;
    playChime().then((played) => {
      window.setTimeout(() => {
        slotSubmitReplay = true;
        try {
          if (submitter && typeof form.requestSubmit === 'function') form.requestSubmit(submitter);
          else form.requestSubmit();
        } finally {
          window.setTimeout(() => { slotSubmitReplay = false; slotSubmitPending = false; }, 0);
        }
      }, played ? 520 : 0);
    });
  }, true);

  function safeLink(url) {
    return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') ? url : '/my-reservations';
  }
  function render(items) {
    list.replaceChildren();
    if (!items.length) {
      const item = document.createElement('p');
      item.className = 'notification-empty';
      item.textContent = 'No notifications yet. Booking updates will appear here.';
      list.append(item);
      return;
    }
    items.forEach((item) => {
      const link = document.createElement('a');
      link.href = safeLink(item.url);
      link.className = `notification-item${item.is_read ? '' : ' is-unread'}`;
      const title = document.createElement('strong'); title.textContent = item.title;
      const desc = document.createElement('small'); desc.textContent = item.body;
      const time = document.createElement('time'); time.textContent = `${item.created_at} (server time)`;
      link.append(title, desc, time);
      list.append(link);
    });
  }
  async function fetchUpdates() {
    try {
      const response = await fetch('/api/notifications', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) return;
      const result = await response.json();
      const latest = result.notifications.length ? result.notifications[0].notification_id : 0;
      if (loaded && latest > highId && result.notifications.some(n => !n.is_read && n.notification_id > highId)) playChime();
      highId = Math.max(highId, latest);
      loaded = true;
      count.hidden = result.unread === 0;
      count.textContent = String(Math.min(99, result.unread)) + (result.unread > 99 ? '+' : '');
      render(result.notifications);
    } catch (_) { setHint('Could not refresh notifications. Check the connection.'); }
  }
  async function markRead() {
    try {
      const response = await fetch('/api/notifications/read', {
        method: 'POST', credentials: 'same-origin', headers: {'X-CSRF-Token': csrf}
      });
      if (response.ok) await fetchUpdates();
    } catch (_) { /* Retry when opened next time. */ }
  }
  toggle.addEventListener('click', () => {
    panel.hidden = !panel.hidden;
    toggle.setAttribute('aria-expanded', String(!panel.hidden));
    if (!panel.hidden) { fetchUpdates(); markRead(); }
  });
  document.addEventListener('click', (event) => {
    if (!panel.hidden && !event.target.closest('.notifications-wrap')) {
      panel.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !panel.hidden) {
      panel.hidden = true;
      toggle.focus();
      toggle.setAttribute('aria-expanded', 'false');
    }
  });

  const decodeKey = (base64url) => {
    const padding = '='.repeat((4 - base64url.length % 4) % 4);
    const raw = atob((base64url + padding).replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  };
  function updatePushButton(enabled) {
    pushButton.textContent = enabled ? 'Push enabled ✓' : 'Enable push';
    pushButton.setAttribute('aria-pressed', String(enabled));
    pushButton.dataset.enabled = enabled ? 'true' : 'false';
    if (testPushButton) testPushButton.disabled = !enabled;
  }
  function pushSupported() {
    return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  }
  async function getPushRegistration() {
    await navigator.serviceWorker.register('/sw.js', {scope: '/'});
    return navigator.serviceWorker.ready;
  }
  async function saveSubscription(subscription) {
    const response = await fetch('/api/push/subscribe', {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
      body: JSON.stringify(subscription.toJSON())
    });
    if (!response.ok) {
      let detail = `server returned ${response.status}`;
      try { const body = await response.json(); if (body.description) detail = body.description; } catch (_) { /* Use status. */ }
      throw new Error(detail);
    }
  }
  function subscriptionUsesCurrentKey(subscription) {
    try {
      const configured = subscription?.options?.applicationServerKey;
      if (!configured || !publicKey) return false;
      const actual = new Uint8Array(configured);
      const expected = decodeKey(publicKey);
      return actual.length === expected.length && actual.every((byte, i) => byte === expected[i]);
    } catch (_) { return false; }
  }
  async function removeServerSubscription(subscription) {
    if (!subscription?.endpoint) return;
    try {
      await fetch('/api/push/unsubscribe', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({endpoint: subscription.endpoint})
      });
    } catch (_) { /* The browser subscription is still removed locally below. */ }
  }
  async function getCurrentSubscription(registration) {
    let subscription = await registration.pushManager.getSubscription();
    if (subscription && !subscriptionUsesCurrentKey(subscription)) {
      // A VAPID private key may have been regenerated when the project ZIP was
      // extracted into a new folder. Browser subscriptions are bound to the old key.
      await removeServerSubscription(subscription);
      await subscription.unsubscribe();
      subscription = null;
    }
    if (!subscription) {
      if (!publicKey) throw new Error('The server did not provide a VAPID public key.');
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true, applicationServerKey: decodeKey(publicKey)
      });
    }
    await saveSubscription(subscription);
    return subscription;
  }

  // Browser subscriptions survive page navigation. Restore the UI state and sync
  // the existing endpoint to this signed-in user's SQLite account on every page.
  async function restorePushState() {
    updatePushButton(false);
    if (!pushSupported()) {
      pushButton.disabled = true;
      pushButton.textContent = 'Push unavailable';
      setHint('This browser does not support Web Push. In-site notifications still work.');
      return;
    }
    if (Notification.permission !== 'granted') {
      if (Notification.permission === 'denied') setHint('Notifications are blocked in browser settings. Allow them there to use Push.');
      return;
    }
    try {
      const registration = await getPushRegistration();
      const subscription = await registration.pushManager.getSubscription();
      if (!subscription) {
        setHint('Browser permission is allowed, but Push is not subscribed on this browser yet. Click Enable push to subscribe.');
        return;
      }
      if (!subscriptionUsesCurrentKey(subscription)) {
        updatePushButton(false);
        setHint('This browser has an old Push key from a previous UniFlow folder. Click Enable push once to renew its subscription.');
        return;
      }
      await saveSubscription(subscription);
      updatePushButton(true);
      setHint('Push is enabled for this browser and signed-in account.');
    } catch (error) {
      setHint(`Saved browser permission found, but Push could not be synced: ${error.message}`);
    }
  }

  pushButton.addEventListener('click', async () => {
    if (!pushSupported()) {
      setHint('This browser does not support Web Push. In-site notifications still work.');
      return;
    }
    if (!window.isSecureContext) {
      setHint('Push requires HTTPS or localhost (127.0.0.1).');
      return;
    }
    try {
      if (Notification.permission === 'denied') {
        setHint('Notifications are blocked in your browser settings.');
        return;
      }
      const permission = Notification.permission === 'granted'
        ? 'granted' : await Notification.requestPermission();
      if (permission !== 'granted') {
        setHint('You can enable Push later in your browser settings.');
        return;
      }
      pushButton.disabled = true;
      const registration = await getPushRegistration();
      const subscription = await getCurrentSubscription(registration);
      updatePushButton(true);
      setHint('Push enabled and saved with the current UniFlow key. It will remain enabled between pages.');
    } catch (error) {
      updatePushButton(false);
      setHint(`Push could not be enabled: ${error.message}`);
    } finally { pushButton.disabled = false; }
  });


  if (testPushButton) {
    testPushButton.addEventListener('click', async () => {
      testPushButton.disabled = true;
      setHint('Sending a test push notification…');
      try {
        const response = await fetch('/api/push/test', {
          method: 'POST', credentials: 'same-origin',
          headers: {'X-CSRF-Token': csrf}
        });
        const result = await response.json();
        if (!response.ok) {
          if (result.renew) {
            const registration = await getPushRegistration();
            const subscription = await registration.pushManager.getSubscription();
            if (subscription) {
              await removeServerSubscription(subscription);
              await subscription.unsubscribe();
            }
            updatePushButton(false);
            const providerDetail = result.detail ? ` Provider response: ${result.detail}` : '';
            throw new Error(`${result.error || 'Push subscription rejected.'} Click Enable push to create a fresh subscription.${providerDetail}`);
          }
          throw new Error(result.error || `server returned ${response.status}`);
        }
        setHint('Test push accepted by the push service. Check browser and Windows notifications.');
      } catch (error) {
        setHint(`Test push failed: ${error.message}`);
      } finally {
        testPushButton.disabled = pushButton.dataset.enabled !== 'true';
      }
    });
  }

  fetchUpdates();
  restorePushState();
  window.setInterval(fetchUpdates, 20000);
})();
