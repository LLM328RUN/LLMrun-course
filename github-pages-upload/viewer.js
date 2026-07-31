(function () {
  'use strict';

  const SESSION_KEY = 'verl-encrypted-session-v1';
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const elements = {
    loginView: document.getElementById('loginView'), courseView: document.getElementById('courseView'),
    form: document.getElementById('loginForm'), username: document.getElementById('username'),
    password: document.getElementById('password'), button: document.getElementById('loginButton'),
    message: document.getElementById('loginMessage'), frame: document.getElementById('lessonFrame'),
    loading: document.getElementById('loading'), watermarks: document.getElementById('watermarks'),
    identity: document.getElementById('identityName'), logout: document.getElementById('logoutButton'),
    navToggle: document.getElementById('navToggle'), navPanel: document.getElementById('navPanel'),
    navItems: document.getElementById('navItems'), progress: document.getElementById('progress'),
    previous: document.getElementById('previousPage'), next: document.getElementById('nextPage')
  };
  let manifest;
  let session;
  let currentPageId;
  let watermarkTimer;

  const bytesFromBase64 = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
  const base64FromBytes = value => btoa(String.fromCharCode(...new Uint8Array(value)));
  const normalizeUsername = value => value.trim().toLocaleLowerCase();
  const stop = event => { event.preventDefault(); event.stopPropagation(); };

  async function sha256(value) {
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))))
      .map(byte => byte.toString(16).padStart(2, '0')).join('');
  }

  async function passwordKey(password, salt, iterations) {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: bytesFromBase64(salt), iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptBytes(key, iv, encrypted) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted);
  }

  async function authenticate(username, password) {
    const lookup = await sha256(normalizeUsername(username));
    const account = manifest.users.find(user => user.lookup === lookup);
    if (!account) throw new Error('INVALID_CREDENTIALS');
    const key = await passwordKey(password, account.salt, account.iterations);
    const clear = await decryptBytes(key, bytesFromBase64(account.iv), bytesFromBase64(account.payload));
    return JSON.parse(decoder.decode(clear));
  }

  async function importContentKey(base64) {
    return crypto.subtle.importKey('raw', bytesFromBase64(base64), { name: 'AES-GCM' }, false, ['decrypt']);
  }

  function saveSession(identity) {
    const value = {
      ...identity,
      buildId: manifest.buildId,
      sessionId: crypto.getRandomValues(new Uint32Array(2)).join('-'),
      expiresAt: Date.now() + (Number(manifest.sessionHours) || 12) * 3600000
    };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(value));
    return value;
  }

  function restoreSession() {
    try {
      const value = JSON.parse(sessionStorage.getItem(SESSION_KEY));
      if (!value || value.buildId !== manifest.buildId || value.expiresAt <= Date.now() || !value.contentKey) return null;
      return value;
    } catch (_) {
      return null;
    }
  }

  function pageFromHash() {
    const id = decodeURIComponent(location.hash.replace(/^#/, ''));
    return manifest.pages.some(page => page.id === id) ? id : manifest.initialPage;
  }

  function updateWatermarks() {
    const stamp = new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short', hour12: false }).format(new Date());
    const text = `${session.username} · ${session.displayName} · ${stamp} · SID ${session.sessionId}`;
    elements.watermarks.replaceChildren(...Array.from({ length: 48 }, () => {
      const span = document.createElement('span'); span.textContent = text; return span;
    }));
  }

  function renderNavigation() {
    elements.navItems.replaceChildren(...manifest.pages.map(page => {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'nav-item'; button.dataset.page = page.id;
      const short = document.createElement('b'); short.textContent = page.short;
      const label = document.createElement('span'); label.textContent = page.label;
      button.append(short, label);
      button.addEventListener('click', () => { location.hash = page.id; elements.navPanel.hidden = true; elements.navToggle.setAttribute('aria-expanded', 'false'); });
      return button;
    }));
  }

  function updateNavigation(pageId) {
    const index = manifest.pages.findIndex(page => page.id === pageId);
    elements.progress.textContent = `${index + 1} / ${manifest.pages.length}`;
    elements.previous.disabled = index <= 0;
    elements.next.disabled = index >= manifest.pages.length - 1;
    for (const button of elements.navItems.querySelectorAll('[data-page]')) button.classList.toggle('active', button.dataset.page === pageId);
  }

  async function loadPage(pageId) {
    if (!session || pageId === currentPageId) return;
    const page = manifest.pages.find(item => item.id === pageId) || manifest.pages[0];
    currentPageId = page.id; elements.loading.hidden = false; updateNavigation(page.id);
    try {
      const response = await fetch(page.file, { cache: 'no-store' });
      if (!response.ok) throw new Error(`课件请求失败：${response.status}`);
      const packet = new Uint8Array(await response.arrayBuffer());
      const key = await importContentKey(session.contentKey);
      const clear = await decryptBytes(key, packet.slice(0, 12), packet.slice(12));
      const frameDocument = elements.frame.contentWindow.document;
      frameDocument.open();
      frameDocument.write(decoder.decode(clear));
      frameDocument.close();
      document.title = `${page.short} · ${page.label}｜${manifest.title}`;
    } catch (error) {
      console.error(error); sessionStorage.removeItem(SESSION_KEY); alert('课件解密失败，请重新登录。'); location.reload();
    } finally {
      elements.loading.hidden = true;
    }
  }

  function enterCourse(identity) {
    session = identity; elements.identity.textContent = identity.username;
    elements.form.reset();
    elements.loginView.hidden = true; elements.courseView.hidden = false;
    renderNavigation(); updateWatermarks(); clearInterval(watermarkTimer); watermarkTimer = setInterval(updateWatermarks, 60000);
    const pageId = pageFromHash();
    if (location.hash !== `#${pageId}`) history.replaceState(null, '', `#${pageId}`);
    loadPage(pageId);
  }

  async function start() {
    try {
      const response = await fetch('./course-manifest.json', { cache: 'no-store' });
      if (!response.ok) throw new Error('课程配置加载失败');
      manifest = await response.json();
      const restored = restoreSession();
      if (restored) enterCourse(restored);
    } catch (error) {
      elements.message.textContent = '课程配置加载失败，请联系课程管理员';
      elements.button.disabled = true;
      console.error(error);
    }
  }

  elements.form.addEventListener('submit', async event => {
    event.preventDefault(); elements.message.textContent = ''; elements.button.disabled = true; elements.button.textContent = '正在验证并解密…';
    try {
      const identity = await authenticate(elements.username.value, elements.password.value);
      enterCourse(saveSession(identity));
    } catch (_) {
      elements.message.textContent = '用户名或密码不正确'; elements.password.value = ''; elements.password.focus();
    } finally {
      elements.button.disabled = false; elements.button.textContent = '解密并进入课程';
    }
  });
  elements.logout.addEventListener('click', () => { sessionStorage.removeItem(SESSION_KEY); location.hash = ''; location.reload(); });
  elements.navToggle.addEventListener('click', event => { event.stopPropagation(); elements.navPanel.hidden = !elements.navPanel.hidden; elements.navToggle.setAttribute('aria-expanded', String(!elements.navPanel.hidden)); });
  elements.previous.addEventListener('click', () => { const index = manifest.pages.findIndex(page => page.id === currentPageId); if (index > 0) location.hash = manifest.pages[index - 1].id; });
  elements.next.addEventListener('click', () => { const index = manifest.pages.findIndex(page => page.id === currentPageId); if (index < manifest.pages.length - 1) location.hash = manifest.pages[index + 1].id; });
  addEventListener('hashchange', () => loadPage(pageFromHash()));
  addEventListener('message', event => {
    if (event.source !== elements.frame.contentWindow || event.data?.type !== 'course-library:navigate') return;
    const pageId = String(event.data.pageId || '');
    if (!manifest.pages.some(page => page.id === pageId) || pageId === currentPageId) return;
    location.hash = pageId;
  });
  document.addEventListener('click', event => { if (!elements.navPanel.hidden && !event.target.closest('.course-nav')) { elements.navPanel.hidden = true; elements.navToggle.setAttribute('aria-expanded', 'false'); } });
  document.addEventListener('contextmenu', stop, { capture: true });
  document.addEventListener('copy', stop, { capture: true });
  document.addEventListener('dragstart', stop, { capture: true });
  document.addEventListener('keydown', event => { const key = event.key.toLowerCase(); if (event.key === 'F12' || ((event.ctrlKey || event.metaKey) && ['s', 'u', 'p'].includes(key))) stop(event); }, { capture: true });
  start();
})();
