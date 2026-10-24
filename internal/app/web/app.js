'use strict';

const REFRESH_MS = 15000;
const RESULT_MS = 60000;
const NS_PER_MIN = 6e10;
const NEAR_NS = 5 * NS_PER_MIN;
const NBSP = ' ';
const COLUMNS = 4;
const ACTION_HEADER = { 'X-Parental-Control': '1' };

const $ = id => document.getElementById(id);
// location.origin never carries user:pass, which fetch rejects when the page URL does.
const api = path => new URL(path, location.origin);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

// Non-breaking spaces keep "1h 30m" and "15 s" on one line; "used / limit" may break after the slash.
const fmt = ns => {
  const m = Math.floor(ns / NS_PER_MIN);
  if (m === 0 && ns > 0) return '<1m';
  return m >= 60 ? `${Math.floor(m / 60)}h${NBSP}${m % 60}m` : `${m}m`;
};

// Short host label (first DNS label) works for any network's naming, not only Tailscale's.
const label = c => (c.name && c.name.split('.')[0]) || c.ip;
// IP disambiguates devices whose short names collide.
const fullLabel = c => (label(c) === c.ip ? c.ip : `${label(c)} (${c.ip})`);

let busy = false;
let paused = false;
let readOnly = false;
let inflight = null;
const results = new Map(); // ip -> { text, ok, at }, shown in that device's row for RESULT_MS
let stale = false;
let loaded = false;
let statusTimer;
let fillTimer;
let alertTimer;
const rendered = new Map(); // ip -> { sig, tr }, so unchanged rows are never rebuilt

const resultFor = ip => {
  const r = results.get(ip);
  return r && Date.now() - r.at < RESULT_MS ? r : null;
};

// Success goes to the polite status region; errors to the alert region so they interrupt.
// pending shows progress in a neutral colour, so it never reads as done.
function announce(text, ok, pending = false) {
  clearTimeout(statusTimer);
  clearTimeout(fillTimer);
  clearTimeout(alertTimer);
  $('msg').textContent = '';
  $('alert').textContent = '';
  delete $('alert').dataset.load;
  $('msg').classList.toggle('pending', pending);
  // Emptying first, then filling, makes a repeated message announce again.
  fillTimer = setTimeout(() => {
    $(ok ? 'msg' : 'alert').textContent = text;
    // Progress stays until its result replaces it; results and errors clear themselves.
    if (ok && text && !pending) statusTimer = setTimeout(() => { $('msg').textContent = ''; }, 8000);
    if (!ok && text) alertTimer = setTimeout(() => { $('alert').textContent = ''; }, RESULT_MS);
  }, 50);
}

function ask(question, okLabel, danger) {
  const dialog = $('confirm');
  $('confirm-text').textContent = question;
  $('confirm-ok').textContent = okLabel;
  $('confirm-ok').classList.toggle('danger', danger);
  dialog.returnValue = '';
  if (dialog.open) return Promise.resolve(false);
  return new Promise(resolve => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'ok'), { once: true });
    try {
      dialog.showModal();
    } catch (err) {
      console.error(err);
      resolve(false);
    }
  });
}

function deviceStatus(c, limit) {
  if (c.blocked) return ['Blocked', 'blocked', 'until midnight or until you unblock'];
  if (!c.limited) return ['No limit', 'free', ''];
  const left = limit - c.time_watched_today;
  if (left <= 0) return ['Over limit', 'blocked', 'will be blocked within a minute'];
  if (left <= NEAR_NS) return ['Almost out', 'near', `${fmt(left)}${NBSP}left`];
  return ['Within limit', 'active', `${fmt(left)}${NBSP}left`];
}

function question(path, c) {
  const name = fullLabel(c);
  if (path === '/block') {
    return [`Block the time-limited sites on ${name} now? They stay blocked until midnight or until you unblock.`, 'Block'];
  }
  return c.blocked
    ? [`Unblock ${name} and reset today’s time to 0?`, 'Unblock']
    : [`Reset today’s time on ${name} to 0?`, 'Reset'];
}

async function act(path, c, verb, key) {
  if (busy) return;
  const [text, okLabel] = question(path, c);
  if (!await ask(text, okLabel, path === '/block')) return;
  const name = fullLabel(c);
  setBusy(true);
  announce(`${verb} ${name}…`, true, true);
  try {
    const res = await fetch(api(`${path}?ip=${encodeURIComponent(c.ip)}`), {
      method: 'POST', headers: ACTION_HEADER, signal: AbortSignal.timeout(20000),
    });
    const reply = (await res.text()).trim()
      || (res.ok ? `Done: ${name}.` : `Something went wrong with ${name}. Try again in a minute.`);
    results.set(c.ip, { text: reply, ok: res.ok, at: Date.now() });
    announce(reply, res.ok);
  } catch (err) {
    console.error(err);
    const reply = err.name === 'TimeoutError'
      ? 'The server is taking too long. The change may still go through; the list will show it.'
      : 'Could not reach the server. Check your connection and try again.';
    results.set(c.ip, { text: reply, ok: false, at: Date.now() });
    announce(reply, false);
  } finally {
    setBusy(false);
    await load({ restoreKey: key });
  }
}

// aria-disabled keeps buttons focusable, so a keyboard user's place survives the request.
function setBusy(value) {
  busy = value;
  syncDisabled();
}

function syncDisabled() {
  $('rows').querySelectorAll('button').forEach(b => b.setAttribute('aria-disabled', String(busy || stale)));
}

function button(text, c, action, opts = {}) {
  const key = `${action}:${c.ip}`;
  const b = el('button', opts.danger ? 'danger' : '', text);
  b.type = 'button';
  b.setAttribute('aria-label', `${opts.aria || text}, ${fullLabel(c)}`);
  b.setAttribute('aria-disabled', String(busy || stale));
  b.dataset.key = key;
  b.addEventListener('click', () => {
    if (b.getAttribute('aria-disabled') !== 'true') act(`/${action}`, c, opts.verb, key);
    else if (stale) announce('The list is out of date. Buttons work again once it updates.', false);
  });
  return b;
}

function usedCell(c, limit) {
  const td = el('td', 'num', c.limited ? `${fmt(c.time_watched_today)}${NBSP}/ ${fmt(limit)}` : fmt(c.time_watched_today));
  if (!c.limited) return td;
  // A 0 limit means no allowance at all, so the bar reads as full.
  const pct = limit ? Math.min(100, Math.round(100 * c.time_watched_today / limit)) : 100;
  const left = limit - c.time_watched_today;
  const bar = el('div', `bar${left <= 0 ? ' bar-over' : left <= NEAR_NS ? ' bar-near' : ''}`);
  bar.setAttribute('role', 'progressbar');
  bar.setAttribute('aria-valuemin', '0');
  bar.setAttribute('aria-valuemax', '100');
  bar.setAttribute('aria-valuenow', String(pct));
  bar.setAttribute('aria-label', `${fullLabel(c)}: ${pct}% of daily limit used`);
  const fill = el('span');
  fill.style.width = `${pct}%`;
  bar.append(fill);
  td.append(bar);
  return td;
}

function statusCell(c, limit) {
  const [text, cls, hint] = deviceStatus(c, limit);
  const td = el('td');
  td.append(el('span', `tag tag-${cls}`, text));
  if (hint) td.append(el('span', 'hint', hint));
  const result = resultFor(c.ip);
  if (result) td.append(el('span', `hint ${result.ok ? 'ok' : 'err'}`, result.text));
  return td;
}

function actionsCell(c) {
  const td = el('td');
  if (readOnly) return td;
  const wrap = el('div', 'actions');
  if (c.blocked) {
    wrap.append(button('Unblock', c, 'reset', { verb: 'Unblocking', aria: 'Unblock and reset today’s time' }));
  } else {
    wrap.append(button('Block', c, 'block', { danger: true, verb: 'Blocking' }));
    // Resetting time means nothing for a device without a limit.
    if (c.limited) wrap.append(button('Reset', c, 'reset', { verb: 'Resetting', aria: 'Reset today’s time' }));
  }
  td.append(wrap);
  return td;
}

function row(c, limit) {
  const tr = el('tr');
  tr.dataset.ip = c.ip;
  const name = el('th');
  name.scope = 'row';
  name.append(label(c));
  if (label(c) !== c.ip) name.append(el('div', 'ip', c.ip));
  tr.append(name, usedCell(c, limit), statusCell(c, limit), actionsCell(c));
  return tr;
}

function messageRow(text) {
  const tr = el('tr');
  const td = el('td', '', text);
  td.colSpan = COLUMNS;
  tr.append(td);
  return tr;
}

// Reuse unchanged rows and swap only changed ones, so screen-reader position,
// focus and an in-progress click survive the periodic refresh.
function renderRows(rows, clients, limit) {
  const trs = clients.map(c => {
    const sig = JSON.stringify([c, limit, readOnly, resultFor(c.ip)]);
    const prev = rendered.get(c.ip);
    if (prev && prev.sig === sig) return prev.tr;
    const tr = row(c, limit);
    rendered.set(c.ip, { sig, tr });
    return tr;
  });
  const current = [...rows.children];
  const sameOrder = current.length === trs.length && current.every((tr, i) => tr.dataset.ip === trs[i].dataset.ip);
  if (sameOrder) current.forEach((tr, i) => { if (tr !== trs[i]) tr.replaceWith(trs[i]); });
  else rows.replaceChildren(...trs);
  const keep = new Set(clients.map(c => c.ip));
  [...rendered.keys()].forEach(ip => { if (!keep.has(ip)) rendered.delete(ip); });
}

function restoreFocus(rows, key) {
  if (!key || rows.contains(document.activeElement)) return;
  const ip = key.slice(key.indexOf(':') + 1);
  // The clicked button may be gone (Block becomes Unblock), so fall back to the row's first button.
  const target = rows.querySelector(`[data-key="${CSS.escape(key)}"]`)
    || rows.querySelector(`tr[data-ip="${CSS.escape(ip)}"] button`);
  target?.focus();
}

async function refresh(restoreKey) {
  const rows = $('rows');
  const focusKey = restoreKey || document.activeElement?.dataset?.key;
  try {
    const res = await fetch(api('/stats'), { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`status ${res.status}`);
    const s = await res.json();
    const limit = Number(s.daily_limit_ns) || 0;
    readOnly = Boolean(s.read_only);
    $('readonly').hidden = !readOnly;
    $('limit').textContent = fmt(limit);
    // Stable order (limited first, then by name) so rows never move under the pointer.
    const clients = (s.clients || []).sort((a, b) => (b.limited - a.limited) || label(a).localeCompare(label(b)));
    stale = false;
    loaded = true;
    $('stalenote').hidden = true;
    rows.classList.remove('stale');
    if (clients.length) renderRows(rows, clients, limit);
    else {
      rendered.clear();
      rows.replaceChildren(messageRow('No devices yet. A device appears here after it first opens a time-limited site.'));
    }
    restoreFocus(rows, focusKey);
    $('updated').textContent = `updated ${new Date().toLocaleTimeString()}`;
    // Clear only the load error, never an action result the user has not read yet.
    if ($('alert').dataset.load) { $('alert').textContent = ''; delete $('alert').dataset.load; }
  } catch (err) {
    console.error(err);
    if (!$('alert').textContent) {
      $('alert').textContent = 'Could not load devices. Retrying automatically.';
      $('alert').dataset.load = '1';
    }
    // Out-of-date rows must not offer actions on state that may have changed.
    if (rows.querySelector('tr[data-ip]')) {
      stale = true;
      $('stalenote').hidden = false;
      rows.classList.add('stale');
      syncDisabled();
      rendered.clear();
    } else if (!loaded) rows.replaceChildren(messageRow('Devices will appear once the server answers.'));
  }
}

async function load({ restoreKey, poll } = {}) {
  // A refresh behind the open confirm box would detach the button focus returns to.
  if (poll && (paused || busy || document.hidden || inflight || $('confirm').open)) return;
  while (inflight) await inflight;
  inflight = refresh(restoreKey);
  try { await inflight; } finally { inflight = null; }
}

function updateEvery() {
  $('every').textContent = paused ? 'updates paused' : `updates every ${REFRESH_MS / 1000}${NBSP}s`;
  $('pause').textContent = paused ? 'Resume updates' : 'Pause updates';
}

$('pause').addEventListener('click', () => {
  paused = !paused;
  updateEvery();
  if (!paused) load();
});
['confirm-ok', 'confirm-cancel'].forEach(id => $(id).addEventListener('click', e => $('confirm').close(e.currentTarget.value)));
updateEvery();
document.addEventListener('visibilitychange', () => load({ poll: true }));
load();
setInterval(() => load({ poll: true }), REFRESH_MS);
