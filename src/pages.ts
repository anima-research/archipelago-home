/**
 * The human-facing pages: sign-in chooser, account self-service, setup link.
 * Vanilla JS, served under a nonce CSP (http.ts securePage); tokens live in
 * page memory only, never storage.
 */
import { esc } from './http.js';

const CSS = `
:root{color-scheme:light dark;--bg:#fafafa;--fg:#1c1c1e;--dim:#66666b;--line:#d6d6db;--field:#fff;--card:#fff;
--accent:#2f5bd3;--on-accent:#fff;--err:#b3261e;--ok:#1e7a34;--discord:#5865f2}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#e4e4e4;--dim:#909096;--line:#2f2f33;--field:#18181a;--card:#161618;
--accent:#5b84f0;--on-accent:#fff;--err:#ff8a80;--ok:#7fd88f}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:30rem;margin:8vh auto 4rem;padding:0 16px}
h1{font-size:1.5rem;line-height:1.25;margin:0 0 .25rem}
h2{font-size:1.05rem;margin:0 0 .35rem}
p{margin:.5rem 0}
a{color:var(--accent)}
.dim{color:var(--dim)}.small{font-size:.875rem}.err{color:var(--err)}.ok{color:var(--ok)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}
label{display:block;font-size:.875rem;color:var(--dim);margin:.75rem 0 .25rem}
input{display:block;width:100%;font:inherit;font-size:16px;color:var(--fg);background:var(--field);border:1px solid var(--line);
border-radius:8px;padding:.55rem .7rem}
input:focus-visible,.btn:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn{display:inline-flex;align-items:center;justify-content:center;font:inherit;font-weight:500;text-decoration:none;color:var(--fg);
background:transparent;border:1px solid var(--line);border-radius:8px;padding:.5rem 1rem;min-height:44px;cursor:pointer}
.btn.block{display:flex;width:100%;margin-top:.75rem}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn.discord{background:var(--discord);border-color:var(--discord);color:#fff}
.btn.danger{color:var(--err)}
.btn.sm{min-height:36px;padding:.3rem .75rem;font-size:.875rem}
.btn:disabled{opacity:.55;cursor:default}
.row{display:flex;gap:.5rem;align-items:flex-end;flex-wrap:wrap}.row>input{flex:1;min-width:10rem}
.or{display:flex;align-items:center;gap:.75rem;color:var(--dim);font-size:.875rem;margin:1rem 0}
.or::before,.or::after{content:"";flex:1;border-top:1px solid var(--line)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;word-break:break-all}
code.key{word-break:normal;font-size:1rem;letter-spacing:.02em}
ul.list{list-style:none;padding:0;margin:.5rem 0}
ul.list li{display:flex;justify-content:space-between;align-items:center;gap:.75rem;padding:.5rem 0;border-top:1px solid var(--line)}
ul.list li:first-child{border-top:0}
.codes{display:grid;grid-template-columns:repeat(2,1fr);gap:.25rem 1rem;padding:.75rem;border:1px dashed var(--line);border-radius:8px;margin:.5rem 0}
.qr{display:flex;justify-content:center;margin:.75rem 0}.qr svg{max-width:100%;height:auto;border-radius:6px}
#msg:empty,#err:empty{display:none}
`;

/** Client helpers every page shares: base64url ⇄ ArrayBuffer, JSON POST, HTML escape. */
const JS_COMMON = `
const $ = (id) => document.getElementById(id);
const h = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const dec = (s) => { s = s.replace(/-/g,'+').replace(/_/g,'/'); s += '='.repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer; };
async function post(path, body, headers) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json', ...(headers || {}) }, body: JSON.stringify(body || {}) });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}
const passkeysSupported = () => typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
function credJSON(c) {
  const r = c.response, out = { id: c.id, type: c.type, response: { clientDataJSON: enc(r.clientDataJSON) } };
  if (r.attestationObject) out.response.attestationObject = enc(r.attestationObject);
  if (r.authenticatorData) out.response.authenticatorData = enc(r.authenticatorData);
  if (r.signature) out.response.signature = enc(r.signature);
  if (r.userHandle) out.response.userHandle = enc(r.userHandle);
  return out;
}
function webauthnError(e) {
  if (e && e.name === 'NotAllowedError') return 'Cancelled, or no passkey for this site on this device.';
  if (e && e.name === 'InvalidStateError') return 'This device already has a passkey for this account.';
  return (e && e.message) || 'Passkey request failed.';
}
`;

/** JSON safe to inline in a <script>. */
function scriptJson(v: unknown): string {
  return JSON.stringify(v)
    .replace(/</g, '\\u003c')
    .split(String.fromCharCode(0x2028)).join('\\u2028')
    .split(String.fromCharCode(0x2029)).join('\\u2029');
}

function shell(title: string, nonce: string, body: string, script: string): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style>
<main>${body}</main>
<script nonce="${nonce}">${JS_COMMON}${script}</script></html>`;
}

const AUDIENCE_LABEL: Record<string, string> = { account: 'your sign-in settings', console: 'the agent-invite console' };

// ── /login ──

export function loginPage(o: { iss: string; audience: string; state: string; discord: boolean; google: boolean; nonce: string }): string {
  const target = AUDIENCE_LABEL[o.audience] ?? o.audience;
  const body = `
<h1>Sign in</h1>
<p class="dim">to continue to <b>${esc(target)}</b> · ${esc(o.iss)}</p>
<p id="err" class="err" role="alert"></p>
<section id="step1">
  ${o.discord ? `<a class="btn discord block" href="/login/discord?state=${encodeURIComponent(o.state)}">Continue with Discord</a>` : ''}
  ${o.google ? `<a class="btn block" href="/login/google?state=${encodeURIComponent(o.state)}">Continue with Google</a>` : ''}
  ${o.discord || o.google ? '<div class="or">or</div>' : ''}
  <form id="pw" novalidate>
    <label for="u">Username</label>
    <input id="u" name="username" autocomplete="username webauthn" autocapitalize="none" autocorrect="off" spellcheck="false" required>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <button class="btn primary block" type="submit">Sign in</button>
  </form>
  <button id="pk" class="btn block" type="button" hidden>Sign in with a passkey</button>
</section>
<section id="step2" hidden>
  <form id="otp" novalidate>
    <label for="c">Code from your authenticator app</label>
    <input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" required>
    <p class="dim small">Lost your phone? Enter one of your recovery codes instead.</p>
    <button class="btn primary block" type="submit">Verify</button>
  </form>
  <button id="back" class="btn block" type="button">Start over</button>
</section>
<p class="dim small" style="margin-top:2rem">${
    o.discord
      ? 'No username yet? Continue with Discord, then add a password or passkey under <a href="/login?audience=account">sign-in settings</a>.'
      : 'Accounts are created by this home’s operator.'
  }</p>`;
  const script = `
const S = ${scriptJson({ state: o.state })};
let ticket = null, conditional = null;
const err = (m) => { $('err').textContent = m || ''; };
const busy = (form, on) => form.querySelectorAll('button,input').forEach((e) => (e.disabled = on));
const go = (r) => { if (r.body && r.body.redirect) { location.assign(r.body.redirect); return true; } return false; };

$('pw').onsubmit = async (e) => {
  e.preventDefault(); err('');
  const username = $('u').value.trim(), password = $('p').value;
  if (!username || !password) return err('Enter your username and password.');
  busy($('pw'), true);
  const r = await post('/login/password', { state: S.state, username, password }).catch(() => ({ body: { error: 'Network error.' } }));
  busy($('pw'), false);
  if (go(r)) return;
  if (r.body.next === 'totp') {
    ticket = r.body.ticket; if (conditional) conditional.abort();
    $('step1').hidden = true; $('step2').hidden = false; $('c').focus(); return;
  }
  err(r.body.error || 'Sign-in failed.'); $('p').select();
};

$('otp').onsubmit = async (e) => {
  e.preventDefault(); err('');
  const code = $('c').value.trim(); if (!code) return err('Enter the code.');
  busy($('otp'), true);
  const r = await post('/login/totp', { ticket, code }).catch(() => ({ body: { error: 'Network error.' } }));
  busy($('otp'), false);
  if (go(r)) return;
  err(r.body.error || 'Wrong code.'); $('c').select();
  if (r.body.restart) restart();
};
function restart() { ticket = null; $('step2').hidden = true; $('step1').hidden = false; $('p').value = ''; $('c').value = ''; }
$('back').onclick = () => { err(''); restart(); };

async function passkey(mode) {
  if (conditional) { conditional.abort(); conditional = null; }
  const opt = await post('/login/passkey/begin', { state: S.state }).catch(() => null);
  if (!opt || opt.status !== 200) { if (mode === 'modal') err((opt && opt.body.error) || 'Could not start passkey sign-in.'); return; }
  const pk = opt.body.publicKey;
  const req = { publicKey: { ...pk, challenge: dec(pk.challenge) } };
  if (mode === 'conditional') { conditional = new AbortController(); req.mediation = 'conditional'; req.signal = conditional.signal; }
  let cred;
  try { cred = await navigator.credentials.get(req); }
  catch (e) { if (mode === 'modal') err(webauthnError(e)); return; }
  if (!cred) return;
  err('');
  const r = await post('/login/passkey/finish', { state: S.state, credential: credJSON(cred) }).catch(() => ({ body: { error: 'Network error.' } }));
  if (!go(r)) err(r.body.error || 'Passkey sign-in failed.');
}
if (passkeysSupported()) {
  $('pk').hidden = false;
  $('pk').onclick = () => { err(''); passkey('modal'); };
  // Passkey autofill: offered in the username field's suggestions.
  if (PublicKeyCredential.isConditionalMediationAvailable)
    PublicKeyCredential.isConditionalMediationAvailable().then((ok) => ok && passkey('conditional')).catch(() => {});
}
$('u').focus();
`;
  return shell(`sign in — ${o.iss}`, o.nonce, body, script);
}

// ── /account ──

export function accountPage(iss: string, nonce: string): string {
  const body = `
<h1>Sign-in settings</h1>
<p class="dim">${esc(iss)}</p>
<p id="msg" role="status"></p>
<div id="app"><p class="dim">Checking sign-in…</p></div>`;
  const script = `
const app = $('app');
let token = new URLSearchParams(location.hash.slice(1)).get('token');
if (token) history.replaceState(null, '', '/account');
let me = null;
const msg = (m, cls) => { $('msg').className = cls || 'ok'; $('msg').textContent = m || ''; };

async function api(path, body) {
  const r = await fetch(path, body === undefined
    ? { headers: { authorization: 'Bearer ' + token } }
    : { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { signIn('Your sign-in here expired (it lasts 10 minutes). Sign in again to keep going.'); throw new Error('expired'); }
  return { status: r.status, body: j };
}
function signIn(text) {
  token = null;
  app.innerHTML = '<p>' + h(text) + '</p><a class="btn primary" href="/login?audience=account">Sign in</a>';
}
async function act(path, body, okText) {
  msg('');
  let r; try { r = await api(path, body); } catch { return null; }
  if (r.status !== 200) { msg(r.body.error || 'That didn’t work.', 'err'); return null; }
  if (r.body.sub) me = r.body;
  if (okText) msg(okText);
  return r.body;
}
const fmt = (iso) => iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '';

function render(extra) {
  const until = new Date(me.exp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  let s = '<div class="card"><p>Signed in as <b>' + h(me.name) + '</b></p><p class="dim small mono">' + h(me.sub) + '</p>' +
    '<p class="dim small">This page stays signed in until ' + until + '.</p></div>';

  // username + password
  s += '<div class="card"><h2>Username &amp; password</h2>';
  if (me.hasPassword) {
    s += '<p>Username <b>' + h(me.username) + '</b></p><form id="f-pw"><label for="pw-cur">Current password</label>' +
      '<input id="pw-cur" type="password" autocomplete="current-password" required>' +
      '<input type="text" autocomplete="username" value="' + h(me.username) + '" hidden>' +
      '<label for="pw-new">New password</label><input id="pw-new" type="password" autocomplete="new-password" minlength="10" required>' +
      '<label for="pw-new2">New password again</label><input id="pw-new2" type="password" autocomplete="new-password" required>' +
      '<button class="btn block" type="submit">Change password</button></form>';
  } else {
    s += '<p class="dim">' + (me.discord ? 'Sign in without Discord. ' : '') + 'At least 10 characters.</p><form id="f-pw">' +
      (me.username ? '<p>Username <b>' + h(me.username) + '</b></p><input type="text" autocomplete="username" value="' + h(me.username) + '" hidden>'
        : '<label for="pw-user">Username</label><input id="pw-user" autocomplete="username" autocapitalize="none" spellcheck="false" required>' +
          '<p class="dim small">3–32 characters: a–z, 0–9, . _ -. It can’t be changed later.</p>') +
      '<label for="pw-new">Password</label><input id="pw-new" type="password" autocomplete="new-password" minlength="10" required>' +
      '<label for="pw-new2">Password again</label><input id="pw-new2" type="password" autocomplete="new-password" required>' +
      '<button class="btn primary block" type="submit">Set password</button></form>';
  }
  s += '</div>';

  // two-factor
  s += '<div class="card"><h2>Two-factor code</h2>';
  if (!me.hasPassword) s += '<p class="dim">Set a password first — the code is asked for after your password.</p>';
  else if (me.totp) {
    s += '<p><span class="ok">On</span> since ' + fmt(me.totp.since) + '. ' + me.totp.recoveryLeft + ' recovery code' + (me.totp.recoveryLeft === 1 ? '' : 's') + ' left.</p>' +
      '<label for="t-code">Current code from your app (needed for either button)</label><input id="t-code" inputmode="numeric" autocomplete="one-time-code">' +
      '<div class="row" style="margin-top:.5rem"><button id="t-new" class="btn sm" type="button">New recovery codes</button>' +
      '<button id="t-off" class="btn sm danger" type="button">Turn off</button></div>';
  } else if (extra && extra.setup) {
    s += '<p>Scan this with your authenticator app (1Password, Google Authenticator, Authy, …), then enter the 6-digit code it shows.</p>' +
      '<div class="qr">' + extra.setup.qr + '</div>' +
      '<p class="dim small">Can’t scan? Enter this key instead:</p><p><code class="key">' + h(extra.setup.secret.replace(/(.{4})/g, '$1 ').trim()) + '</code></p>' +
      '<form id="f-totp" class="row"><input id="t-confirm" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" required>' +
      '<button class="btn primary" type="submit">Turn on</button></form>';
  } else {
    s += '<p class="dim">Off. With it on, password sign-in also asks for a code from your phone. (Passkeys don’t need it — they’re two factors already.)</p>' +
      '<button id="t-start" class="btn block" type="button">Set up</button>';
  }
  if (extra && extra.codes) {
    s += '<p><b>Your recovery codes.</b> Each works once, in place of a code from your phone. Save them now — they won’t be shown again.</p>' +
      '<div class="codes mono">' + extra.codes.map((c) => '<span>' + h(c) + '</span>').join('') + '</div>' +
      '<button id="copy" class="btn sm" type="button">Copy</button>';
  }
  s += '</div>';

  // passkeys
  s += '<div class="card"><h2>Passkeys</h2><p class="dim">One step — fingerprint, face, or device PIN. No password or code needed.</p>';
  if (me.passkeys.length) {
    s += '<ul class="list">' + me.passkeys.map((p) => '<li><span><b>' + h(p.name) + '</b><br><span class="dim small">added ' + fmt(p.createdAt) +
      (p.lastUsedAt ? ' · last used ' + fmt(p.lastUsedAt) : ' · not used yet') + '</span></span>' +
      '<button class="btn sm danger" data-rm="' + h(p.id) + '" type="button">Remove</button></li>').join('') + '</ul>';
  }
  s += passkeysSupported()
    ? '<form id="f-pk" class="row"><input id="pk-name" maxlength="40" placeholder="name, e.g. MacBook" aria-label="Passkey name">' +
      '<button class="btn primary" type="submit">Add a passkey</button></form>'
    : '<p class="dim small">This browser can’t create passkeys.</p>';
  s += '</div>';

  // google
  if (me.google || me.canLinkGoogle) {
    s += '<div class="card"><h2>Google</h2>';
    if (me.google && me.google.linked) s += '<p>Linked to <b>' + h(me.google.email) + '</b>. Continue with Google signs in here. (Google adds no access by itself.)</p><button id="g-off" class="btn sm danger" type="button">Unlink</button>';
    else {
      if (me.google) s += '<p>Invited as <b>' + h(me.google.email) + '</b> — Continue with Google with that address links it on first use. Or link a different Google account:</p>';
      else s += '<p class="dim">Link a Google account so Continue with Google signs in here. Google adds no access by itself.</p>';
      s += '<button id="g-link" class="btn block" type="button">Link Google</button>';
    }
    s += '</div>';
  }

  // discord
  if (me.discord || me.canLinkDiscord) {
    s += '<div class="card"><h2>Discord</h2>';
    if (me.discord && !me.discord.canUnlink) s += '<p>This account is your Discord identity (<b>' + h(me.discord.name) + '</b>) — Continue with Discord always works, and your roles there decide your access.</p>';
    else if (me.discord) s += '<p>Linked to <b>' + h(me.discord.name) + '</b>. Continue with Discord signs in here, and your roles there add to your access.</p><button id="d-off" class="btn sm danger" type="button">Unlink</button>';
    else s += '<p class="dim">Link a Discord account so Continue with Discord signs in here, and its server roles add to your access. If you’ve used that Discord account here before on its own, what belongs to that identity stays with it.</p><button id="d-link" class="btn block" type="button">Link Discord</button>';
    s += '</div>';
  }
  app.innerHTML = s;
  wire();
}

function wire() {
  const on = (id, ev, fn) => { const el = $(id); if (el) el['on' + ev] = fn; };
  on('f-pw', 'submit', async (e) => {
    e.preventDefault();
    const pw = $('pw-new').value;
    if (pw !== $('pw-new2').value) return msg('The two passwords don’t match.', 'err');
    const body = { password: pw };
    if ($('pw-cur')) body.current = $('pw-cur').value;
    if ($('pw-user')) body.username = $('pw-user').value.trim();
    if (await act('/account/password', body, me.hasPassword ? 'Password changed.' : 'Password set — you can now sign in with your username.')) render();
  });
  on('t-start', 'click', async () => { const r = await act('/account/totp/begin', {}); if (r) { render({ setup: r }); $('t-confirm').focus(); } });
  on('f-totp', 'submit', async (e) => {
    e.preventDefault();
    const r = await act('/account/totp/confirm', { code: $('t-confirm').value.trim() }, 'Two-factor is on.');
    if (r) render({ codes: r.recoveryCodes });
  });
  on('t-new', 'click', async () => { const r = await act('/account/recovery', { code: $('t-code').value.trim() }, 'New recovery codes — the old ones no longer work.'); if (r) render({ codes: r.recoveryCodes }); });
  on('t-off', 'click', async () => {
    if (!confirm('Turn off two-factor? Password sign-in will need only your password.')) return;
    if (await act('/account/totp/disable', { code: $('t-code').value.trim() }, 'Two-factor is off.')) render();
  });
  on('copy', 'click', () => {
    const codes = [...document.querySelectorAll('.codes span')].map((e) => e.textContent).join('\\n');
    navigator.clipboard.writeText(codes).then(() => msg('Copied.'), () => msg('Copy failed — select them by hand.', 'err'));
  });
  on('f-pk', 'submit', async (e) => {
    e.preventDefault();
    const r = await act('/account/passkeys/begin', {}); if (!r) return;
    const pk = r.publicKey;
    let cred;
    try {
      cred = await navigator.credentials.create({ publicKey: { ...pk, challenge: dec(pk.challenge),
        user: { ...pk.user, id: dec(pk.user.id) }, excludeCredentials: pk.excludeCredentials.map((c) => ({ ...c, id: dec(c.id) })) } });
    } catch (e2) { return msg(webauthnError(e2), 'err'); }
    if (await act('/account/passkeys/finish', { credential: credJSON(cred), name: $('pk-name').value.trim() }, 'Passkey added.')) render();
  });
  document.querySelectorAll('[data-rm]').forEach((b) => (b.onclick = async () => {
    if (!confirm('Remove this passkey? (Also delete it from your device or password manager.)')) return;
    if (await act('/account/passkeys/remove', { id: b.dataset.rm }, 'Passkey removed.')) render();
  }));
  on('g-link', 'click', async () => { const r = await act('/account/google/link', {}); if (r && r.url) location.assign(r.url); });
  on('g-off', 'click', async () => {
    if (!confirm('Unlink Google? Continue with Google will stop signing in here.')) return;
    if (await act('/account/google/unlink', {}, 'Google unlinked.')) render();
  });
  on('d-link', 'click', async () => { const r = await act('/account/discord/link', {}); if (r && r.url) location.assign(r.url); });
  on('d-off', 'click', async () => {
    if (!confirm('Unlink Discord? Continue with Discord will stop signing in here, and Discord roles stop counting.')) return;
    if (await act('/account/discord/unlink', {}, 'Discord unlinked.')) render();
  });
}

(async () => {
  if (!token) return signIn('Sign in to manage how you sign in: username & password, a two-factor code, passkeys.');
  try { const r = await api('/account/me'); me = r.body; render(); } catch {}
})();
`;
  return shell(`sign-in settings — ${iss}`, nonce, body, script);
}

// ── /account/setup ──

export function setupPage(iss: string, nonce: string): string {
  const body = `
<h1>Set up your sign-in</h1>
<p class="dim">${esc(iss)}</p>
<p id="err" class="err" role="alert"></p>
<div id="app"><p class="dim">Checking your link…</p></div>`;
  const script = `
const app = $('app');
const code = new URLSearchParams(location.hash.slice(1)).get('code');
if (code) history.replaceState(null, '', '/account/setup');
const err = (m) => { $('err').textContent = m || ''; };
(async () => {
  if (!code) { app.innerHTML = '<p>This page needs the full setup link you were sent.</p>'; return; }
  const info = await post('/account/setup/info', { code });
  if (info.status !== 200) { app.innerHTML = '<p>' + h(info.body.error || 'This link doesn’t work.') + '</p>'; return; }
  const i = info.body;
  app.innerHTML = '<form id="f" novalidate>' +
    (i.needsUsername ? '<label for="u">Choose a username</label><input id="u" autocomplete="username" autocapitalize="none" spellcheck="false" required>' +
      '<p class="dim small">3–32 characters: a–z, 0–9, . _ -. It can’t be changed later.</p>'
      : '<p>Username <b>' + h(i.username) + '</b></p><input type="text" autocomplete="username" value="' + h(i.username) + '" hidden>') +
    '<label for="p">New password</label><input id="p" type="password" autocomplete="new-password" minlength="10" required>' +
    '<label for="p2">New password again</label><input id="p2" type="password" autocomplete="new-password" required>' +
    (i.needsTotp ? '<label for="t">Code from your authenticator app (or a recovery code)</label><input id="t" inputmode="numeric" autocomplete="one-time-code" required>' : '') +
    '<p class="dim small">At least 10 characters. Next you can add a passkey or a two-factor code.</p>' +
    '<button class="btn primary block" type="submit">Save and continue</button></form>';
  $('f').onsubmit = async (e) => {
    e.preventDefault(); err('');
    if ($('p').value !== $('p2').value) return err('The two passwords don’t match.');
    const r = await post('/account/setup', { code, username: $('u') ? $('u').value.trim() : undefined, password: $('p').value, totp: $('t') ? $('t').value.trim() : undefined });
    if (r.body.redirect) return location.assign(r.body.redirect);
    err(r.body.error || 'That didn’t work.');
  };
  ($('u') || $('p')).focus();
})();
`;
  return shell(`set up sign-in — ${iss}`, nonce, body, script);
}
