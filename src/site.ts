/**
 * What every page of this node looks like, and what it says about itself.
 *
 * `config/site.json` (optional, hot-reloaded) names the node for people:
 *   { "name": "Coevolution Conference", "description": "Sign-in for the conference: …" }
 * Without it the node calls itself by its issuer domain. The look is
 * Archipelago's own, the same on every node.
 */
import { JsonStore } from './stores.js';

export interface SiteInfo {
  /** What people know this node as (header, home page, page titles). */
  name?: string;
  /** A sentence or two for the home page: what signing in here is for. */
  description?: string;
}

export function siteStore(path: string): JsonStore<SiteInfo> {
  return new JsonStore<SiteInfo>(
    path,
    (raw) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
      const r = raw as Record<string, unknown>;
      const out: SiteInfo = {};
      if (r.name !== undefined) {
        if (typeof r.name !== 'string' || !r.name.trim() || r.name.length > 80) return null;
        out.name = r.name.trim();
      }
      if (r.description !== undefined) {
        if (typeof r.description !== 'string' || r.description.length > 400) return null;
        out.description = r.description.trim();
      }
      return out;
    },
    {},
    'site',
  );
}

const esc = (s: string): string =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** The node's name for people: its configured name, or its domain. */
export const siteName = (site: SiteInfo, iss: string): string => site.name || iss;

/** Islands on a horizon: the mark beside the node's name. */
export const MARK = `<svg class="mark" viewBox="0 0 32 32" width="28" height="28" aria-hidden="true" focusable="false">
<circle cx="10" cy="17" r="6" fill="currentColor" opacity=".9"/><circle cx="21" cy="19" r="4" fill="currentColor" opacity=".65"/>
<circle cx="27" cy="16" r="2.2" fill="currentColor" opacity=".45"/>
<path d="M2 22.5c3.5 2.2 7 2.2 10.5 0s7-2.2 10.5 0 5.5 2.2 7 1.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" opacity=".55"/></svg>`;

export const STYLE = `
:root{color-scheme:light dark;--bg:#f5f7f7;--fg:#13191b;--dim:#5b676c;--line:#d8dfe1;--field:#fff;--card:#fff;
--accent:#0d6b70;--accent-soft:#e3f0f0;--on-accent:#fff;--err:#b3261e;--ok:#1e7a34;--discord:#5865f2;
--shadow:0 1px 2px rgba(16,24,27,.05),0 6px 20px rgba(16,24,27,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#0c1113;--fg:#e5ebec;--dim:#94a2a7;--line:#253136;--field:#11181b;--card:#121a1d;
--accent:#55b6bc;--accent-soft:#13292b;--on-accent:#062224;--err:#ff8a80;--ok:#7fd88f;--shadow:none}}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.top{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;max-width:60rem;margin:0 auto;padding:16px}
.brand{display:flex;gap:.6rem;align-items:center;color:var(--fg);text-decoration:none;min-width:0}
.brand .mark{color:var(--accent);flex:none}
.brand b{display:block;font-size:1rem;line-height:1.2;overflow-wrap:anywhere}
.brand small{display:block;color:var(--dim);font-size:.7rem;letter-spacing:.08em;text-transform:uppercase}
.top nav{display:flex;gap:.25rem;flex-wrap:wrap}
.top nav a{color:var(--fg);text-decoration:none;font-size:.9rem;padding:.4rem .7rem;border-radius:8px}
.top nav a:hover{background:var(--accent-soft);color:var(--accent)}
main{max-width:32rem;margin:3vh auto 3rem;padding:0 16px}
main.wide{max-width:52rem}
main.home{max-width:60rem}
h1{font-size:1.6rem;line-height:1.2;margin:0 0 .35rem;letter-spacing:-.01em}
h2{font-size:1.05rem;margin:0 0 .4rem}
h3{font-size:.95rem;margin:1rem 0 .35rem}
p{margin:.5rem 0}
a{color:var(--accent)}
.dim{color:var(--dim)}.small{font-size:.875rem}.err{color:var(--err)}.ok{color:var(--ok)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:16px 0;box-shadow:var(--shadow)}
.card>h2:first-child{margin-top:0}
.section-title{font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);margin:2rem 0 .25rem}
label{display:block;font-size:.875rem;color:var(--dim);margin:.75rem 0 .25rem}
label.check{display:flex;gap:.5rem;align-items:center;color:var(--fg)}
label.check input{width:auto}
input,textarea,select{display:block;width:100%;font:inherit;font-size:16px;color:var(--fg);background:var(--field);border:1px solid var(--line);
border-radius:8px;padding:.55rem .7rem}
textarea{min-height:4.5rem;resize:vertical}
input:focus-visible,textarea:focus-visible,select:focus-visible,.btn:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;font:inherit;font-weight:500;text-decoration:none;color:var(--fg);
background:transparent;border:1px solid var(--line);border-radius:10px;padding:.5rem 1rem;min-height:44px;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.block{display:flex;width:100%;margin-top:.75rem}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.btn.primary:hover{filter:brightness(1.07)}
.btn.big{min-height:52px;padding:.7rem 1.4rem;font-size:1.05rem}
.btn.discord{background:var(--discord);border-color:var(--discord);color:#fff}
.btn.danger{color:var(--err)}
.btn.sm{min-height:34px;padding:.25rem .7rem;font-size:.875rem}
.btn:disabled{opacity:.55;cursor:default}
.row{display:flex;gap:.5rem;align-items:flex-end;flex-wrap:wrap}.row>input{flex:1;min-width:10rem}
.or{display:flex;align-items:center;gap:.75rem;color:var(--dim);font-size:.875rem;margin:1rem 0}
.or::before,.or::after{content:"";flex:1;border-top:1px solid var(--line)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;word-break:break-all}
code.key{word-break:normal;font-size:1rem;letter-spacing:.02em}
ul.list{list-style:none;padding:0;margin:.5rem 0}
ul.list li{display:flex;justify-content:space-between;align-items:center;gap:.75rem;padding:.55rem 0;border-top:1px solid var(--line)}
ul.list li:first-child{border-top:0}
.codes{display:grid;grid-template-columns:repeat(2,1fr);gap:.25rem 1rem;padding:.75rem;border:1px dashed var(--line);border-radius:8px;margin:.5rem 0}
.qr{display:flex;justify-content:center;margin:.75rem 0}.qr svg{max-width:100%;height:auto;border-radius:6px}
.tag{display:inline-block;font-size:.75rem;line-height:1.5;padding:0 .5rem;border-radius:99px;background:var(--accent-soft);color:var(--accent);white-space:nowrap}
.tag.off{background:transparent;border:1px solid var(--line);color:var(--dim)}
.hero{padding:3vh 0 1rem}
.hero h1{font-size:clamp(1.9rem,4.5vw,2.6rem)}
.hero .lede{font-size:1.15rem;color:var(--dim);max-width:40rem}
.actions{display:flex;gap:.75rem;flex-wrap:wrap;margin:1.5rem 0}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr))}
.grid .card{margin:0}
.svc{display:flex;flex-direction:column;gap:.25rem;text-decoration:none;color:var(--fg)}
.svc:hover b{color:var(--accent)}
.tbl{overflow-x:auto}
table.t{width:100%;border-collapse:collapse;font-size:.9rem}
table.t th{font-weight:600;color:var(--dim);font-size:.75rem;letter-spacing:.04em;text-transform:uppercase}
table.t td,table.t th{padding:.5rem .4rem;border-top:1px solid var(--line);text-align:left;vertical-align:top}
details{margin:.75rem 0}
details>summary{cursor:pointer;color:var(--accent)}
footer.foot{max-width:60rem;margin:2.5rem auto 1.5rem;padding:16px;color:var(--dim);font-size:.85rem;border-top:1px solid var(--line)}
#msg:empty,#err:empty{display:none}
`;

/** The header every page carries: the mark and the node's name, and where to go. */
export function topBar(site: SiteInfo, iss: string): string {
  return `<header class="top"><a class="brand" href="/">${MARK}<span><b>${esc(siteName(site, iss))}</b><small>Archipelago</small></span></a>
<nav aria-label="Main"><a href="/account">Your account</a><a href="/agents.md">For agents</a></nav></header>`;
}

/** A plain page (no script): the home page, the enroll page, and the node's short messages. */
export function plainPage(o: { site: SiteInfo; iss: string; title: string; body: string; main?: 'home' | 'wide' | '' }): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(o.title)} — ${esc(siteName(o.site, o.iss))}</title><style>${STYLE}</style>
${topBar(o.site, o.iss)}
<main${o.main ? ` class="${o.main}"` : ''}>${o.body}</main>
<footer class="foot">${esc(siteName(o.site, o.iss))} runs on Archipelago, an identity home for people and AI agents.</footer></html>`;
}

interface Listed { name?: string; description?: string; url?: string; redirect: string }

/** The home page: what Archipelago is, where to sign in, the services that sign in here; the key last. */
export function homePage(o: { site: SiteInfo; iss: string; issuerId: string; audiences: Record<string, Listed> }): string {
  const name = siteName(o.site, o.iss);
  const services = Object.entries(o.audiences)
    .filter(([, a]) => a.name)
    .map(([, a]) => {
      let href = a.url || '';
      if (!href) try { href = new URL(a.redirect).origin; } catch { href = ''; }
      return `<a class="card svc" href="${esc(href)}"><b>${esc(a.name!)}</b>${a.description ? `<span class="dim small">${esc(a.description)}</span>` : ''}<span class="small">${esc(href.replace(/^https?:\/\//, ''))}</span></a>`;
    });
  const body = `<section class="hero">
<h1>${esc(name)}</h1>
<p class="lede">${esc(o.site.description || `Sign in once, and use it wherever ${name} is.`)}</p>
<div class="actions"><a class="btn primary big" href="/login?audience=account">Sign in</a><a class="btn big" href="/agents.md">I’m an AI agent</a></div>
</section>
${services.length ? `<h2 class="section-title">Signs in here</h2><div class="grid">${services.join('')}</div>` : ''}
<h2 class="section-title">What is Archipelago?</h2>
<div class="grid">
<div class="card"><h2>One account, your choice of sign-in</h2><p class="dim">Sign in with a code sent to your email, with Google, with a passkey or with a password. Add or change them any time in your account.</p></div>
<div class="card"><h2>For people and their agents</h2><p class="dim">AI agents get an identity here too. A person vouches for each one with an invite, and the agent enrolls itself with it.</p></div>
<div class="card"><h2>Services get only what they need</h2><p class="dim">Each service receives a short-lived sign-in token that says who you are and what you may do there. Your email address stays here.</p></div>
</div>
<details class="small dim"><summary>Technical details</summary>
<p>Issuer <code>${esc(o.iss)}</code> · key <code>${esc(o.issuerId)}</code></p>
<p>Agents exchange key proofs at <code>POST /token</code> and enroll at <code>POST /enroll</code>; services verify tokens offline with the key at <a href="/.well-known/mcpl-identity">/.well-known/mcpl-identity</a> and find each other at <a href="/services">/services</a>.</p>
</details>`;
  return plainPage({ site: o.site, iss: o.iss, title: 'Home', body, main: 'home' });
}

/** What someone sees opening the enroll address in a browser: it is a door for agents. */
export function enrollPage(o: { site: SiteInfo; iss: string; publicUrl: string }): string {
  const body = `<div class="card">
<h1>Enrolling is done by agents</h1>
<p>This is where an AI agent gets its identity on this node. The agent does it itself: it makes a key, signs a short statement with its invite code, and sends it here. There's nothing to do in a browser.</p>
<h2>Have an invite code for your agent?</h2>
<p>Give your agent the code and this link: <a href="/agents.md">${esc(o.publicUrl)}/agents.md</a>. It explains every step, and your agent can follow it on its own.</p>
<h2>Want to sign in yourself?</h2>
<p><a class="btn primary" href="/login?audience=account">Sign in</a></p>
<details class="small dim"><summary>Technical details</summary><p>Agents <code>POST ${esc(o.publicUrl)}/enroll</code> with their key proof and receive their identity and first token. The statement to sign is in <a href="/agents.md">/agents.md</a>.</p></details>
</div>`;
  return plainPage({ site: o.site, iss: o.iss, title: 'Enroll', body });
}

/** The old console address: invites for agents are part of the account now. */
export function consoleMovedPage(o: { site: SiteInfo; iss: string }): string {
  const body = `<div class="card"><h1>Agent invites are in your account now</h1>
<p>If you can make invites for agents here, you'll find them on your account page.</p>
<p><a class="btn primary" href="/login?audience=account">Go to your account</a></p></div>`;
  return plainPage({ site: o.site, iss: o.iss, title: 'Agent invites', body });
}
