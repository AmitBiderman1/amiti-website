// Amiti's: Cloudflare Worker (API + static assets) backed by D1.
// Every request is checked against the Cloudflare Access login before anything is served.

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { ...JSON_HEADERS, ...extra } });
const fail = (status, error, code) => json({ error, code }, status);

/* ---------- Cloudflare Access (JWT) verification ---------- */

let certCache = { at: 0, keys: null, domain: '' };

function b64uToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const b64uToJson = (s) => JSON.parse(new TextDecoder().decode(b64uToBytes(s)));

async function accessCerts(domain) {
  if (certCache.keys && certCache.domain === domain && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const r = await fetch(`https://${domain}/cdn-cgi/access/certs`);
  if (!r.ok) throw new Error('certs');
  const j = await r.json();
  certCache = { at: Date.now(), keys: j.keys || [], domain };
  return certCache.keys;
}

async function verifyAccessJwt(token, env) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  let header, payload;
  try { header = b64uToJson(h); payload = b64uToJson(p); } catch { return null; }
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(env.ACCESS_AUD)) return null;
  if (payload.iss !== `https://${env.TEAM_DOMAIN}`) return null;
  if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
  const keys = await accessCerts(env.TEAM_DOMAIN);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64uToBytes(sig), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) return null;
  return String(payload.email || payload.sub || '').toLowerCase() || null;
}

// Returns the owner id (the signed-in email), or a Response to send back.
async function authenticate(req, env, url) {
  if (env.TEAM_DOMAIN && env.ACCESS_AUD) {
    const token = req.headers.get('Cf-Access-Jwt-Assertion');
    if (!token) return new Response('Sign-in required.', { status: 401 });
    try {
      const owner = await verifyAccessJwt(token, env);
      if (owner) return owner;
    } catch { /* fall through */ }
    return new Response('Sign-in required.', { status: 401 });
  }
  if (pwMode(env)) {
    if (await sessionOk(req, env)) return 'owner';
    if (url.pathname.startsWith('/api/')) return fail(401, 'Sign-in required', 'unauthorised');
    return new Response(null, { status: 302, headers: { location: '/login', 'cache-control': 'no-store' } });
  }
  // Not configured yet: only allow local development.
  if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') return 'local';
  return new Response(
    'Amiti’s is not protected yet. Set APP_PASSWORD (or TEAM_DOMAIN and ACCESS_AUD), see the README, then redeploy.',
    { status: 503 }
  );
}

/* ---------- Password login (free alternative to Cloudflare Access) ---------- */

const enc = new TextEncoder();
const pwMode = (env) => !!(env.APP_PASSWORD && env.APP_PASSWORD.length >= 10);

async function hmacHex(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function sessionOk(req, env) {
  const [exp, sig] = cookie(req, 'amitis_s').split('.');
  if (!exp || !sig || !(Number(exp) > Date.now())) return false;
  return safeEq(sig, await hmacHex(env.APP_PASSWORD, 's:' + exp));
}
const LOGIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Amiti’s</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#faf6ef;color:#3a2b21;font:16px system-ui,sans-serif}
form{background:#fffdf9;border:1px solid #e8dccb;border-radius:16px;padding:24px;width:min(340px,90vw);display:grid;gap:12px}
h1{margin:0;font:700 1.6rem Georgia,serif}input,button{font:inherit;padding:10px;border-radius:8px;border:1px solid #e8dccb}
button{background:#8a5a3b;color:#fff;border-color:#8a5a3b;cursor:pointer;font-weight:600}p{margin:0;color:#c4573f;min-height:1.2em;font-size:.9rem}
</style></head><body><form id="f"><h1>Amiti’s</h1><input id="p" type="password" placeholder="Password" autocomplete="current-password" required autofocus><button>Sign in</button><p id="m" role="status"></p></form>
<script>document.getElementById('f').onsubmit=function(e){e.preventDefault();var m=document.getElementById('m');m.textContent='';
fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})})
.then(function(r){if(r.ok){location.href='/'}else{m.textContent=r.status===429?'Too many attempts. Try again in 15 minutes.':'Wrong password.'}}).catch(function(){m.textContent='Network error.'})}</script></body></html>`;

async function handleLogin(req, env) {
  const key = 'login_fail';
  const rec = (await getSetting(env, 'owner', key)) || '0:0';
  let [count, at] = rec.split(':').map(Number);
  if (count >= 10 && Date.now() - at < 15 * 60000) return fail(429, 'Too many attempts', 'rate_limited');
  if (Date.now() - at >= 15 * 60000) count = 0;
  let b;
  try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
  const given = await hmacHex('cmp', String(b.password ?? ''));
  const real = await hmacHex('cmp', env.APP_PASSWORD);
  if (!safeEq(given, real)) {
    await setSetting(env, 'owner', key, `${count + 1}:${Date.now()}`);
    return fail(401, 'Wrong password', 'unauthorised');
  }
  await delSetting(env, 'owner', key);
  const exp = Date.now() + 30 * 86400000;
  const sig = await hmacHex(env.APP_PASSWORD, 's:' + exp);
  return json({ ok: true }, 200, {
    'set-cookie': `amitis_s=${exp}.${sig}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
  });
}

/* ---------- helpers ---------- */

const RE_ID = /^[A-Za-z0-9._-]{1,40}$/;
const RE_DAY = /^\d{4}-\d{2}-\d{2}$/;
const RE_DT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
const str = (v, n) => String(v ?? '').slice(0, n);
const num = (v, min, max, def) => {
  const x = Number(v);
  return Number.isFinite(x) ? Math.min(max, Math.max(min, x)) : def;
};
const bit = (v) => (v ? 1 : 0);
const dt = (v) => (typeof v === 'string' && (v === '' || RE_DT.test(v)) ? v : '');
const TAGS = ['home', 'mil', 'priv', 'fam'];
const SLOTS = ['breakfast', 'lunch', 'dinner', 'snack'];

async function getSetting(env, owner, key) {
  const r = await env.DB.prepare('SELECT value FROM settings WHERE owner=? AND key=?').bind(owner, key).first();
  return r ? r.value : null;
}
const setSetting = (env, owner, key, value) =>
  env.DB.prepare(
    'INSERT INTO settings(owner,key,value) VALUES(?,?,?) ON CONFLICT(owner,key) DO UPDATE SET value=excluded.value'
  ).bind(owner, key, value).run();
const delSetting = (env, owner, key) =>
  env.DB.prepare('DELETE FROM settings WHERE owner=? AND key=?').bind(owner, key).run();

/* ---------- state + sync ---------- */

async function getState(env, owner) {
  const cutoff = new Date(Date.now() - 120 * 86400000).toISOString().slice(0, 10);
  const [t, f, m, goal] = await Promise.all([
    env.DB.prepare('SELECT id,text,due,dur,snooze,fired,tag,urgent,important,done,gcal_id FROM tasks WHERE owner=?').bind(owner).all(),
    env.DB.prepare('SELECT id,day,slot,name,kcal,p,c,f FROM food WHERE owner=? AND day>=?').bind(owner, cutoff).all(),
    env.DB.prepare('SELECT id,name,servings,ing FROM meals WHERE owner=?').bind(owner).all(),
    getSetting(env, owner, 'goal'),
  ]);
  return {
    tasks: t.results.map(({ gcal_id, ...r }) => ({ ...r, urgent: !!r.urgent, important: !!r.important, done: !!r.done, gcal: !!gcal_id })),
    food: f.results,
    meals: m.results.map((r) => {
      let ing = [];
      try { ing = JSON.parse(r.ing); } catch { /* ignore */ }
      return { id: r.id, name: r.name, servings: r.servings, ing };
    }),
    goal: Number(goal) > 0 ? Number(goal) : 2000,
  };
}

async function applySync(env, owner, b) {
  const db = env.DB;
  const stmts = [];
  const now = new Date().toISOString();
  const list = (x, n = 500) => (Array.isArray(x) ? x.slice(0, n) : []);
  const calTasks = [];
  const taskDels = [];

  for (const t of list(b.tasks?.upsert)) {
    if (!t || !RE_ID.test(String(t.id))) continue;
    const text = str(t.text, 200).trim();
    if (!text) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO tasks(owner,id,text,due,dur,snooze,fired,tag,urgent,important,done,updated)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET text=excluded.text,due=excluded.due,dur=excluded.dur,snooze=excluded.snooze,
           fired=excluded.fired,tag=excluded.tag,urgent=excluded.urgent,important=excluded.important,done=excluded.done,
           updated=excluded.updated`
      ).bind(
        owner, String(t.id), text, dt(t.due), Math.round(num(t.dur, 5, 1440, 30)), dt(t.snooze), dt(t.fired),
        TAGS.includes(t.tag) ? t.tag : 'priv', bit(t.urgent), bit(t.important), bit(t.done), now
      )
    );
    calTasks.push({ id: String(t.id), text, due: dt(t.due), dur: Math.round(num(t.dur, 5, 1440, 30)), tag: TAGS.includes(t.tag) ? t.tag : 'priv', done: !!t.done });
  }
  for (const id of list(b.tasks?.del)) {
    if (RE_ID.test(String(id))) {
      taskDels.push(String(id));
      stmts.push(db.prepare('DELETE FROM tasks WHERE owner=? AND id=?').bind(owner, String(id)));
    }
  }

  // Remember the calendar event ids before the rows change.
  const before = await existingTasks(env, owner, [...calTasks.map((t) => t.id), ...taskDels]);

  for (const e of list(b.food?.upsert)) {
    if (!e || !RE_ID.test(String(e.id)) || !RE_DAY.test(String(e.day))) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO food(owner,id,day,slot,name,kcal,p,c,f) VALUES(?,?,?,?,?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET day=excluded.day,slot=excluded.slot,name=excluded.name,kcal=excluded.kcal,
           p=excluded.p,c=excluded.c,f=excluded.f`
      ).bind(
        owner, String(e.id), e.day, SLOTS.includes(e.slot) ? e.slot : 'snack', str(e.name, 120) || 'Food',
        Math.round(num(e.kcal, 0, 20000, 0)), num(e.p, 0, 2000, 0), num(e.c, 0, 2000, 0), num(e.f, 0, 2000, 0)
      )
    );
  }
  for (const id of list(b.food?.del)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM food WHERE owner=? AND id=?').bind(owner, String(id)));
  }

  for (const m of list(b.meals?.upsert, 200)) {
    if (!m || !RE_ID.test(String(m.id))) continue;
    const name = str(m.name, 80).trim();
    if (!name) continue;
    const ing = (Array.isArray(m.ing) ? m.ing : []).slice(0, 60).map((i) => ({
      n: str(i && i.n, 120), k: num(i && i.k, 0, 50000, 0), p: num(i && i.p, 0, 5000, 0),
      c: num(i && i.c, 0, 5000, 0), f: num(i && i.f, 0, 5000, 0),
    }));
    stmts.push(
      db.prepare(
        `INSERT INTO meals(owner,id,name,servings,ing) VALUES(?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET name=excluded.name,servings=excluded.servings,ing=excluded.ing`
      ).bind(owner, String(m.id), name, num(m.servings, 0.25, 1000, 1), JSON.stringify(ing))
    );
  }
  for (const id of list(b.meals?.del, 200)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM meals WHERE owner=? AND id=?').bind(owner, String(id)));
  }

  if (b.goal !== undefined) {
    const g = Math.round(num(b.goal, 500, 10000, 2000));
    stmts.push(
      db.prepare('INSERT INTO settings(owner,key,value) VALUES(?,?,?) ON CONFLICT(owner,key) DO UPDATE SET value=excluded.value')
        .bind(owner, 'goal', String(g))
    );
  }

  // D1 batches run as one transaction; keep chunks modest.
  for (let i = 0; i < stmts.length; i += 90) await db.batch(stmts.slice(i, i + 90));
  let gcal = {};
  try { gcal = await calendarSideEffects(env, owner, before, calTasks, taskDels); } catch (e) { console.error('calendar sync', e && e.message); }
  return { n: stmts.length, gcal };
}

/* ---------- tasks with a time go to Google Calendar automatically ---------- */

const TAG_NAMES = { home: 'Home tasks', mil: 'Military', priv: 'Private', fam: 'Friends and family' };
const RE_GID = /^[A-Za-z0-9_-]{1,200}$/;

async function existingTasks(env, owner, ids) {
  const m = new Map();
  const uniq = [...new Set(ids)];
  for (let i = 0; i < uniq.length; i += 80) {
    const part = uniq.slice(i, i + 80);
    const r = await env.DB.prepare(
      `SELECT id,text,due,dur,tag,gcal_id FROM tasks WHERE owner=? AND id IN (${part.map(() => '?').join(',')})`
    ).bind(owner, ...part).all();
    for (const row of r.results) m.set(row.id, row);
  }
  return m;
}

function addMinutes(local, mins) {
  const [d, t] = local.split('T');
  const [y, mo, da] = d.split('-').map(Number);
  const [h, mi] = t.split(':').map(Number);
  const x = new Date(Date.UTC(y, mo - 1, da, h, mi + mins));
  const p = (n) => String(n).padStart(2, '0');
  return `${x.getUTCFullYear()}-${p(x.getUTCMonth() + 1)}-${p(x.getUTCDate())}T${p(x.getUTCHours())}:${p(x.getUTCMinutes())}:00`;
}

function taskEventBody(env, t) {
  const tz = env.TIMEZONE || 'Asia/Jerusalem';
  return {
    summary: t.text,
    description: TAG_NAMES[t.tag] || '',
    start: { dateTime: t.due + ':00', timeZone: tz },
    end: { dateTime: addMinutes(t.due, t.dur), timeZone: tz },
    reminders: { useDefault: true },
    extendedProperties: { private: { amitisTask: t.id } },
  };
}

// One Calendar API call. Returns {skip:true} when Google is not connected yet.
async function calCall(env, owner, method, path, body) {
  if (!gConfigured(env)) return { skip: true };
  let token;
  try { token = await googleToken(env, owner); } catch { return { ok: false, status: 0 }; }
  if (!token) return { skip: true };
  const r = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events' + path, {
    method,
    headers: { authorization: 'Bearer ' + token, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) await delSetting(env, owner, 'g_access');
  let j = null;
  if (r.status !== 204) { try { j = await r.json(); } catch { /* ignore */ } }
  return { ok: r.ok, status: r.status, json: j };
}

const setGid = (env, owner, id, gid) =>
  env.DB.prepare('UPDATE tasks SET gcal_id=? WHERE owner=? AND id=?').bind(gid, owner, id).run();

// Creates or updates the event. Returns the event id, or '' when it could not be done.
async function pushTaskToCalendar(env, owner, t, gid) {
  if (gid) {
    const r = await calCall(env, owner, 'PATCH', '/' + encodeURIComponent(gid), taskEventBody(env, t));
    if (r.skip) return gid;
    if (r.ok) return gid;
    if (r.status !== 404 && r.status !== 410) return gid; // temporary failure: keep the link
  }
  const r = await calCall(env, owner, 'POST', '', taskEventBody(env, t));
  if (r.ok && r.json && RE_GID.test(String(r.json.id))) {
    await setGid(env, owner, t.id, r.json.id);
    return r.json.id;
  }
  return '';
}

async function calendarSideEffects(env, owner, before, upserts, dels) {
  const out = {};
  for (const id of dels) {
    const gid = before.get(id)?.gcal_id;
    if (gid) await calCall(env, owner, 'DELETE', '/' + encodeURIComponent(gid));
  }
  let budget = 25;
  for (const t of upserts) {
    const old = before.get(t.id);
    const gid = old?.gcal_id || '';
    if (!t.due) { // time removed: take it off the calendar
      if (gid) {
        const r = await calCall(env, owner, 'DELETE', '/' + encodeURIComponent(gid));
        if (r.skip || r.ok || r.status === 404 || r.status === 410) await setGid(env, owner, t.id, '');
        else { out[t.id] = true; continue; }
      }
      out[t.id] = false;
      continue;
    }
    if (t.done) { out[t.id] = !!gid; continue; } // done tasks keep their past event
    const same = gid && old && old.text === t.text && old.due === t.due && old.dur === t.dur && old.tag === t.tag;
    if (same || budget <= 0) { out[t.id] = !!gid; continue; }
    budget--;
    out[t.id] = !!(await pushTaskToCalendar(env, owner, t, gid));
  }
  return out;
}

const localToday = (env) => new Date().toLocaleDateString('sv-SE', { timeZone: env.TIMEZONE || 'Asia/Jerusalem' });

// Adds events for upcoming timed tasks that have none yet (Google was not connected, or an earlier call failed).
async function reconcileCalendar(env, owner, limit = 10) {
  try {
    if (!gConfigured(env) || !(await getSetting(env, owner, 'g_refresh'))) return 0;
    const r = await env.DB.prepare(
      "SELECT id,text,due,dur,tag FROM tasks WHERE owner=? AND done=0 AND due<>'' AND gcal_id='' AND due>=? ORDER BY due LIMIT ?"
    ).bind(owner, localToday(env) + 'T00:00', limit).all();
    let n = 0;
    for (const row of r.results) if (await pushTaskToCalendar(env, owner, row, '')) n++;
    return n;
  } catch (e) { console.error('reconcile', e && e.message); return 0; }
}

const background = (ctx, p) => (ctx && ctx.waitUntil ? ctx.waitUntil(p) : p);

/* ---------- Claude (Anthropic API) proxy ---------- */

const aiEnabled = (env) => !!(env.ANTHROPIC_API_KEY || env.AI);

async function handleAi(req, env) {
  if (!aiEnabled(env)) return fail(503, 'AI is not configured', 'ai_config');
  let b;
  try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
  if (!Array.isArray(b.messages) || !b.messages.length || b.messages.length > 20) return fail(400, 'Bad messages', 'bad_request');

  const merged = [];
  let chars = 0;
  for (const m of b.messages) {
    if (!m || (m.role !== 'user' && m.role !== 'assistant') || typeof m.content !== 'string' || !m.content) {
      return fail(400, 'Bad messages', 'bad_request');
    }
    chars += m.content.length;
    const last = merged[merged.length - 1];
    if (last && last.role === m.role) last.content += '\n\n' + m.content;
    else merged.push({ role: m.role, content: m.content });
  }
  if (chars > 120000 || merged[0].role !== 'user' || merged[merged.length - 1].role !== 'user') {
    return fail(400, 'Bad messages', 'bad_request');
  }
  const images = (Array.isArray(b.images) ? b.images : []).slice(0, 1);
  const okTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
  for (const im of images) {
    if (!im || !okTypes.includes(im.media_type) || typeof im.data !== 'string' || im.data.length > 7_000_000) {
      return fail(400, 'Bad image', 'image_rejected');
    }
  }
  return env.ANTHROPIC_API_KEY ? aiClaude(env, merged, images) : aiWorkers(env, merged, images);
}

async function aiClaude(env, merged, images) {
  const blocks = images.map((im) => ({ type: 'image', source: { type: 'base64', media_type: im.media_type, data: im.data } }));
  blocks.push({ type: 'text', text: merged[merged.length - 1].content });
  const messages = merged.map((m, i) => (i === merged.length - 1 ? { role: 'user', content: blocks } : m));
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: env.AI_MODEL || 'claude-sonnet-5-5', max_tokens: 2048, messages }),
  });
  if (r.status === 429) return fail(429, 'Rate limited', 'rate_limited');
  if (r.status === 401 || r.status === 403) return fail(502, 'AI key rejected', 'ai_config');
  if (!r.ok) return fail(502, 'AI request failed', 'upstream_error');
  const j = await r.json();
  const text = (j.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('');
  return json({ text, truncated: j.stop_reason === 'max_tokens' });
}

// Free option: Cloudflare Workers AI (daily free allowance, no card needed).
// Workers AI retired the old Llama 3.1 8B / LLaVA models on 2026-05-30, so try current models in order.
const TEXT_MODELS = ['@cf/meta/llama-3.1-8b-instruct-fast', '@cf/google/gemma-4-26b-a4b-it', '@cf/zai-org/glm-4.7-flash'];
const VISION_MODELS = ['@cf/google/gemma-4-26b-a4b-it', '@cf/moonshotai/kimi-k2.6'];
const RETIRED = /llama-3\.1-8b-instruct$|llava-1\.5|llama-3-8b|llama-3\.1-70b|gemma-3-12b|mistral-7b|uform/i;

function aiText(out) {
  const c = out?.choices?.[0]?.message?.content;
  const t = out?.response ?? c ?? out?.result?.response ?? out?.description ?? '';
  return String(Array.isArray(t) ? t.map((x) => x?.text || '').join('') : t);
}

async function aiWorkers(env, merged, images) {
  const wanted = images.length ? env.AI_VISION_MODEL : env.AI_TEXT_MODEL;
  const models = [...new Set([wanted && !RETIRED.test(wanted) ? wanted : null, ...(images.length ? VISION_MODELS : TEXT_MODELS)].filter(Boolean))];
  const errors = [];
  for (const model of models) {
    try {
      let input;
      if (images.length) {
        const url = `data:${images[0].media_type};base64,${images[0].data}`;
        const msgs = merged.map((m, i) => (i === merged.length - 1
          ? { role: 'user', content: [{ type: 'text', text: m.content }, { type: 'image_url', image_url: { url } }] }
          : m));
        input = { messages: msgs, max_tokens: 1200 };
      } else {
        input = { messages: merged, max_tokens: 1500 };
      }
      const text = aiText(await env.AI.run(model, input));
      if (text) return json({ text, truncated: false });
      errors.push(model.split('/').pop() + ': empty');
    } catch (e) {
      const msg = String((e && e.message) || e);
      console.error('workers ai error', model, msg);
      if (/limit|quota|neuron|429|capacity/i.test(msg) && !/not found|deprecat|no such model/i.test(msg)) {
        return fail(429, 'Free daily AI limit reached', 'rate_limited');
      }
      errors.push(model.split('/').pop() + ': ' + msg.replace(/\s+/g, ' ').slice(0, 90));
    }
  }
  return json({ error: 'AI request failed', code: 'upstream_error', detail: errors.join(' | ').slice(0, 300) }, 502);
}

/* ---------- Google Calendar (OAuth + API) ---------- */

const GA = 'https://www.googleapis.com/auth/';
const SC = {
  cal: GA + 'calendar.events',
  crCourses: GA + 'classroom.courses.readonly',
  crWork: GA + 'classroom.coursework.me.readonly',
  crSubs: GA + 'classroom.student-submissions.me.readonly',
  mail: GA + 'gmail.readonly',
};
const G_SCOPE = Object.values(SC).join(' ');
const gConfigured = (env) => !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);

function cookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

async function googleConnect(req, env, url) {
  if (!gConfigured(env)) return fail(503, 'Google is not configured', 'gcal_config');
  const state = crypto.randomUUID();
  const q = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: `${url.origin}/api/google/callback`,
    response_type: 'code',
    scope: G_SCOPE,
    access_type: 'offline',
    include_granted_scopes: 'true',
    prompt: 'consent',
    state,
  });
  return new Response(null, {
    status: 302,
    headers: {
      location: 'https://accounts.google.com/o/oauth2/v2/auth?' + q,
      'set-cookie': `g_state=${state}; Path=/api/google; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
      'cache-control': 'no-store',
    },
  });
}

async function googleCallback(req, env, url, owner) {
  const back = (qs) => new Response(null, { status: 302, headers: { location: '/' + qs, 'cache-control': 'no-store' } });
  if (!gConfigured(env)) return back('?gcal=error');
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state || state !== cookie(req, 'g_state')) return back('?gcal=error');
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${url.origin}/api/google/callback`,
      grant_type: 'authorization_code',
    }),
  });
  if (!r.ok) return back('?gcal=error');
  const t = await r.json();
  if (t.refresh_token) await setSetting(env, owner, 'g_refresh', t.refresh_token);
  else if (!(await getSetting(env, owner, 'g_refresh'))) return back('?gcal=error');
  if (t.scope) await setSetting(env, owner, 'g_scope', t.scope);
  if (t.access_token) {
    await setSetting(env, owner, 'g_access', t.access_token);
    await setSetting(env, owner, 'g_exp', String(Date.now() + (t.expires_in || 3600) * 1000));
  }
  return back('?gcal=connected');
}

// Returns an access token, null when not connected, or throws 'needs_reauth'.
async function googleToken(env, owner) {
  const refresh = await getSetting(env, owner, 'g_refresh');
  if (!refresh) return null;
  const access = await getSetting(env, owner, 'g_access');
  const exp = Number(await getSetting(env, owner, 'g_exp'));
  if (access && exp > Date.now() + 60000) return access;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refresh,
      grant_type: 'refresh_token',
    }),
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    if (j.error === 'invalid_grant') {
      await delSetting(env, owner, 'g_refresh');
      await delSetting(env, owner, 'g_access');
      throw new Error('needs_reauth');
    }
    throw new Error('upstream');
  }
  const t = await r.json();
  await setSetting(env, owner, 'g_access', t.access_token);
  await setSetting(env, owner, 'g_exp', String(Date.now() + (t.expires_in || 3600) * 1000));
  return t.access_token;
}

async function gcalRequest(env, owner, build) {
  if (!gConfigured(env)) return { error: fail(503, 'Google is not configured', 'gcal_config') };
  let token;
  try { token = await googleToken(env, owner); } catch (e) {
    return { error: e.message === 'needs_reauth' ? fail(401, 'Reconnect Google Calendar', 'needs_reauth') : fail(502, 'Google error', 'upstream_error') };
  }
  if (!token) return { error: fail(409, 'Google Calendar is not connected', 'not_connected') };
  const r = await build(token);
  if (r.status === 401) {
    await delSetting(env, owner, 'g_access');
    return { error: fail(401, 'Reconnect Google Calendar', 'needs_reauth') };
  }
  if (r.status === 429) return { error: fail(429, 'Google rate limit', 'rate_limited') };
  if (!r.ok) return { error: fail(502, 'Google error', 'upstream_error') };
  return { r };
}

async function gcalList(env, owner, url) {
  const start = new Date(url.searchParams.get('start') || '');
  const end = new Date(url.searchParams.get('end') || '');
  if (isNaN(start) || isNaN(end) || end <= start || end - start > 100 * 86400000) return fail(400, 'Bad range', 'bad_request');
  const r = await gcalRequest(env, owner, (token) => {
    const q = new URLSearchParams({
      timeMin: start.toISOString(),
      timeMax: end.toISOString(),
      singleEvents: 'true',
      orderBy: 'startTime',
      maxResults: '250',
      fields: 'items(id,status,summary,start,end,htmlLink)',
    });
    return fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events?' + q, {
      headers: { authorization: 'Bearer ' + token },
    });
  });
  if (r.error) return r.error;
  const j = await r.r.json();
  return json({ events: j.items || [] });
}

async function gcalCreate(req, env, owner) {
  let b;
  try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
  const summary = str(b.summary, 200).trim();
  const RE_LOCAL = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;
  if (!summary || !RE_LOCAL.test(String(b.startTime)) || !RE_LOCAL.test(String(b.endTime))) return fail(400, 'Bad event', 'bad_request');
  const tz = env.TIMEZONE || 'Asia/Jerusalem';
  const body = { summary, description: str(b.description, 1000), reminders: { useDefault: true } };
  if (b.allDay) {
    body.start = { date: String(b.startTime).slice(0, 10) };
    body.end = { date: String(b.endTime).slice(0, 10) };
  } else {
    const fix = (s) => (s.length === 16 ? s + ':00' : s);
    body.start = { dateTime: fix(String(b.startTime)), timeZone: tz };
    body.end = { dateTime: fix(String(b.endTime)), timeZone: tz };
  }
  const r = await gcalRequest(env, owner, (token) =>
    fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
  );
  if (r.error) return r.error;
  const j = await r.r.json();
  return json({ id: j.id, htmlLink: j.htmlLink });
}

/* ---------- router ---------- */


/* ---------- Google Classroom + Gmail orders ---------- */

const hasScope = async (env, owner, ...need) => {
  const have = ((await getSetting(env, owner, 'g_scope')) || '').split(' ');
  return need.every((s) => have.includes(s));
};
const classroomOk = (env, owner) => hasScope(env, owner, SC.crCourses, SC.crWork, SC.crSubs);
const mailOk = (env, owner) => hasScope(env, owner, SC.mail);

async function gGet(env, owner, url) {
  const token = await googleToken(env, owner);
  if (!token) throw new Error('not_connected');
  const r = await fetch(url, { headers: { authorization: 'Bearer ' + token } });
  if (r.status === 401) { await delSetting(env, owner, 'g_access'); throw new Error('needs_reauth'); }
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    const why = String(j?.error?.status || j?.error?.errors?.[0]?.reason || '').toLowerCase().replace(/[^a-z_]/g, '');
    throw new Error('google_' + r.status + (why ? '_' + why : ''));
  }
  return r.json();
}

async function shortHash(s) {
  const d = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].slice(0, 9).map((b) => b.toString(16).padStart(2, '0')).join('');
}
const isSeen = async (env, owner, kind, key) =>
  !!(await env.DB.prepare('SELECT 1 x FROM seen WHERE owner=? AND kind=? AND key=?').bind(owner, kind, key).first());
const markSeen = (env, owner, kind, key) =>
  env.DB.prepare('INSERT OR IGNORE INTO seen(owner,kind,key) VALUES(?,?,?)').bind(owner, kind, key).run();

// Classroom gives deadlines in UTC; convert to the owner's local time.
function classroomDue(env, w) {
  const d = w.dueDate;
  if (!d || !d.year) return '';
  const p = (n) => String(n).padStart(2, '0');
  if (!w.dueTime || (w.dueTime.hours == null && w.dueTime.minutes == null)) return `${d.year}-${p(d.month)}-${p(d.day)}T23:59`;
  const utc = new Date(Date.UTC(d.year, d.month - 1, d.day, w.dueTime.hours || 0, w.dueTime.minutes || 0));
  return utc.toLocaleString('sv-SE', { timeZone: env.TIMEZONE || 'Asia/Jerusalem' }).replace(' ', 'T').slice(0, 16);
}

async function syncClassroom(env, owner, force = false) {
  if (!gConfigured(env) || !(await getSetting(env, owner, 'g_refresh'))) return { ok: false, reason: 'not_connected' };
  if (!(await classroomOk(env, owner))) return { ok: false, reason: 'scope' };
  const last = Number(await getSetting(env, owner, 'cr_last')) || 0;
  if (!force && Date.now() - last < 20 * 60000) return { ok: true, skipped: true, added: 0, done: 0 };
  await setSetting(env, owner, 'cr_last', String(Date.now()));
  const now = new Date().toISOString();
  const oldest = new Date(Date.now() - 14 * 86400000).toLocaleDateString('sv-SE', { timeZone: env.TIMEZONE || 'Asia/Jerusalem' });
  let added = 0, done = 0;
  const courses = (await gGet(env, owner, 'https://classroom.googleapis.com/v1/courses?studentId=me&courseStates=ACTIVE&pageSize=30')).courses || [];
  for (const c of courses.slice(0, 15)) {
    const base = `https://classroom.googleapis.com/v1/courses/${encodeURIComponent(c.id)}/courseWork`;
    const works = (await gGet(env, owner, base + '?pageSize=50&orderBy=dueDate%20desc')).courseWork || [];
    const subs = (await gGet(env, owner, base + '/-/studentSubmissions?userId=me&pageSize=100')).studentSubmissions || [];
    const state = {};
    for (const s of subs) state[s.courseWorkId] = s.state;
    for (const w of works) {
      if (!w.dueDate) continue;
      const src = `cr:${c.id}:${w.id}`;
      const turned = state[w.id] === 'TURNED_IN' || state[w.id] === 'RETURNED';
      const ex = await env.DB.prepare('SELECT id,done FROM tasks WHERE owner=? AND src=?').bind(owner, src).first();
      if (ex) {
        if (turned && !ex.done) { await env.DB.prepare('UPDATE tasks SET done=1,updated=? WHERE owner=? AND id=?').bind(now, owner, ex.id).run(); done++; }
        continue;
      }
      if (await isSeen(env, owner, 'cr', src)) continue;
      const due = classroomDue(env, w);
      if (turned || !due || due.slice(0, 10) < oldest) { await markSeen(env, owner, 'cr', src); continue; }
      const soon = new Date(due) - Date.now() < 2 * 86400000;
      await env.DB.prepare(
        `INSERT INTO tasks(owner,id,text,due,dur,snooze,fired,tag,urgent,important,done,src,updated)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).bind(owner, 'cr' + (await shortHash(src)), str(`${w.title} (${c.name})`, 200), due, 15, '', '', 'priv', bit(soon), 1, 0, src, now).run();
      await markSeen(env, owner, 'cr', src);
      added++;
    }
  }
  if (added) await reconcileCalendar(env, owner, 25);
  return { ok: true, added, done };
}

/* Gmail: find order emails and keep a small table of orders (no email bodies are stored). */

const STATUS_RANK = { ordered: 1, shipped: 2, out_for_delivery: 3, ready_for_pickup: 3, delivered: 4, collected: 5, cancelled: 9 };
const STATUS_RULES = [
  ['cancelled', /cancel|refund|בוטל|ביטול הזמנה|זיכוי/i],
  ['collected', /picked up|has been collected|was collected|thank you for (?:picking|collecting)|נאספה|נאסף|נלקחה|נלקח|אישור איסוף|איסוף הושלם|תודה שאספת/i],
  ['delivered', /delivered|נמסר|נמסרה|הגיעה ליעד/i],
  ['ready_for_pickup', /ready for pick-?up|ready to collect|available for pick-?up|מוכנה? לאיסוף|ממתינה? לאיסוף|ניתן לאסוף|הגיעה לנקודת/i],
  ['out_for_delivery', /out for delivery|arriving today|בדרך אליך|יצא(?:ה)? לחלוקה|יצא(?:ה)? למשלוח|שליח בדרך/i],
  ['shipped', /shipped|has shipped|on its way|shipment|tracking|נשלח|נשלחה|יצא(?:ה)? לדרך|מספר מעקב/i],
  ['ordered', /order confirm|thank you for your order|order received|we received your order|order #?\S* confirmed|your order|הזמנה התקבלה|אישור הזמנה|תודה על ההזמנה|ההזמנה שלך|קיבלנו את ההזמנה|הזמנה \S* אושרה|אושרה/i],
];
// The subject decides the status. The preview text is only a fallback, because confirmation emails
// often mention "delivery" in the small print.
function classifyOrder(subject, snippet) {
  const pick = (t) => { for (const [s, re] of STATUS_RULES) if (re.test(t)) return s; return null; };
  return pick(subject) || pick(snippet.slice(0, 200));
}
function shopFrom(from) {
  let n = (/^\s*"?([^"<]+?)"?\s*</.exec(from) || [])[1] || '';
  n = n.replace(/\b(orders?|support|noreply|no-reply|team|customer service|notifications?|shipping|store)\b/gi, '').replace(/[-–|]+\s*$/g, '').trim();
  if (n.length < 2) {
    const dom = (/@([\w.-]+)/.exec(from) || [])[1] || 'Unknown';
    const parts = dom.split('.');
    n = parts.length > 2 ? parts[parts.length - 2] : parts[0];
    n = n.charAt(0).toUpperCase() + n.slice(1);
  }
  return n.slice(0, 60);
}
function orderNo(text) {
  const re = /(?:order|הזמנה|הזמנתך)(?:\s*(?:#|no\.?|number|מספר|:))*\s*#?\s*([A-Z0-9][A-Z0-9-]{2,24})/gi;
  for (const m of text.matchAll(re)) if (/\d/.test(m[1])) return m[1];
  const h = /#\s*([A-Z0-9][A-Z0-9-]{2,24})/i.exec(text);
  return h && /\d/.test(h[1]) ? h[1] : '';
}
function mailText(payload) {
  const parts = [];
  const walk = (p) => {
    if (!p) return;
    if (p.body && p.body.data && /^text\/(plain|html)/.test(p.mimeType || '')) {
      let t = new TextDecoder().decode(b64uToBytes(p.body.data));
      if (p.mimeType === 'text/html') t = t.replace(/<(style|script)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ');
      parts.push(t.replace(/\s+/g, ' ').trim());
    }
    (p.parts || []).forEach(walk);
  };
  walk(payload);
  return parts.join(' ').slice(0, 2500);
}
async function aiItem(env, shop, subject, body) {
  if (!env.AI) return '';
  const models = [...new Set([env.AI_TEXT_MODEL && !RETIRED.test(env.AI_TEXT_MODEL) ? env.AI_TEXT_MODEL : null, ...TEXT_MODELS].filter(Boolean))];
  for (const model of models) {
    try {
      const r = await env.AI.run(model, {
        max_tokens: 60,
        messages: [
          { role: 'system', content: 'You read one order email. Reply with ONLY the name of the main product ordered, under 8 words, in the email language. If unclear reply NONE.' },
          { role: 'user', content: `Shop: ${shop}\nSubject: ${subject}\n${body.slice(0, 1500)}` },
        ],
      });
      const t = aiText(r).split('\n')[0].replace(/^["'\s]+|["'\s.]+$/g, '').slice(0, 80);
      return /^none$/i.test(t) ? '' : t;
    } catch { /* try the next model */ }
  }
  return '';
}

async function checkOrders(env, owner, force = false) {
  if (!gConfigured(env) || !(await getSetting(env, owner, 'g_refresh'))) return { ok: false, reason: 'not_connected' };
  if (!(await mailOk(env, owner))) return { ok: false, reason: 'scope' };
  const last = Number(await getSetting(env, owner, 'ord_last')) || 0;
  if (!force && Date.now() - last < 3 * 3600000) return { ok: true, skipped: true, changed: 0 };
  await setSetting(env, owner, 'ord_last', String(Date.now()));
  const q = 'newer_than:60d {subject:order subject:shipped subject:delivered subject:shipment subject:tracking subject:package subject:הזמנה subject:משלוח subject:נשלח subject:נמסר subject:חבילה}';
  const list = (await gGet(env, owner, 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=50&q=' + encodeURIComponent(q))).messages || [];
  const fresh = [];
  for (const m of list) if (!(await isSeen(env, owner, 'mail', m.id))) fresh.push(m.id);
  let changed = 0, aiBudget = 8;
  const msgs = [];
  for (const id of fresh.slice(0, 25)) {
    const m = await gGet(env, owner, `https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`);
    const h = (n) => ((m.payload?.headers || []).find((x) => x.name.toLowerCase() === n) || {}).value || '';
    msgs.push({ id, sent: (m.labelIds || []).includes('SENT') || (m.labelIds || []).includes('DRAFT'), subject: h('subject'), from: h('from'), date: Number(m.internalDate) || Date.now(), snippet: m.snippet || '', body: mailText(m.payload) });
  }
  msgs.sort((a, b) => a.date - b.date);
  for (const m of msgs) {
    await markSeen(env, owner, 'mail', m.id);
    if (m.sent || /^\s*(re|fwd?|fw|השב|תגובה|הועבר)\s*:/i.test(m.subject)) continue; // your own replies and forwards
    const status = classifyOrder(m.subject, m.snippet);
    if (!status) continue;
    const shop = shopFrom(m.from);
    const no = orderNo(m.subject) || orderNo(m.snippet + ' ' + m.body);
    const placed = new Date(m.date).toISOString();
    let ex = null;
    const open = "status NOT IN ('delivered','collected','cancelled')";
    if (no) {
      ex = await env.DB.prepare('SELECT * FROM orders WHERE owner=? AND shop=? AND order_no=?').bind(owner, shop, no).first();
      // an earlier email of this order had no number: adopt it instead of creating a duplicate
      if (!ex) ex = await env.DB.prepare(`SELECT * FROM orders WHERE owner=? AND shop=? AND order_no='' AND ${open} ORDER BY placed DESC LIMIT 1`).bind(owner, shop).first();
    } else {
      ex = await env.DB.prepare(`SELECT * FROM orders WHERE owner=? AND shop=? AND ${open} ORDER BY placed DESC LIMIT 1`).bind(owner, shop).first();
    }
    if (ex) {
      if ((STATUS_RANK[status] || 0) > (STATUS_RANK[ex.status] || 0) || status === 'cancelled') {
        await env.DB.prepare('UPDATE orders SET status=?,updated=?,msg_id=?,order_no=?,hidden=0 WHERE owner=? AND id=?').bind(status, placed, m.id, ex.order_no || no, owner, ex.id).run();
        changed++;
      } else if (no && !ex.order_no) {
        await env.DB.prepare('UPDATE orders SET order_no=? WHERE owner=? AND id=?').bind(no, owner, ex.id).run();
      }
      continue;
    }
    let item = '';
    if (aiBudget > 0) { aiBudget--; item = await aiItem(env, shop, m.subject, m.body); }
    if (!item) item = str(m.subject, 80);
    await env.DB.prepare(
      'INSERT INTO orders(owner,id,shop,item,order_no,status,placed,updated,msg_id,hidden) VALUES(?,?,?,?,?,?,?,?,?,0)'
    ).bind(owner, 'o' + (await shortHash(m.id)), shop, item, no, status, placed, placed, m.id).run();
    changed++;
  }
  return { ok: true, changed, scanned: msgs.length };
}

async function listOrders(env, owner) {
  const r = await env.DB.prepare(
    'SELECT id,shop,item,order_no,status,placed,updated,msg_id FROM orders WHERE owner=? AND hidden=0 ORDER BY updated DESC LIMIT 100'
  ).bind(owner).all();
  return r.results;
}

// Called on every state load: refreshes Classroom (every 20 min) and orders (every 3 h) in the background.
async function autoRefresh(env, owner) {
  try { await syncClassroom(env, owner); } catch (e) { console.error('classroom', e && e.message); }
  try { await checkOrders(env, owner); } catch (e) { console.error('orders', e && e.message); }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!(env.TEAM_DOMAIN && env.ACCESS_AUD) && pwMode(env)) {
      if (url.pathname === '/login' && req.method === 'GET') {
        return new Response(LOGIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
      }
      if (url.pathname === '/api/login' && req.method === 'POST') return handleLogin(req, env);
      if (url.pathname === '/api/logout') {
        return new Response(null, { status: 302, headers: { location: '/login', 'set-cookie': 'amitis_s=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' } });
      }
    }
    const auth = await authenticate(req, env, url);
    if (auth instanceof Response) return auth;
    const owner = auth;

    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);

    try {
      const route = `${req.method} ${url.pathname}`;
      switch (route) {
        case 'GET /api/config': {
          const connected = !!(await getSetting(env, owner, 'g_refresh'));
          return json({
            ai: aiEnabled(env), gcal: gConfigured(env), gconnected: connected, tz: env.TIMEZONE || 'Asia/Jerusalem',
            classroom: connected && (await classroomOk(env, owner)), mail: connected && (await mailOk(env, owner)),
          });
        }
        case 'GET /api/state': {
          const st = await getState(env, owner);
          if (st.tasks.some((t) => t.due && !t.done && !t.gcal)) await background(ctx, reconcileCalendar(env, owner));
          await background(ctx, autoRefresh(env, owner));
          return json(st);
        }
        case 'POST /api/sync': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          const res = await applySync(env, owner, b || {});
          return json({ ok: true, n: res.n, gcal: res.gcal });
        }
        case 'POST /api/ai':
          return await handleAi(req, env);
        case 'GET /api/google/connect':
          return await googleConnect(req, env, url);
        case 'GET /api/google/callback': {
          const resp = await googleCallback(req, env, url, owner);
          await background(ctx, reconcileCalendar(env, owner, 25));
          return resp;
        }
        case 'POST /api/classroom/sync': {
          try { return json(await syncClassroom(env, owner, true)); } catch (e) {
            return fail(e.message === 'needs_reauth' ? 401 : 502, 'Classroom error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40));
          }
        }
        case 'GET /api/orders':
          return json({ orders: await listOrders(env, owner), mail: !!(await getSetting(env, owner, 'g_refresh')) && (await mailOk(env, owner)) });
        case 'POST /api/orders/check': {
          let res;
          try { res = await checkOrders(env, owner, true); } catch (e) {
            return fail(e.message === 'needs_reauth' ? 401 : 502, 'Gmail error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40));
          }
          return json({ ...res, orders: await listOrders(env, owner) });
        }
        case 'POST /api/orders/hide': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          if (RE_ID.test(String(b?.id))) await env.DB.prepare('UPDATE orders SET hidden=1 WHERE owner=? AND id=?').bind(owner, String(b.id)).run();
          return json({ ok: true });
        }
        case 'GET /api/gcal/events':
          return await gcalList(env, owner, url);
        case 'POST /api/gcal/events':
          return await gcalCreate(req, env, owner);
        default:
          return fail(404, 'Not found', 'not_found');
      }
    } catch (e) {
      console.error('api error', e && e.message);
      return fail(500, 'Server error', 'server');
    }
  },
};
