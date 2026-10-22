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
const RECS = ['', 'daily', 'weekdays', 'weekly', 'monthly'];
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
  const [t, f, m, goal, wk, wt, burn, wmins, sh, qt, rc] = await Promise.all([
    env.DB.prepare('SELECT id,text,due,dur,snooze,fired,tag,urgent,important,done,rec,gcal_id FROM tasks WHERE owner=?').bind(owner).all(),
    env.DB.prepare('SELECT id,day,slot,name,kcal,p,c,f FROM food WHERE owner=? AND day>=?').bind(owner, cutoff).all(),
    env.DB.prepare('SELECT id,name,servings,ing FROM meals WHERE owner=?').bind(owner).all(),
    getSetting(env, owner, 'goal'),
    env.DB.prepare('SELECT id,day,kind,mins,kcal FROM workouts WHERE owner=? AND day>=?').bind(owner, cutoff).all(),
    env.DB.prepare('SELECT id,day,kg FROM weights WHERE owner=?').bind(owner).all(),
    getSetting(env, owner, 'burn'),
    getSetting(env, owner, 'wmins'),
    env.DB.prepare('SELECT id,name,done,rid,rname FROM shop WHERE owner=?').bind(owner).all(),
    env.DB.prepare('SELECT id,text,author FROM quotes WHERE owner=? ORDER BY added').bind(owner).all(),
    env.DB.prepare('SELECT id,title,source,servings,ing,steps,notes,img,cat FROM recipes WHERE owner=? ORDER BY added').bind(owner).all(),
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
    work: wk.results,
    weights: wt.results,
    shop: sh.results.map((r) => ({ id: r.id, name: r.name, done: !!r.done, rid: r.rid || '', rname: r.rname || '' })),
    quotes: qt.results,
    recipes: rc.results.map((r) => {
      const j = (t) => { try { const a = JSON.parse(t); return Array.isArray(a) ? a : []; } catch { return []; } };
      return { ...r, ing: j(r.ing), steps: j(r.steps) };
    }),
    burn: Number(burn) > 0 ? Number(burn) : 300,
    wmins: Number(wmins) > 0 ? Number(wmins) : 30,
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
        `INSERT INTO tasks(owner,id,text,due,dur,snooze,fired,tag,urgent,important,done,rec,updated)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET text=excluded.text,due=excluded.due,dur=excluded.dur,snooze=excluded.snooze,
           fired=excluded.fired,tag=excluded.tag,urgent=excluded.urgent,important=excluded.important,done=excluded.done,
           rec=excluded.rec,updated=excluded.updated`
      ).bind(
        owner, String(t.id), text, dt(t.due), Math.round(num(t.dur, 5, 1440, 30)), dt(t.snooze), dt(t.fired),
        TAGS.includes(t.tag) ? t.tag : 'priv', bit(t.urgent), bit(t.important), bit(t.done), RECS.includes(t.rec) ? t.rec : '', now
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

  for (const e of list(b.shop?.upsert)) {
    if (!e || !RE_ID.test(String(e.id))) continue;
    const name = str(e.name, 120).trim();
    if (!name) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO shop(owner,id,name,done,added,rid,rname) VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET name=excluded.name,done=excluded.done,rid=excluded.rid,rname=excluded.rname`
      ).bind(owner, String(e.id), name, bit(e.done), now, RE_ID.test(String(e.rid || '')) ? String(e.rid) : '', str(e.rname, 160))
    );
  }
  for (const id of list(b.shop?.del)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM shop WHERE owner=? AND id=?').bind(owner, String(id)));
  }
  for (const e of list(b.recipes?.upsert, 100)) {
    if (!e || !RE_ID.test(String(e.id))) continue;
    const title = str(e.title, 160).trim();
    if (!title) continue;
    const arr = (x, n, len) => (Array.isArray(x) ? x : []).slice(0, n).map((t) => str(t, len).trim()).filter(Boolean);
    stmts.push(
      db.prepare(
        `INSERT INTO recipes(owner,id,title,source,servings,ing,steps,notes,img,added,cat) VALUES(?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET title=excluded.title,source=excluded.source,servings=excluded.servings,ing=excluded.ing,steps=excluded.steps,notes=excluded.notes,img=excluded.img,cat=excluded.cat`
      ).bind(owner, String(e.id), title, str(e.source, 500), str(e.servings, 40), JSON.stringify(arr(e.ing, 100, 200)), JSON.stringify(arr(e.steps, 80, 1200)), str(e.notes, 1500), /^https:\/\//.test(String(e.img)) ? str(e.img, 600) : '', now, str(e.cat, 30).trim())
    );
  }
  for (const id of list(b.recipes?.del, 100)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM recipes WHERE owner=? AND id=?').bind(owner, String(id)));
  }
  for (const e of list(b.quotes?.upsert)) {
    if (!e || !RE_ID.test(String(e.id))) continue;
    const text = str(e.text, 1000).trim();
    if (!text) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO quotes(owner,id,text,author,added) VALUES(?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET text=excluded.text,author=excluded.author`
      ).bind(owner, String(e.id), text, str(e.author, 120).trim(), now)
    );
  }
  for (const id of list(b.quotes?.del)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM quotes WHERE owner=? AND id=?').bind(owner, String(id)));
  }
  for (const e of list(b.work?.upsert)) {
    if (!e || !RE_ID.test(String(e.id)) || !RE_DAY.test(String(e.day))) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO workouts(owner,id,day,kind,mins,kcal) VALUES(?,?,?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET day=excluded.day,kind=excluded.kind,mins=excluded.mins,kcal=excluded.kcal`
      ).bind(owner, String(e.id), e.day, str(e.kind, 80) || 'Workout', Math.round(num(e.mins, 0, 1440, 0)), Math.round(num(e.kcal, 0, 20000, 0)))
    );
  }
  for (const id of list(b.work?.del)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM workouts WHERE owner=? AND id=?').bind(owner, String(id)));
  }
  for (const e of list(b.weights?.upsert)) {
    if (!e || !RE_ID.test(String(e.id)) || !RE_DAY.test(String(e.day))) continue;
    const kg = num(e.kg, 20, 500, 0);
    if (!kg) continue;
    stmts.push(
      db.prepare(
        `INSERT INTO weights(owner,id,day,kg) VALUES(?,?,?,?)
         ON CONFLICT(owner,id) DO UPDATE SET day=excluded.day,kg=excluded.kg`
      ).bind(owner, String(e.id), e.day, Math.round(kg * 10) / 10)
    );
  }
  for (const id of list(b.weights?.del)) {
    if (RE_ID.test(String(id))) stmts.push(db.prepare('DELETE FROM weights WHERE owner=? AND id=?').bind(owner, String(id)));
  }
  for (const [k, lo, hi] of [['burn', 0, 5000], ['wmins', 0, 600]]) {
    if (b[k] !== undefined) {
      stmts.push(
        db.prepare('INSERT INTO settings(owner,key,value) VALUES(?,?,?) ON CONFLICT(owner,key) DO UPDATE SET value=excluded.value')
          .bind(owner, k, String(Math.round(num(b[k], lo, hi, k === 'burn' ? 300 : 30))))
      );
    }
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

const aiEnabled = (env) => !!(env.ANTHROPIC_API_KEY || env.GEMINI_API_KEY || env.AI);

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
  if (env.ANTHROPIC_API_KEY) return aiClaude(env, merged, images);
  if (env.GEMINI_API_KEY) {
    const errs = [];
    const g = await aiGemini(env, merged, images, errs);
    if (g) return g;
    if (!env.AI) return json({ error: 'AI request failed', code: 'upstream_error', detail: errs.join(' | ').slice(0, 300) }, 502);
    const w = await aiWorkers(env, merged, images);
    if (w.status === 502) { const j = await w.json().catch(() => ({})); return json({ ...j, detail: ('gemini: ' + errs.join(' | ') + ' || ' + (j.detail || '')).slice(0, 400) }, 502); }
    return w;
  }
  const w = await aiWorkers(env, merged, images);
  if (w.status === 502) { const j = await w.json().catch(() => ({})); return json({ ...j, detail: ('GEMINI_API_KEY not found by the site || ' + (j.detail || '')).slice(0, 400) }, 502); }
  return w;
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

// Free option: Google Gemini API (free tier of Google AI Studio, no card). Returns null when it fails so Workers AI can take over.
async function aiGemini(env, merged, images, errs = []) {
  const contents = merged.map((m, i) => {
    const parts = [{ text: m.content }];
    if (i === merged.length - 1) for (const im of images) parts.push({ inline_data: { mime_type: im.media_type, data: im.data } });
    return { role: m.role === 'assistant' ? 'model' : 'user', parts };
  });
  const models = [...new Set([env.GEMINI_MODEL, 'gemini-2.5-flash', 'gemini-2.0-flash'].filter(Boolean))];
  for (const model of models) {
    try {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST',
        headers: { 'x-goog-api-key': env.GEMINI_API_KEY, 'content-type': 'application/json' },
        body: JSON.stringify({ contents, generationConfig: { maxOutputTokens: 4096, temperature: 0.3 } }),
      });
      if (!r.ok) {
        const eb = await r.json().catch(() => ({}));
        errs.push(model + ' ' + r.status + ' ' + String(eb?.error?.message || eb?.error?.status || '').replace(/\s+/g, ' ').slice(0, 90));
        console.error('gemini error', model, r.status);
        continue;
      }
      const j = await r.json();
      const text = (j.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('').trim();
      if (text) return json({ text, truncated: j.candidates?.[0]?.finishReason === 'MAX_TOKENS' });
      errs.push(model + ' empty ' + (j.promptFeedback?.blockReason || j.candidates?.[0]?.finishReason || ''));
    } catch (e) {
      errs.push(model + ' ' + String(e && e.message || e).slice(0, 50)); console.error('gemini fetch failed', model, String(e && e.message || e).slice(0, 80)); }
  }
  return null;
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
        input = { messages: msgs, max_tokens: 3000 };
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
  mailMod: GA + 'gmail.modify',
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
const mailOk = async (env, owner) => (await hasScope(env, owner, SC.mail)) || (await hasScope(env, owner, SC.mailMod));
const mailModOk = (env, owner) => hasScope(env, owner, SC.mailMod);

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
  const newTasks = [];
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
      newTasks.push({ text: str(`${w.title} (${c.name})`, 120), due });
    }
  }
  if (added) await reconcileCalendar(env, owner, 25);
  return { ok: true, added, done, newTasks };
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
  const updates = [];
  const recent = Date.now() - 2 * 86400000;
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
        if (m.date > recent) updates.push({ shop, item: ex.item, status });
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
    if (m.date > recent) updates.push({ shop, item, status });
  }
  return { ok: true, changed, scanned: msgs.length, updates };
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



/* ---------- Inbox: sorts Gmail into folders inside the app (read-only, Gmail itself is never changed) ---------- */

const MAIL_FOLDERS = ['trips', 'college', 'money', 'shopping', 'health', 'people', 'promos', 'other'];
const RX = {
  college: /colman\.ac\.il|המכללה למנהל|מכללה למנהל|\bcolman\b/i,
  tripStrong: /(itinerary|e-?ticket|boarding pass|(booking|reservation|flight|trip|stay|hotel).{0,30}confirm|confirm.{0,30}(booking|reservation|flight|trip|stay)|your (flight|booking|reservation|trip|stay)|אישור (הזמנה|טיסה|הזמנת)|כרטיס טיסה|פרטי (הטיסה|ההזמנה)|טיסתך|הזמנתך ב)/i,
  trips: /\b(flights?|airlines?|airport|visa|passport|vacation|travel|tripadvisor|skyscanner|kayak|trivago|hotels\.com|hostelworld|getyourguide|klook|lufthansa|turkish airlines|pegasus|aegean|wizz|ryanair|easyjet|vueling|etihad|emirates|qatar airways|boarding pass|itinerary|e-?ticket|airbnb|booking\.com|hotels?|hostel|expedia|agoda|ryanair|wizz ?air|easyjet|el al|israir|arkia|check-?in|reservation confirm|car rental)\b|טיסה|טיסות|כרטיס טיסה|מלון|חופשה|חופשת|נופש|חו"ל|חול|נסיעה|דרכון|שדה התעופה|נחיתה|ביטוח נסיעות|השכרת רכב|סוכנות נסיעות|אל על|ישראייר|ארקיע|הזמנת מלון|טיול|העברה לשדה/i,
  shopping: /aliexpress|shein|amazon|temu|ebay|zara|asos|iherb|\bksp\b|ivory|wolt|10bis|your order|הזמנה|משלוח|חבילה/i,
  money: /invoice|receipt|payment|billing|חשבונית|קבלה|חיוב|תשלום|ויזה|כאל|ישראכרט|\bmax\b|\bbank\b|בנק|paypal|ביטוח לאומי|מס הכנסה|ארנונה|חשמל|bill\b/i,
  health: /clalit|maccabi|meuhedet|leumit|כללית|מכבי|מאוחדת|לאומית|קופת חולים|תור לרופא|בדיקת דם|רופא/i,
  important: /דחוף|\burgent\b|final notice|payment (?:due|failed)|overdue|past due|חיוב נכשל|מועד אחרון|תזכורת תשלום|בחינה|מבחן|\bexam\b|deadline|boarding pass|טיסה.{0,20}(?:מחר|היום)|security alert|פג תוקף|expires? (?:today|tomorrow|soon)/i,
};
function ruleFolder(m) {
  const t = `${m.sender} ${m.addr} ${m.subject} ${m.snippet}`;
  const promo = m.labels.some((l) => /CATEGORY_(PROMOTIONS|SOCIAL|FORUMS)/.test(l));
  if (RX.college.test(t)) return 'college';
  if (RX.tripStrong.test(`${m.sender} ${m.subject}`) && RX.trips.test(t)) return 'trips';
  if (promo) return 'promos';
  if (RX.trips.test(t)) return 'trips';
  if (classifyOrder(m.subject, m.snippet) || RX.shopping.test(`${m.sender} ${m.addr} ${m.subject}`)) return 'shopping';
  if (RX.health.test(t)) return 'health';
  if (RX.money.test(t)) return 'money';
  return '';
}

async function aiJsonList(env, system, user) {
  if (!env.AI) return null;
  const models = [...new Set([env.AI_TEXT_MODEL && !RETIRED.test(env.AI_TEXT_MODEL) ? env.AI_TEXT_MODEL : null, ...TEXT_MODELS].filter(Boolean))];
  for (const model of models) {
    try {
      const text = aiText(await env.AI.run(model, { max_tokens: 1200, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] }));
      const a = text.indexOf('['), z = text.lastIndexOf(']');
      if (a >= 0 && z > a) { const j = JSON.parse(text.slice(a, z + 1)); if (Array.isArray(j)) return j; }
    } catch (e) {
      const msg = String((e && e.message) || e);
      if (/limit|quota|neuron|429|capacity/i.test(msg) && !/not found|deprecat|no such model/i.test(msg)) return 'limit';
    }
  }
  return null;
}

async function aiSortMails(env, owner, rows, tripNames) {
  const lines = rows.map((r, i) => `${i}. From: ${r.sender || r.addr} | Subject: ${r.subject} | ${r.snippet.slice(0, 140)}`).join('\n');
  const out = await aiJsonList(env,
    'You sort one person\'s emails into folders. Folders: trips (flights, hotels, bookings, anything about a holiday), college (anything from or about her college, "המכללה למנהל": classes, exams, grades, tuition, registration), money (bills, banks, invoices, taxes), shopping (orders, deliveries, shops), health (clinics, appointments), people (a real person writing personally), promos (marketing, newsletters), other. For trips also give "trip": a short holiday name such as "Japan 2026" (destination + year), reusing one of the existing names when it is the same holiday: [' + tripNames.map((n) => JSON.stringify(n)).join(', ') + ']. Give "important": true ONLY if it needs her attention soon (a bill due, an exam or class change, a flight soon, a security alert, a deadline). Reply with ONLY a JSON array like [{"i":0,"folder":"money","trip":"","important":false}], one entry per email.',
    lines);
  if (out === 'limit' || !out) return out;
  const upd = [];
  for (const o of out) {
    const r = rows[Number(o && o.i)];
    if (!r) continue;
    const folder = MAIL_FOLDERS.includes(o.folder) ? o.folder : 'other';
    const trip = folder === 'trips' ? str(o.trip, 60).trim() : '';
    upd.push(env.DB.prepare('UPDATE mails SET folder=?,trip=?,important=?,gsync=0 WHERE owner=? AND id=? AND fixed=0').bind(folder, trip, folder === 'promos' ? 0 : (o.important === true || r.important ? 1 : 0), owner, r.id));
  }
  if (upd.length) await env.DB.batch(upd);
  return upd.length;
}

const hdr = (m, n) => ((m.payload?.headers || []).find((x) => x.name.toLowerCase() === n) || {}).value || '';
function parseFrom(f) {
  const nm = (/^\s*"?([^"<]*?)"?\s*</.exec(f) || [])[1] || '';
  const addr = (/<([^>]+)>/.exec(f) || /([^\s<>]+@[^\s<>]+)/.exec(f) || [])[1] || '';
  return { sender: nm.trim().slice(0, 80), addr: addr.slice(0, 120) };
}

// One step of the scan. Phases run in order: trips (whole mailbox), college (whole mailbox), then everything else.
// bulk=true is the app driving it (bigger steps); otherwise it is the background timer (small steps).
const SCAN_PHASES = [
  'subject:(flight OR itinerary OR "boarding pass" OR hotel OR booking OR reservation OR airbnb OR airline OR טיסה OR מלון OR חופשה OR טיול OR "חו\\"ל" OR נסיעה OR visa OR vacation OR trip OR travel) -in:sent -in:drafts -in:chats',
  '(from:colman.ac.il OR "המכללה למנהל" OR "college of management") -in:sent -in:drafts -in:chats',
  '-in:sent -in:drafts -in:chats',
];
async function scanInbox(env, owner, opts = {}) {
  if (!gConfigured(env) || !(await getSetting(env, owner, 'g_refresh'))) return { ok: false, reason: 'not_connected' };
  if (!(await mailOk(env, owner))) return { ok: false, reason: 'scope' };
  const base = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';
  const step = opts.bulk ? 38 : 12;
  const ids = [];
  const addList = async (q, max, page) => {
    const r = await gGet(env, owner, `${base}?maxResults=${max}&q=${encodeURIComponent(q)}${page ? '&pageToken=' + encodeURIComponent(page) : ''}`);
    (r.messages || []).forEach((m) => ids.push(m.id));
    return r.nextPageToken || '';
  };
  if (!opts.bulk) await addList('newer_than:3d -in:sent -in:drafts -in:chats', 12);
  let phase = -1;
  for (let i = 0; i < SCAN_PHASES.length; i++) if ((await getSetting(env, owner, 'sp_d' + i)) !== '1') { phase = i; break; }
  const done0 = phase < 0;
  if (!done0) {
    const page = (await getSetting(env, owner, 'sp_p' + phase)) || '';
    const next = await addList(SCAN_PHASES[phase], step, page);
    if (next) await setSetting(env, owner, 'sp_p' + phase, next);
    else await setSetting(env, owner, 'sp_d' + phase, '1');
  }
  const uniq = [...new Set(ids)];
  let fresh = uniq;
  if (uniq.length) {
    const have = new Set((await env.DB.prepare(`SELECT id FROM mails WHERE owner=? AND id IN (${uniq.map(() => '?').join(',')})`).bind(owner, ...uniq).all()).results.map((r) => r.id));
    fresh = uniq.filter((i) => !have.has(i));
  }
  const rules = new Map((await env.DB.prepare('SELECT addr,folder,trip FROM mail_rules WHERE owner=?').bind(owner).all()).results.map((r) => [r.addr.toLowerCase(), r]));
  const ins = [];
  const take = fresh.slice(0, opts.bulk ? 40 : 14);
  for (let i = 0; i < take.length; i += 10) {
    const got = await Promise.all(take.slice(i, i + 10).map(async (id) => {
      try { return [id, await gGet(env, owner, `${base}/${id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=List-Unsubscribe`)]; } catch (e) { if (e.message === 'needs_reauth') throw e; return null; }
    }));
    for (const g of got) {
      if (!g) continue;
      const [id, m] = g;
      const labels = m.labelIds || [];
      if (labels.includes('SENT') || labels.includes('DRAFT')) continue;
      const f = parseFrom(hdr(m, 'from'));
      const row = { id, thread: m.threadId || id, ...f, subject: str(hdr(m, 'subject'), 200), date: Number(m.internalDate) || Date.now(), snippet: str(m.snippet, 240), labels };
      const learned = rules.get(row.addr.toLowerCase());
      row.folder = learned ? learned.folder : ruleFolder(row);
      row.important = row.folder !== 'promos' && RX.important.test(`${row.subject} ${row.snippet}`) ? 1 : 0;
      const gpromo = !learned && labels.some((l) => /CATEGORY_(PROMOTIONS|SOCIAL|FORUMS)/.test(l)) && row.folder === 'promos' ? 1 : 0;
      const um = /<(https?:[^>]+)>/.exec(hdr(m, 'list-unsubscribe')) || /<(mailto:[^>]+)>/.exec(hdr(m, 'list-unsubscribe'));
      ins.push(env.DB.prepare('INSERT OR IGNORE INTO mails(owner,id,thread,sender,addr,subject,date,snippet,folder,trip,important,pushed,fixed,gpromo,unsub) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)')
        .bind(owner, id, row.thread, row.sender, row.addr, row.subject, row.date, row.snippet, row.folder, learned ? learned.trip : '', row.important, learned ? 1 : 0, gpromo, um ? um[1].slice(0, 400) : ''));
    }
  }
  if (ins.length) await env.DB.batch(ins);
  // let the AI sort what the rules could not (and name the holidays); retried later if it is rate limited
  let ai = 0, limited = false;
  if (!opts.noAi && env.AI) {
    const pend = (await env.DB.prepare("SELECT id,sender,addr,subject,snippet,important FROM mails WHERE owner=? AND fixed=0 AND deleted=0 AND (folder='' OR (folder='trips' AND trip='')) ORDER BY date DESC LIMIT 12").bind(owner).all()).results;
    if (pend.length) {
      const names = (await env.DB.prepare("SELECT DISTINCT trip FROM mails WHERE owner=? AND trip<>'' LIMIT 20").bind(owner).all()).results.map((r) => r.trip);
      const r = await aiSortMails(env, owner, pend, names);
      if (r === 'limit') limited = true; else if (typeof r === 'number') ai = r;
    }
  }
  const total = (await env.DB.prepare('SELECT COUNT(*) n FROM mails WHERE owner=?').bind(owner).first()).n;
  return { ok: true, added: ins.length, ai, limited, done: done0 || phase === SCAN_PHASES.length - 1 && (await getSetting(env, owner, 'sp_d' + phase)) === '1', phase, total };
}

// One morning push (08:00) with what needs attention, instead of a ping per mail.
async function mailDigest(env, owner) {
  const stamp = localStamp(env), day = stamp.slice(0, 10);
  if (Number(stamp.slice(11, 13)) < 8 || (await getSetting(env, owner, 'digest_day')) === day) return false;
  if (!(await pushCount(env, owner))) return false;
  const since = Date.now() - 3 * 86400000;
  const rows = (await env.DB.prepare('SELECT sender,subject FROM mails WHERE owner=? AND important=1 AND hidden=0 AND deleted=0 AND date>=? ORDER BY date DESC LIMIT 20').bind(owner, since).all()).results;
  if (!rows.length) { await setSetting(env, owner, 'digest_day', day); return false; }
  const top = rows.slice(0, 3).map((r) => (r.sender ? r.sender + ': ' : '') + r.subject).join(' · ');
  const ok = await sendPush(env, owner, { title: `📧 ${rows.length} important mail${rows.length > 1 ? 's' : ''}`, body: top, url: '/#inbox', tag: 'maildigest' });
  if (ok) await setSetting(env, owner, 'digest_day', day);
  return ok;
}

async function listInbox(env, owner, folder, trip, q = '', days = 0) {
  const live = 'hidden=0 AND deleted=0';
  const counts = {};
  (await env.DB.prepare(`SELECT CASE WHEN folder='' THEN 'unsorted' ELSE folder END f, COUNT(*) n FROM mails WHERE owner=? AND ${live} GROUP BY f`).bind(owner).all()).results.forEach((r) => { counts[r.f] = r.n; });
  const trips = (await env.DB.prepare(`SELECT trip, COUNT(*) n, MAX(date) d FROM mails WHERE owner=? AND folder='trips' AND ${live} GROUP BY trip ORDER BY d DESC`).bind(owner).all()).results;
  const since = Date.now() - 14 * 86400000;
  let where = `owner=? AND ${live}`, args = [owner];
  if (folder === 'deleted') where = 'owner=? AND deleted>=1';
  else if (folder === 'important') { where += ' AND important=1 AND date>=?'; args.push(since); }
  else if (folder === 'unsorted') where += " AND folder=''";
  else if (MAIL_FOLDERS.includes(folder)) { where += ' AND folder=?'; args.push(folder); if (folder === 'trips' && trip !== undefined && trip !== null) { where += ' AND trip=?'; args.push(String(trip)); } }
  const qq = String(q || '').trim().slice(0, 60);
  if (qq) {
    const like = '%' + qq.replace(/[%_\\]/g, (c) => '\\' + c) + '%';
    where += " AND (subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\' OR addr LIKE ? ESCAPE '\\' OR snippet LIKE ? ESCAPE '\\')";
    args.push(like, like, like, like);
  }
  if (days > 0) { where += ' AND date>=?'; args.push(Date.now() - days * 86400000); }
  const mails = (await env.DB.prepare(`SELECT id,thread,sender,addr,subject,date,snippet,folder,trip,important,unsub FROM mails WHERE ${where} ORDER BY date DESC LIMIT 120`).bind(...args).all()).results;
  const imp = (await env.DB.prepare(`SELECT COUNT(*) n FROM mails WHERE owner=? AND important=1 AND ${live} AND date>=?`).bind(owner, since).first()).n;
  const del = (await env.DB.prepare('SELECT COUNT(*) n FROM mails WHERE owner=? AND deleted>=1').bind(owner).first()).n;
  let tripInfo = null;
  if (folder === 'trips' && trip !== undefined && trip !== null) {
    const t = await env.DB.prepare(`SELECT MIN(date) a, MAX(date) b, COUNT(*) n FROM mails WHERE owner=? AND folder='trips' AND trip=? AND ${live}`).bind(owner, String(trip)).first();
    const senders = (await env.DB.prepare(`SELECT CASE WHEN sender<>'' THEN sender ELSE addr END s, COUNT(*) n FROM mails WHERE owner=? AND folder='trips' AND trip=? AND ${live} GROUP BY s ORDER BY n DESC LIMIT 4`).bind(owner, String(trip)).all()).results.map((r) => r.s);
    tripInfo = { from: t.a, to: t.b, n: t.n, senders };
  }
  return { counts, trips, mails, important: imp, deleted: del, tripInfo, done: (await getSetting(env, owner, 'inbox_done')) === '1' };
}

/* ---------- Inbox write-back: Gmail labels, archive, trash (needs the gmail.modify permission) ---------- */

async function gSend(env, owner, url, body) {
  const token = await googleToken(env, owner);
  if (!token) throw new Error('not_connected');
  const r = await fetch(url, { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 401) { await delSetting(env, owner, 'g_access'); throw new Error('needs_reauth'); }
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    const why = String(j?.error?.status || j?.error?.errors?.[0]?.reason || '').toLowerCase().replace(/[^a-z_]/g, '');
    throw new Error('google_' + r.status + (why ? '_' + why : ''));
  }
  return r.status === 204 ? {} : r.json().catch(() => ({}));
}

const LABEL_NAMES = { trips: 'Trips', college: 'המכללה למנהל', money: 'Money', shopping: 'Shopping', health: 'Health', people: 'People', other: 'Other', promos: 'Promos' };
const labelFor = (m) => 'Amiti/' + (m.folder === 'trips' ? 'Trips/' + (m.trip || 'Unnamed') : LABEL_NAMES[m.folder] || 'Other');

async function gmailLabelMap(env, owner, need) {
  let map = {};
  try { map = JSON.parse((await getSetting(env, owner, 'gl_map')) || '{}'); } catch { map = {}; }
  const missing = need.filter((n) => !map[n]);
  if (!missing.length) return map;
  const have = (await gGet(env, owner, 'https://gmail.googleapis.com/gmail/v1/users/me/labels')).labels || [];
  for (const l of have) if (l.name && l.name.startsWith('Amiti')) map[l.name] = l.id;
  for (const n of missing) {
    if (map[n]) continue;
    const c = await gSend(env, owner, 'https://gmail.googleapis.com/gmail/v1/users/me/labels', { name: n, labelListVisibility: 'labelShow', messageListVisibility: 'show' });
    if (c.id) map[n] = c.id;
  }
  await setSetting(env, owner, 'gl_map', JSON.stringify(map));
  return map;
}

// Mirrors the folders into Gmail as labels (and archives them out of the inbox), and moves Promotions to the Trash.
async function syncGmail(env, owner, opts = {}) {
  if (!(await mailModOk(env, owner))) return { ok: false, reason: 'scope_modify' };
  const base = 'https://gmail.googleapis.com/gmail/v1/users/me/messages';
  let trashed = 0, labelled = 0;
  const queued = (await env.DB.prepare('SELECT id FROM mails WHERE owner=? AND deleted=2 LIMIT 300').bind(owner).all()).results.map((r) => r.id);
  if (queued.length) {
    await gSend(env, owner, base + '/batchModify', { ids: queued, addLabelIds: ['TRASH'], removeLabelIds: ['INBOX'] });
    await env.DB.prepare(`UPDATE mails SET deleted=1 WHERE owner=? AND id IN (${queued.map(() => '?').join(',')})`).bind(owner, ...queued).run();
    trashed += queued.length;
  }
  // never trash something that looks like a booking confirmation or college mail, even if Gmail called it a promotion
  const cand = (await env.DB.prepare("SELECT id,sender,addr,subject,snippet FROM mails WHERE owner=? AND folder='promos' AND gpromo=1 AND fixed=0 AND deleted=0 LIMIT 300").bind(owner).all()).results;
  const promos = [], rescue = [];
  for (const c of cand) {
    const t = `${c.sender} ${c.addr} ${c.subject} ${c.snippet}`;
    if (RX.college.test(t)) rescue.push(['college', c.id]);
    else if (RX.tripStrong.test(`${c.sender} ${c.subject}`) && RX.trips.test(t)) rescue.push(['trips', c.id]);
    else promos.push(c.id);
  }
  if (rescue.length) await env.DB.batch(rescue.map(([f, id]) => env.DB.prepare("UPDATE mails SET folder=?,gpromo=0,gsync=0 WHERE owner=? AND id=?").bind(f, owner, id)));
  if (promos.length) {
    await gSend(env, owner, base + '/batchModify', { ids: promos, addLabelIds: ['TRASH'], removeLabelIds: ['INBOX'] });
    await env.DB.prepare(`UPDATE mails SET deleted=1 WHERE owner=? AND id IN (${promos.map(() => '?').join(',')})`).bind(owner, ...promos).run();
    trashed += promos.length;
  }
  const rows = (await env.DB.prepare("SELECT id,folder,trip,important,glabel FROM mails WHERE owner=? AND gsync=0 AND deleted=0 AND folder<>'' ORDER BY date DESC LIMIT ?").bind(owner, opts.limit || 300).all()).results;
  if (rows.length) {
    const groups = new Map();
    for (const r of rows) {
      const name = labelFor(r), key = `${r.glabel}|${name}|${r.important ? 1 : 0}`;
      if (!groups.has(key)) groups.set(key, { name, old: r.glabel, keep: !!r.important, ids: [] });
      groups.get(key).ids.push(r.id);
    }
    const list = [...groups.values()].slice(0, 8);
    const map = await gmailLabelMap(env, owner, [...new Set(list.flatMap((g) => [g.name]))]);
    for (const g of list) {
      const add = map[g.name];
      if (!add) continue;
      const rem = [];
      if (!g.keep) rem.push('INBOX');
      if (g.old && map[g.old] && g.old !== g.name) rem.push(map[g.old]);
      await gSend(env, owner, base + '/batchModify', { ids: g.ids, addLabelIds: [add], removeLabelIds: rem });
      await env.DB.prepare(`UPDATE mails SET glabel=?,gsync=1 WHERE owner=? AND id IN (${g.ids.map(() => '?').join(',')})`).bind(g.name, owner, ...g.ids).run();
      labelled += g.ids.length;
    }
  }
  return { ok: true, trashed, labelled, more: rows.length >= (opts.limit || 300) };
}

async function trashMail(env, owner, id) {
  // Without the Gmail permission yet, hide it here and trash it in Gmail as soon as the permission is granted.
  if (!(await mailModOk(env, owner))) {
    await env.DB.prepare('UPDATE mails SET deleted=2 WHERE owner=? AND id=?').bind(owner, id).run();
    return { ok: true, pending: true };
  }
  await gSend(env, owner, `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}/trash`);
  await env.DB.prepare('UPDATE mails SET deleted=1 WHERE owner=? AND id=?').bind(owner, id).run();
  return { ok: true };
}

async function trashMails(env, owner, ids) {
  if (!ids.length) return { ok: true, n: 0 };
  const ph = ids.map(() => '?').join(',');
  if (!(await mailModOk(env, owner))) {
    await env.DB.prepare(`UPDATE mails SET deleted=2 WHERE owner=? AND id IN (${ph})`).bind(owner, ...ids).run();
    return { ok: true, n: ids.length, pending: true };
  }
  await gSend(env, owner, 'https://gmail.googleapis.com/gmail/v1/users/me/messages/batchModify', { ids, addLabelIds: ['TRASH'], removeLabelIds: ['INBOX'] });
  await env.DB.prepare(`UPDATE mails SET deleted=1 WHERE owner=? AND id IN (${ph})`).bind(owner, ...ids).run();
  return { ok: true, n: ids.length };
}

async function restoreMail(env, owner, id) {
  const cur = await env.DB.prepare('SELECT deleted FROM mails WHERE owner=? AND id=?').bind(owner, id).first();
  if (cur && cur.deleted === 2) {
    await env.DB.prepare('UPDATE mails SET deleted=0,gsync=0 WHERE owner=? AND id=?').bind(owner, id).run();
    return { ok: true };
  }
  if (!(await mailModOk(env, owner))) return { ok: false, reason: 'scope_modify' };
  await gSend(env, owner, `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}/untrash`);
  await env.DB.prepare("UPDATE mails SET deleted=0,hidden=0,gsync=0,fixed=1,gpromo=0 WHERE owner=? AND id=?").bind(owner, id).run();
  return { ok: true };
}

/* ---------- Recipes: read a web page / caption for the app to turn into a recipe ---------- */

const htmlDecode = (t) => String(t || '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&#(\d+);/g, (m, n) => String.fromCharCode(Number(n)));
function metaContent(html, key) {
  const re = new RegExp(`<meta[^>]+(?:property|name)=["']${key}["'][^>]*>`, 'i');
  const tag = (re.exec(html) || [])[0];
  return tag ? htmlDecode((/content=["']([^"']*)["']/i.exec(tag) || [])[1] || '') : '';
}
function findRecipeNode(x) {
  if (!x || typeof x !== 'object') return null;
  if (Array.isArray(x)) { for (const i of x) { const r = findRecipeNode(i); if (r) return r; } return null; }
  const t = x['@type'];
  if (t === 'Recipe' || (Array.isArray(t) && t.includes('Recipe'))) return x;
  return findRecipeNode(x['@graph']);
}
function flatSteps(x) {
  if (!x) return [];
  if (typeof x === 'string') return x.split(/\n+/).map((t) => htmlDecode(t.replace(/<[^>]+>/g, ' ')).trim()).filter(Boolean);
  if (Array.isArray(x)) return x.flatMap(flatSteps);
  if (x.itemListElement) return flatSteps(x.itemListElement);
  return flatSteps(x.text || x.name || '');
}
function recipeFromJsonLd(html) {
  for (const m of html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    let j;
    try { j = JSON.parse(m[1].trim()); } catch { continue; }
    const r = findRecipeNode(j);
    if (!r) continue;
    const img = Array.isArray(r.image) ? r.image[0] : r.image;
    const imgUrl = typeof img === 'string' ? img : img && img.url;
    const yld = Array.isArray(r.recipeYield) ? r.recipeYield[0] : r.recipeYield;
    return {
      title: htmlDecode(String(r.name || '')).slice(0, 160),
      servings: yld ? String(yld).slice(0, 40) : '',
      ingredients: (Array.isArray(r.recipeIngredient) ? r.recipeIngredient : []).map((t) => htmlDecode(String(t)).trim()).filter(Boolean).slice(0, 100),
      steps: flatSteps(r.recipeInstructions).slice(0, 80),
      img: typeof imgUrl === 'string' && imgUrl.startsWith('https://') ? imgUrl.slice(0, 600) : '',
    };
  }
  return null;
}
const BROWSER_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
async function readRecipePage(rawUrl) {
  let u;
  try { u = new URL(String(rawUrl).trim()); } catch { return { error: 'bad_url' }; }
  const host = u.hostname.toLowerCase();
  if (!/^https?:$/.test(u.protocol) || !host.includes('.') || /^[\d.]+$/.test(host) || host.includes(':') || /(^|\.)(localhost|local|internal)$/.test(host)) return { error: 'bad_url' };
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 9000);
  try {
    let why = '';
    const social = /(^|\.)(tiktok\.com|instagram\.com|facebook\.com|fb\.watch)$/.test(host);
    if (/(^|\.)tiktok\.com$/.test(host)) {
      // short share links (vm./vt.tiktok.com) must be resolved to the full video address first
      let full = u.href;
      if (/^(vm|vt)\./.test(host)) {
        try { const h = await fetch(u.href, { signal: ctl.signal, redirect: 'follow', headers: { 'user-agent': BROWSER_UA } }); if (/tiktok\.com\/@/.test(h.url)) full = h.url.split('?')[0]; } catch { /* keep the short link */ }
      }
      const r = await fetch('https://www.tiktok.com/oembed?url=' + encodeURIComponent(full), { signal: ctl.signal, headers: { 'user-agent': BROWSER_UA } });
      if (r.ok) {
        const j = await r.json().catch(() => ({}));
        if (j.title) return { text: String(j.title).slice(0, 4000), title: '', img: typeof j.thumbnail_url === 'string' && j.thumbnail_url.startsWith('https://') ? j.thumbnail_url : '', source: full, kind: 'caption' };
        why = 'tiktok_no_caption';
      } else why = 'tiktok_' + r.status;
    }
    const r = await fetch(u.href, { signal: ctl.signal, redirect: 'follow', headers: { 'user-agent': social ? BROWSER_UA : 'Mozilla/5.0 (compatible; AmitisRecipeReader/1.0)', accept: 'text/html,application/xhtml+xml', 'accept-language': 'en,he;q=0.8' } });
    if (!r.ok) return { error: 'unreadable', status: r.status, why: why || 'http_' + r.status };
    const html = (await r.text()).slice(0, 600000);
    const rec = recipeFromJsonLd(html);
    if (rec && (rec.ingredients.length || rec.steps.length)) return { recipe: rec, source: u.href };
    const title = metaContent(html, 'og:title') || htmlDecode((/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html) || [])[1] || '').trim();
    const desc = metaContent(html, 'og:description') || metaContent(html, 'description');
    const body = htmlDecode(html.replace(/<(script|style|noscript|svg|head)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
    const text = `${title}\n${desc}\n${body}`.slice(0, 7000);
    if (text.replace(/\s/g, '').length < 40) return { error: 'unreadable', why: why || 'empty_page' };
    const img = metaContent(html, 'og:image');
    return { text, title, img: img.startsWith('https://') ? img.slice(0, 600) : '', source: u.href, kind: 'page' };
  } catch (e) {
    return { error: 'unreadable', why: 'fetch_failed' };
  } finally { clearTimeout(timer); }
}


/* ---------- Web Push (reminders to your phone even when the app is closed) ---------- */

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const concatBytes = (...a) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};

// The VAPID key pair identifies this app to the push services. It is created once and kept in your own database.
async function ensureVapid(env, owner) {
  let pub = await getSetting(env, owner, 'vapid_pub');
  let priv = await getSetting(env, owner, 'vapid_priv');
  if (pub && priv) return { pub, priv };
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const raw = new Uint8Array(65);
  raw[0] = 4;
  raw.set(b64uToBytes(jwk.x), 1);
  raw.set(b64uToBytes(jwk.y), 33);
  pub = b64u(raw);
  priv = jwk.d;
  await setSetting(env, owner, 'vapid_pub', pub);
  await setSetting(env, owner, 'vapid_priv', priv);
  return { pub, priv };
}

async function vapidHeader(v, endpoint) {
  const raw = b64uToBytes(v.pub);
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: b64u(raw.slice(1, 33)), y: b64u(raw.slice(33, 65)), d: v.priv },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const enc = new TextEncoder();
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://amiti-website.pages.dev' })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + claims));
  return `vapid t=${head}.${claims}.${b64u(sig)}, k=${v.pub}`;
}

// RFC 8291 (aes128gcm) encryption of the payload for one subscription.
async function encryptPush(sub, payload) {
  const enc = new TextEncoder();
  const uaPub = b64uToBytes(sub.p256dh);
  const auth = b64uToBytes(sub.auth);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const hkdf = async (salt, ikm, info, len) => {
    const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
  };
  const prk = await hkdf(auth, ecdh, concatBytes(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, prk, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, prk, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concatBytes(enc.encode(payload), new Uint8Array([2]))));
  return concatBytes(salt, new Uint8Array([0, 0, 0x10, 0, 65]), asPub, ct);
}

async function pushCount(env, owner) {
  const r = await env.DB.prepare('SELECT COUNT(*) c FROM push_subs WHERE owner=?').bind(owner).first();
  return r ? r.c : 0;
}

// Sends one notification to every phone/browser that enabled alerts. Returns how many accepted it.
async function sendPush(env, owner, note) {
  const subs = (await env.DB.prepare('SELECT endpoint,p256dh,auth FROM push_subs WHERE owner=?').bind(owner).all()).results;
  if (!subs.length) return 0;
  const v = await ensureVapid(env, owner);
  const body = JSON.stringify({ title: str(note.title, 100), body: str(note.body, 200), url: note.url || '/', tag: str(note.tag || '', 60) });
  let ok = 0;
  for (const s of subs) {
    try {
      const r = await fetch(s.endpoint, {
        method: 'POST',
        headers: {
          authorization: await vapidHeader(v, s.endpoint),
          'content-encoding': 'aes128gcm',
          'content-type': 'application/octet-stream',
          ttl: '86400',
          urgency: 'normal',
        },
        body: await encryptPush(s, body),
      });
      if (r.status === 404 || r.status === 410) await env.DB.prepare('DELETE FROM push_subs WHERE owner=? AND endpoint=?').bind(owner, s.endpoint).run();
      else if (r.ok) ok++;
      else console.error('push status', r.status);
    } catch (e) { console.error('push error', e && e.message); }
  }
  return ok;
}

const localStamp = (env, ms = Date.now()) =>
  new Date(ms).toLocaleString('sv-SE', { timeZone: env.TIMEZONE || 'Asia/Jerusalem' }).replace(' ', 'T').slice(0, 16);

// Reminders that came due (or were snoozed to now) and were not shown yet. Marks them as fired.
async function runReminders(env, owner) {
  if (!(await pushCount(env, owner))) return 0;
  const nowL = localStamp(env), oldest = localStamp(env, Date.now() - 12 * 3600000);
  const eff = "(CASE WHEN snooze<>'' THEN snooze ELSE due END)";
  const rows = (await env.DB.prepare(
    `SELECT id,text,${eff} AS e FROM tasks WHERE owner=? AND done=0 AND ${eff}<>'' AND fired<>${eff} AND ${eff}<=? AND ${eff}>=? ORDER BY e LIMIT 10`
  ).bind(owner, nowL, oldest).all()).results;
  let sent = 0;
  for (const t of rows) {
    const d = new Date(t.e);
    const when = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    const ok = await sendPush(env, owner, { title: '⏰ ' + t.text, body: 'Due ' + when, tag: 't' + t.id });
    if (ok) { await env.DB.prepare('UPDATE tasks SET fired=? WHERE owner=? AND id=?').bind(t.e, owner, t.id).run(); sent++; }
  }
  return sent;
}

const ORDER_PUSH = { shipped: 'Shipped', out_for_delivery: 'Out for delivery', ready_for_pickup: 'Ready for pickup', delivered: 'Delivered' };

// End-of-day report: one push at 21:00 local time (sent once per day).
async function dayReport(env, owner) {
  const stamp = localStamp(env), day = stamp.slice(0, 10), hour = Number(stamp.slice(11, 13));
  if (hour < 21) return false;
  if ((await getSetting(env, owner, 'report_day')) === day) return false;
  if (!(await pushCount(env, owner))) return false;
  const one = (sql, ...a) => env.DB.prepare(sql).bind(owner, day, ...a).first();
  const [fd, wk, wt, goal, burn, wmins] = await Promise.all([
    one('SELECT COALESCE(SUM(kcal),0) k, COUNT(*) n FROM food WHERE owner=? AND day=?'),
    one('SELECT COALESCE(SUM(mins),0) m, COALESCE(SUM(kcal),0) k FROM workouts WHERE owner=? AND day=?'),
    one('SELECT kg FROM weights WHERE owner=? AND day=? ORDER BY id DESC LIMIT 1'),
    getSetting(env, owner, 'goal'), getSetting(env, owner, 'burn'), getSetting(env, owner, 'wmins'),
  ]);
  const g = Number(goal) > 0 ? Number(goal) : 2000, b = Number(burn) > 0 ? Number(burn) : 300, wm = Number(wmins) > 0 ? Number(wmins) : 30;
  const parts = [
    fd.n ? `Ate ${fd.k} of ${g} kcal` : 'No food logged',
    `Workout ${wk.m}/${wm} min, burned ${wk.k}/${b} kcal`,
  ];
  if (wt) parts.push(`Weight ${wt.kg} kg`);
  const ok = await sendPush(env, owner, { title: '🌙 Your day', body: parts.join(' · '), url: '/#health', tag: 'report' });
  if (ok) await setSetting(env, owner, 'report_day', day);
  return ok;
}

// Called by the scheduled worker every 15 minutes.
async function scheduledRun(env) {
  const owner = 'owner';
  const out = { reminders: 0, classroom: 0, orders: 0 };
  // Every other 15-minute tick is the mail-sorting turn (free plans allow only ~50 calls per run).
  if (Math.floor(new Date().getUTCMinutes() / 15) % 2 === 1) {
    try { out.reminders = await runReminders(env, owner); } catch (e) { console.error('reminders', e && e.message); }
    try { out.inbox = await scanInbox(env, owner, { limit: 12 }); } catch (e) { console.error('inbox', e && e.message); }
    try { out.digest = await mailDigest(env, owner); } catch (e) { console.error('digest', e && e.message); }
    try { out.gmail = await syncGmail(env, owner, { limit: 200 }); } catch (e) { console.error('gmail sync', e && e.message); }
    return out;
  }
  try { out.report = await dayReport(env, owner); } catch (e) { console.error('report', e && e.message); }
  try { out.reminders = await runReminders(env, owner); } catch (e) { console.error('reminders', e && e.message); }
  try {
    const c = await syncClassroom(env, owner);
    if (c.ok && c.newTasks && c.newTasks.length) {
      const list = c.newTasks.slice(0, 3);
      for (const t of list) await sendPush(env, owner, { title: '🎓 New in Classroom', body: t.text, tag: 'cr' });
      if (c.newTasks.length > 3) await sendPush(env, owner, { title: '🎓 Classroom', body: `and ${c.newTasks.length - 3} more new assignments` });
      out.classroom = c.newTasks.length;
    }
  } catch (e) { console.error('classroom', e && e.message); }
  try {
    const o = await checkOrders(env, owner);
    if (o.ok && o.updates && o.updates.length) {
      for (const u of o.updates.filter((x) => ORDER_PUSH[x.status]).slice(0, 4)) {
        await sendPush(env, owner, { title: '📦 ' + ORDER_PUSH[u.status], body: `${u.shop}${u.item ? ': ' + u.item : ''}`, url: '/#orders', tag: 'ord' });
      }
      out.orders = o.updates.length;
    }
  } catch (e) { console.error('orders', e && e.message); }
  return out;
}

/* ---------- Notion two-way sync (recipes + shopping list) ---------- */
// Needs a free Notion "internal integration" token in the NOTION_TOKEN secret, shared with one Notion page.
// Two databases are created under that page. A map table remembers which app item is which Notion page.
const NOTION_CATS = ['Baking & dough', 'Cakes & desserts', 'Meat', 'Chicken', 'Fish', 'Vegetarian & vegan', 'Pasta & rice', 'Soups', 'Salads & sides', 'Breakfast', 'Snacks & drinks', 'Healthy & light', 'Other'];
async function nApi(env, method, path, body) {
  const r = await fetch('https://api.notion.com/v1' + path, {
    method,
    headers: { authorization: 'Bearer ' + env.NOTION_TOKEN, 'notion-version': '2022-06-28', 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401 || r.status === 403) throw new Error('notion_auth');
  if (r.status === 404) throw new Error('notion_404');
  if (r.status === 429) throw new Error('notion_rate');
  if (!r.ok) throw new Error('notion_' + r.status);
  return r.json();
}
const nPlain = (a) => (Array.isArray(a) ? a.map((x) => x.plain_text || x.text?.content || '').join('') : '');
const nRich = (t) => {
  const s = String(t || '');
  const out = [];
  for (let i = 0; i < s.length && out.length < 90; i += 1900) out.push({ type: 'text', text: { content: s.slice(i, i + 1900) } });
  return out;
};
const newId = () => 'n' + crypto.randomUUID().replace(/-/g, '').slice(0, 14);

async function nEnsureDbs(env, owner) {
  let rdb = await getSetting(env, owner, 'n_rdb');
  let sdb = await getSetting(env, owner, 'n_sdb');
  if (rdb && sdb) return { rdb, sdb };
  let parent = String(env.NOTION_PARENT_PAGE || '').replace(/-/g, '').match(/[0-9a-f]{32}/i)?.[0];
  if (!parent) {
    const s = await nApi(env, 'POST', '/search', { filter: { property: 'object', value: 'page' }, page_size: 30 });
    const pages = (s.results || []).filter((p) => p.parent && (p.parent.type === 'workspace' || p.parent.type === 'page_id'));
    const title = (p) => nPlain(Object.values(p.properties || {}).find((x) => x.type === 'title')?.title);
    const pick = pages.find((p) => /amiti/i.test(title(p))) || pages[0];
    if (!pick) throw new Error('notion_no_page');
    parent = pick.id;
  }
  if (!rdb) {
    const d = await nApi(env, 'POST', '/databases', {
      parent: { type: 'page_id', page_id: parent }, title: [{ type: 'text', text: { content: 'Amiti’s Recipes' } }],
      properties: { Name: { title: {} }, Style: { select: {} }, Servings: { rich_text: {} }, Source: { url: {} }, 'App ID': { rich_text: {} } },
    });
    rdb = d.id; await setSetting(env, owner, 'n_rdb', rdb);
  }
  if (!sdb) {
    const d = await nApi(env, 'POST', '/databases', {
      parent: { type: 'page_id', page_id: parent }, title: [{ type: 'text', text: { content: 'Amiti’s Shopping list' } }],
      properties: { Name: { title: {} }, Bought: { checkbox: {} }, Recipe: { rich_text: {} }, 'App ID': { rich_text: {} } },
    });
    sdb = d.id; await setSetting(env, owner, 'n_sdb', sdb);
  }
  return { rdb, sdb };
}
async function nQueryAll(env, db) {
  const out = [];
  let cursor;
  for (let i = 0; i < 4; i++) {
    const r = await nApi(env, 'POST', `/databases/${db}/query`, { page_size: 100, ...(cursor ? { start_cursor: cursor } : {}) });
    out.push(...(r.results || []).filter((p) => !p.archived && !p.in_trash));
    if (!r.has_more) break;
    cursor = r.next_cursor;
  }
  return out;
}
const nRecipeHash = (r) => shortHash(JSON.stringify([r.title, r.cat || 'Other', r.servings || '', r.source || '', r.ing, r.steps, r.notes || '']));
const nShopHash = (s) => shortHash(JSON.stringify([s.name, s.done ? 1 : 0, s.rid || '', s.rname || '']));
function nRecipeProps(r) {
  return { Name: { title: nRich(r.title).slice(0, 1) }, Style: { select: { name: NOTION_CATS.includes(r.cat) ? r.cat : 'Other' } }, Servings: { rich_text: nRich(r.servings) }, Source: { url: /^https?:\/\//.test(r.source || '') ? r.source.slice(0, 1900) : null }, 'App ID': { rich_text: nRich(r.id) } };
}
function nRecipeBlocks(r) {
  const b = [];
  const h = (t) => b.push({ object: 'block', type: 'heading_2', heading_2: { rich_text: nRich(t) } });
  if (r.ing.length) { h('Ingredients'); r.ing.forEach((t) => b.push({ object: 'block', type: 'bulleted_list_item', bulleted_list_item: { rich_text: nRich(t).slice(0, 1) } })); }
  if (r.steps.length) { h('Method'); r.steps.forEach((t) => b.push({ object: 'block', type: 'numbered_list_item', numbered_list_item: { rich_text: nRich(t).slice(0, 1) } })); }
  if (r.notes) { h('Notes'); b.push({ object: 'block', type: 'paragraph', paragraph: { rich_text: nRich(r.notes).slice(0, 1) } }); }
  return b;
}
async function nCreateRecipe(env, db, r) {
  const blocks = nRecipeBlocks(r);
  const p = await nApi(env, 'POST', '/pages', { parent: { database_id: db }, properties: nRecipeProps(r), children: blocks.slice(0, 100) });
  let t = p.last_edited_time || '';
  for (let i = 100; i < blocks.length; i += 100) { const x = await nApi(env, 'PATCH', `/blocks/${p.id}/children`, { children: blocks.slice(i, i + 100) }); t = x.results?.[0]?.last_edited_time || t; }
  if (blocks.length > 100) { const q = await nApi(env, 'GET', `/pages/${p.id}`); t = q.last_edited_time || t; }
  return { id: p.id, time: t };
}
async function nReadRecipe(env, page) {
  const pr = page.properties || {};
  const title = nPlain(Object.values(pr).find((x) => x.type === 'title')?.title).trim();
  const cat = pr.Style?.select?.name || '';
  const blocks = (await nApi(env, 'GET', `/blocks/${page.id}/children?page_size=100`)).results || [];
  const ing = [], steps = [], notes = [];
  let sec = '';
  for (const b of blocks) {
    const t = b.type;
    const text = nPlain(b[t]?.rich_text).trim();
    if (/^heading_/.test(t)) { sec = /ingred|מרכיב|מצרכ/i.test(text) ? 'ing' : /method|step|instruction|הכנה|אופן/i.test(text) ? 'steps' : /note|tip|טיפ|הערה/i.test(text) ? 'notes' : sec; continue; }
    if (!text) continue;
    if (t === 'numbered_list_item') steps.push(text);
    else if (t === 'bulleted_list_item' || t === 'to_do') (sec === 'steps' ? steps : ing).push(text);
    else if (t === 'paragraph') (sec === 'ing' ? ing : sec === 'steps' ? steps : notes).push(text);
  }
  return {
    title: title.slice(0, 160), cat: NOTION_CATS.includes(cat) ? cat : (cat ? 'Other' : ''),
    servings: nPlain(pr.Servings?.rich_text).trim().slice(0, 40), source: pr.Source?.url || '',
    ing: ing.slice(0, 100).map((x) => x.slice(0, 200)), steps: steps.slice(0, 80).map((x) => x.slice(0, 1200)), notes: notes.join('\n').slice(0, 1500),
  };
}
const nShopProps = (s) => ({ Name: { title: nRich(s.name).slice(0, 1) }, Bought: { checkbox: !!s.done }, Recipe: { rich_text: nRich(s.rname || '').slice(0, 1) }, 'App ID': { rich_text: nRich(s.id) } });

// Runs one pass in both directions. Safe to call often; does at most ~28 Notion writes per call (the free plan allows ~50 calls per request).
async function notionSync(env, owner) {
  if (!env.NOTION_TOKEN) return { ok: false, error: 'not_configured' };
  const lock = Number(await getSetting(env, owner, 'n_lock')) || 0;
  if (Date.now() - lock < 45000) return { ok: true, busy: true };
  await setSetting(env, owner, 'n_lock', String(Date.now()));
  const stats = { ok: true, pushed: 0, pulled: 0, removed: 0, more: false, changed: false };
  let ops = 0;
  const OPS = 26;
  const stmts = [];
  const db = env.DB;
  try {
    const { rdb, sdb } = await nEnsureDbs(env, owner);
    const [maps, recs, shop] = await Promise.all([
      db.prepare('SELECT kind,id,npage,hash,ntime FROM notion_map WHERE owner=?').bind(owner).all(),
      db.prepare('SELECT id,title,source,servings,ing,steps,notes,cat FROM recipes WHERE owner=?').bind(owner).all(),
      db.prepare('SELECT id,name,done,rid,rname FROM shop WHERE owner=?').bind(owner).all(),
    ]);
    const j = (t) => { try { const a = JSON.parse(t); return Array.isArray(a) ? a : []; } catch { return []; } };
    const recipes = recs.results.map((r) => ({ ...r, ing: j(r.ing), steps: j(r.steps), cat: r.cat || 'Other' }));
    const mapOf = { r: {}, s: {} };
    for (const m of maps.results) if (mapOf[m.kind]) mapOf[m.kind][m.id] = m;
    const setMap = (kind, id, npage, hash, ntime) => stmts.push(db.prepare('INSERT INTO notion_map(owner,kind,id,npage,hash,ntime) VALUES(?,?,?,?,?,?) ON CONFLICT(owner,kind,id) DO UPDATE SET npage=excluded.npage,hash=excluded.hash,ntime=excluded.ntime').bind(owner, kind, id, npage, hash, ntime));
    const delMap = (kind, id) => stmts.push(db.prepare('DELETE FROM notion_map WHERE owner=? AND kind=? AND id=?').bind(owner, kind, id));
    const archive = async (pageId) => { ops++; await nApi(env, 'PATCH', `/pages/${pageId}`, { archived: true }).catch((e) => { if (e.message !== 'notion_404') throw e; }); };
    const room = () => ops < OPS;

    /* ----- recipes ----- */
    const rPages = await nQueryAll(env, rdb);
    const rByPage = new Map(rPages.map((p) => [p.id, p]));
    const rSeen = new Set();
    for (const r of recipes) {
      const m = mapOf.r[r.id];
      const h = await nRecipeHash(r);
      if (!m) { if (!room()) { stats.more = true; continue; } ops += 2; const c = await nCreateRecipe(env, rdb, r); setMap('r', r.id, c.id, h, c.time); stats.pushed++; continue; }
      rSeen.add(m.id);
      const page = rByPage.get(m.npage);
      if (!page) { stmts.push(db.prepare('DELETE FROM recipes WHERE owner=? AND id=?').bind(owner, r.id)); delMap('r', r.id); stats.removed++; stats.changed = true; continue; }
      if (h !== m.hash) {
        if (!room()) { stats.more = true; continue; }
        await archive(m.npage); ops += 2;
        const c = await nCreateRecipe(env, rdb, r); setMap('r', r.id, c.id, h, c.time); stats.pushed++;
      } else if (page.last_edited_time !== m.ntime) {
        if (!room()) { stats.more = true; continue; }
        ops++;
        const n = await nReadRecipe(env, page);
        if (n.title && (n.ing.length || n.steps.length)) {
          const merged = { ...r, ...n, cat: n.cat || r.cat, source: n.source || '' };
          stmts.push(db.prepare('UPDATE recipes SET title=?,source=?,servings=?,ing=?,steps=?,notes=?,cat=? WHERE owner=? AND id=?').bind(merged.title, merged.source, merged.servings, JSON.stringify(merged.ing), JSON.stringify(merged.steps), merged.notes, merged.cat, owner, r.id));
          setMap('r', r.id, m.npage, await nRecipeHash(merged), page.last_edited_time);
          stats.pulled++; stats.changed = true;
        } else setMap('r', r.id, m.npage, m.hash, page.last_edited_time);
      }
    }
    const recById = new Set(recipes.map((r) => r.id));
    for (const m of Object.values(mapOf.r)) if (!recById.has(m.id)) { if (!room()) { stats.more = true; continue; } if (rByPage.has(m.npage)) await archive(m.npage); delMap('r', m.id); stats.removed++; }
    const mappedPages = new Set(Object.values(mapOf.r).map((m) => m.npage));
    for (const page of rPages) {
      if (mappedPages.has(page.id)) continue;
      const appId = nPlain(page.properties?.['App ID']?.rich_text).trim();
      if (appId && recById.has(appId)) { setMap('r', appId, page.id, await nRecipeHash(recipes.find((x) => x.id === appId)), page.last_edited_time); continue; }
      if (!room()) { stats.more = true; continue; }
      ops++;
      const n = await nReadRecipe(env, page);
      if (!n.title || !(n.ing.length || n.steps.length)) continue;
      const id = newId();
      const rec = { id, ...n, cat: n.cat || 'Other' };
      stmts.push(db.prepare('INSERT INTO recipes(owner,id,title,source,servings,ing,steps,notes,img,added,cat) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(owner, id, rec.title, rec.source, rec.servings, JSON.stringify(rec.ing), JSON.stringify(rec.steps), rec.notes, '', new Date().toISOString(), rec.cat));
      setMap('r', id, page.id, await nRecipeHash(rec), page.last_edited_time);
      stats.pulled++; stats.changed = true;
    }

    /* ----- shopping list ----- */
    const sPages = await nQueryAll(env, sdb);
    const sByPage = new Map(sPages.map((p) => [p.id, p]));
    const shopIds = new Set(shop.results.map((s) => s.id));
    for (const s0 of shop.results) {
      const s = { ...s0, done: !!s0.done };
      const m = mapOf.s[s.id];
      const h = await nShopHash(s);
      if (!m) { if (!room()) { stats.more = true; continue; } ops++; const p = await nApi(env, 'POST', '/pages', { parent: { database_id: sdb }, properties: nShopProps(s) }); setMap('s', s.id, p.id, h, p.last_edited_time || ''); stats.pushed++; continue; }
      const page = sByPage.get(m.npage);
      if (!page) { stmts.push(db.prepare('DELETE FROM shop WHERE owner=? AND id=?').bind(owner, s.id)); delMap('s', s.id); stats.removed++; stats.changed = true; continue; }
      if (h !== m.hash) {
        if (!room()) { stats.more = true; continue; }
        ops++;
        const p = await nApi(env, 'PATCH', `/pages/${m.npage}`, { properties: nShopProps(s) });
        setMap('s', s.id, m.npage, h, p.last_edited_time || ''); stats.pushed++;
      } else if (page.last_edited_time !== m.ntime) {
        const name = nPlain(Object.values(page.properties || {}).find((x) => x.type === 'title')?.title).trim().slice(0, 120);
        const done = !!page.properties?.Bought?.checkbox;
        if (name) {
          const n = { ...s, name, done };
          stmts.push(db.prepare('UPDATE shop SET name=?,done=? WHERE owner=? AND id=?').bind(name, done ? 1 : 0, owner, s.id));
          setMap('s', s.id, m.npage, await nShopHash(n), page.last_edited_time);
          stats.pulled++; stats.changed = true;
        }
      }
    }
    for (const m of Object.values(mapOf.s)) if (!shopIds.has(m.id)) { if (!room()) { stats.more = true; continue; } if (sByPage.has(m.npage)) await archive(m.npage); delMap('s', m.id); stats.removed++; }
    const sMapped = new Set(Object.values(mapOf.s).map((m) => m.npage));
    for (const page of sPages) {
      if (sMapped.has(page.id)) continue;
      const appId = nPlain(page.properties?.['App ID']?.rich_text).trim();
      const name = nPlain(Object.values(page.properties || {}).find((x) => x.type === 'title')?.title).trim().slice(0, 120);
      if (appId && shopIds.has(appId)) { const s = shop.results.find((x) => x.id === appId); setMap('s', appId, page.id, await nShopHash({ ...s, done: !!s.done }), page.last_edited_time); continue; }
      if (!name) continue;
      const id = newId();
      const done = !!page.properties?.Bought?.checkbox;
      stmts.push(db.prepare("INSERT INTO shop(owner,id,name,done,added,rid,rname) VALUES(?,?,?,?,?,'','')").bind(owner, id, name, done ? 1 : 0, new Date().toISOString()));
      setMap('s', id, page.id, await nShopHash({ name, done, rid: '', rname: '' }), page.last_edited_time);
      stats.pulled++; stats.changed = true;
    }
  } catch (e) {
    stats.ok = false; stats.error = String(e && e.message || e).slice(0, 40);
  }
  try { for (let i = 0; i < stmts.length; i += 40) await db.batch(stmts.slice(i, i + 40)); } catch (e) { stats.ok = false; stats.error = 'db_' + String(e && e.message || e).slice(0, 30); }
  await delSetting(env, owner, 'n_lock').catch(() => {});
  if (stats.ok) await setSetting(env, owner, 'n_last', new Date().toISOString()).catch(() => {});
  return stats;
}

async function exportAll(env, owner) {
  const q = (sql) => env.DB.prepare(sql).bind(owner).all().then((r) => r.results);
  return {
    exported: new Date().toISOString(),
    tasks: await q('SELECT id,text,due,dur,snooze,tag,urgent,important,done,rec FROM tasks WHERE owner=?'),
    food: await q('SELECT id,day,slot,name,kcal,p,c,f FROM food WHERE owner=?'),
    meals: await q('SELECT id,name,servings,ing FROM meals WHERE owner=?'),
    workouts: await q('SELECT id,day,kind,mins,kcal FROM workouts WHERE owner=?'),
    weights: await q('SELECT id,day,kg FROM weights WHERE owner=?'),
    recipes: await q('SELECT id,title,source,servings,ing,steps,notes,cat FROM recipes WHERE owner=?'),
    quotes: await q('SELECT id,text,author FROM quotes WHERE owner=?'),
    mails: await q('SELECT id,sender,addr,subject,date,folder,trip,important FROM mails WHERE owner=? AND deleted=0'),
    mail_rules: await q('SELECT addr,folder,trip FROM mail_rules WHERE owner=?'),
    shopping: await q('SELECT id,name,done,rid,rname FROM shop WHERE owner=?'),
    orders: await q('SELECT shop,item,order_no,status,placed,updated FROM orders WHERE owner=? AND hidden=0'),
  };
}

export { notionSync, readRecipePage, recipeFromJsonLd, mailDigest, restoreMail, syncGmail, trashMail, scanInbox, listInbox, scheduledRun, runReminders, sendPush, ensureVapid, encryptPush, vapidHeader, syncClassroom, checkOrders };

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
            ai: aiEnabled(env), gemini: !!env.GEMINI_API_KEY, notion: !!env.NOTION_TOKEN, gcal: gConfigured(env), gconnected: connected, tz: env.TIMEZONE || 'Asia/Jerusalem',
            classroom: connected && (await classroomOk(env, owner)), mail: connected && (await mailOk(env, owner)), mailMod: connected && (await mailModOk(env, owner)),
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
        case 'GET /api/inbox':
          return json({ ...(await listInbox(env, owner, url.searchParams.get('folder') || 'important', url.searchParams.has('trip') ? url.searchParams.get('trip') : null, url.searchParams.get('q') || '', Number(url.searchParams.get('days')) || 0)), mail: !!(await getSetting(env, owner, 'g_refresh')) && (await mailOk(env, owner)) });
        case 'POST /api/inbox/scan': {
          let res;
          try { res = await scanInbox(env, owner, { bulk: true }); } catch (e) {
            return fail(e.message === 'needs_reauth' ? 401 : 502, 'Gmail error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40));
          }
          return json(res);
        }
        case 'POST /api/notion/sync':
          return json(await notionSync(env, owner));
        case 'GET /api/notion':
          return json({ configured: !!env.NOTION_TOKEN, ready: !!(await getSetting(env, owner, 'n_rdb')), last: await getSetting(env, owner, 'n_last') });
        case 'POST /api/recipes/fetch': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          return json(await readRecipePage(b?.url));
        }
        case 'POST /api/inbox/rescan': {
          for (let i = 0; i < SCAN_PHASES.length; i++) { await delSetting(env, owner, 'sp_d' + i); await delSetting(env, owner, 'sp_p' + i); }
          return json({ ok: true });
        }
        case 'POST /api/inbox/gsync': {
          try { return json(await syncGmail(env, owner)); } catch (e) {
            return fail(e.message === 'needs_reauth' ? 401 : 502, 'Gmail error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40));
          }
        }
        case 'POST /api/inbox/restore': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          if (!/^[A-Za-z0-9_-]{2,40}$/.test(String(b?.id))) return fail(400, 'Bad request', 'bad_request');
          try {
            const r = await restoreMail(env, owner, String(b.id));
            return r.ok ? json(r) : fail(403, 'Allow Gmail changes first', r.reason);
          } catch (e) { return fail(e.message === 'needs_reauth' ? 401 : 502, 'Gmail error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40)); }
        }
        case 'POST /api/inbox/delete': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          if (Array.isArray(b?.ids)) {
            const ids = b.ids.map(String).filter((i) => /^[A-Za-z0-9_-]{2,40}$/.test(i)).slice(0, 300);
            try { return json(await trashMails(env, owner, ids)); } catch (e) {
              return fail(e.message === 'needs_reauth' ? 401 : 502, 'Gmail error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40));
            }
          }
          if (!/^[A-Za-z0-9_-]{2,40}$/.test(String(b?.id))) return fail(400, 'Bad request', 'bad_request');
          try {
            const r = await trashMail(env, owner, String(b.id));
            return r.ok ? json(r) : fail(403, 'Allow Gmail changes first', r.reason);
          } catch (e) { return fail(e.message === 'needs_reauth' ? 401 : 502, 'Gmail error', e.message === 'needs_reauth' ? 'needs_reauth' : String(e.message || 'upstream_error').slice(0, 40)); }
        }
        case 'POST /api/inbox/move': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          if (Array.isArray(b.ids) && b.read) {
            const ids = b.ids.map(String).filter((i) => /^[A-Za-z0-9_-]{2,40}$/.test(i)).slice(0, 300);
            if (ids.length) await env.DB.prepare(`UPDATE mails SET hidden=1,important=0 WHERE owner=? AND id IN (${ids.map(() => '?').join(',')})`).bind(owner, ...ids).run();
            return json({ ok: true, n: ids.length });
          }
          if (!/^[A-Za-z0-9_-]{2,40}$/.test(String(b?.id))) return fail(400, 'Bad request', 'bad_request');
          if (b.read) await env.DB.prepare('UPDATE mails SET hidden=1,important=0 WHERE owner=? AND id=?').bind(owner, String(b.id)).run();
          if (b.dismiss) await env.DB.prepare('UPDATE mails SET important=0 WHERE owner=? AND id=?').bind(owner, String(b.id)).run();
          if (MAIL_FOLDERS.includes(b.folder)) {
            await env.DB.prepare('UPDATE mails SET folder=?,trip=?,fixed=1,gsync=0,important=CASE WHEN ?=\'promos\' THEN 0 ELSE important END WHERE owner=? AND id=?').bind(b.folder, b.folder === 'trips' ? str(b.trip, 60).trim() : '', b.folder, owner, String(b.id)).run();
          }
          let applied = 0;
          if (MAIL_FOLDERS.includes(b.folder)) {
            const mm = await env.DB.prepare('SELECT addr FROM mails WHERE owner=? AND id=?').bind(owner, String(b.id)).first();
            const addr = (mm && mm.addr || '').toLowerCase();
            if (addr) {
              const tp = b.folder === 'trips' ? str(b.trip, 60).trim() : '';
              await env.DB.prepare('INSERT INTO mail_rules(owner,addr,folder,trip) VALUES(?,?,?,?) ON CONFLICT(owner,addr) DO UPDATE SET folder=excluded.folder,trip=excluded.trip').bind(owner, addr, b.folder, tp).run();
              const ur = await env.DB.prepare('UPDATE mails SET folder=?,trip=?,gsync=0 WHERE owner=? AND lower(addr)=? AND fixed=0 AND deleted=0 AND id<>?').bind(b.folder, tp, owner, addr, String(b.id)).run();
              applied = (ur && ur.meta && ur.meta.changes) || 0;
            }
          }
          return json({ ok: true, applied });
        }
        case 'GET /api/push/key':
          return json({ key: (await ensureVapid(env, owner)).pub, subscribed: (await pushCount(env, owner)) > 0 });
        case 'POST /api/push/subscribe': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          const ep = String(b?.endpoint || ''), k = b?.keys || {};
          if (!/^https:\/\/[^\s]{10,480}$/.test(ep) || !/^[A-Za-z0-9_-]{60,100}$/.test(String(k.p256dh)) || !/^[A-Za-z0-9_-]{10,40}$/.test(String(k.auth))) return fail(400, 'Bad subscription', 'bad_request');
          await env.DB.prepare('INSERT INTO push_subs(owner,endpoint,p256dh,auth,created) VALUES(?,?,?,?,?) ON CONFLICT(owner,endpoint) DO UPDATE SET p256dh=excluded.p256dh,auth=excluded.auth')
            .bind(owner, ep, String(k.p256dh), String(k.auth), new Date().toISOString()).run();
          return json({ ok: true });
        }
        case 'POST /api/push/unsubscribe': {
          let b;
          try { b = await req.json(); } catch { return fail(400, 'Bad request', 'bad_request'); }
          await env.DB.prepare('DELETE FROM push_subs WHERE owner=? AND endpoint=?').bind(owner, String(b?.endpoint || '')).run();
          return json({ ok: true });
        }
        case 'POST /api/push/test':
          return json({ ok: true, sent: await sendPush(env, owner, { title: 'Amiti’s', body: 'Alerts are working 🎉' }) });
        case 'GET /api/export':
          return new Response(JSON.stringify(await exportAll(env, owner), null, 2), {
            headers: { ...JSON_HEADERS, 'content-disposition': `attachment; filename="amitis-backup-${new Date().toISOString().slice(0, 10)}.json"` },
          });
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
