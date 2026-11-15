require('dotenv').config();
const express = require('express'), session = require('express-session');
const msal = require('@azure/msal-node'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs');

const db = new Database(process.env.DB_PATH || 'toil.db');
db.exec(`
create table if not exists users(id integer primary key, email text unique not null, name text,
  role text not null default 'member' check(role in('member','manager','admin')),
  manager_id integer references users(id), active integer not null default 1);
create table if not exists entries(id integer primary key, user_id integer not null references users(id),
  date text not null, hours real not null check(hours>0), type text not null check(type in('earned','taken')),
  reason text not null, updated_at text default current_timestamp);`);
try { db.exec('alter table users add column password_hash text'); } catch (e) { /* already migrated */ }
const AUTH_AZURE = process.env.AUTH_AZURE !== 'false' && !!process.env.CLIENT_ID;
const AUTH_LOCAL = process.env.AUTH_LOCAL === 'true';
// Bootstrap admins from env
for (const e of (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean))
  db.prepare("insert into users(email,role) values(?,'admin') on conflict(email) do update set role='admin',active=1").run(e);
if (AUTH_LOCAL && process.env.ADMIN_PASSWORD) // sets a first password only for admins who have none; remove the var afterwards
  db.prepare("update users set password_hash=? where role='admin' and password_hash is null").run(bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12));

// Session store backed by the same SQLite file (survives restarts; no extra dependency)
class SqliteStore extends session.Store {
  constructor(d) {
    super(); this.d = d;
    d.exec('create table if not exists sessions(sid text primary key, sess text not null, expires integer not null)');
    this.purge(); setInterval(() => this.purge(), 3600e3).unref();
  }
  purge() { this.d.prepare('delete from sessions where expires < ?').run(Date.now()); }
  get(sid, cb) {
    try { const r = this.d.prepare('select sess from sessions where sid=? and expires>=?').get(sid, Date.now()); cb(null, r ? JSON.parse(r.sess) : null); }
    catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const exp = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 8 * 3600e3;
      this.d.prepare('insert or replace into sessions(sid,sess,expires) values(?,?,?)').run(sid, JSON.stringify(sess), exp);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
  touch(sid, sess, cb) { this.set(sid, sess, cb); }
  destroy(sid, cb) { try { this.d.prepare('delete from sessions where sid=?').run(sid); cb && cb(null); } catch (e) { cb && cb(e); } }
}

const app = express();
// Only trust X-Forwarded-* headers when a reverse proxy really sits in front (TRUST_PROXY=1). If the app is reachable
// directly, trusting them lets anyone spoof their IP and dodge the login lockout.
const tp = (process.env.TRUST_PROXY || '').trim();
app.set('trust proxy', ['', '0', 'false'].includes(tp) ? false : /^\d+$/.test(tp) ? Number(tp) : tp);
const HTTPS = (process.env.BASE_URL || '').startsWith('https');
if (!HTTPS) console.warn('WARNING: BASE_URL is not https. Passwords and sessions travel unencrypted. Put a TLS proxy in front (see README).');
if (HTTPS && !tp) console.warn('WARNING: BASE_URL is https but TRUST_PROXY is not set. If TLS is terminated by a proxy, set TRUST_PROXY=1 or login cookies will not be issued.');
app.use((req, res, next) => { if (HTTPS) res.setHeader('Strict-Transport-Security', 'max-age=15552000'); next(); });
app.use(express.json());
app.use(session({
  store: new SqliteStore(db), secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: HTTPS, maxAge: 8 * 3600e3 }
}));

// ---- Auth (MFA is enforced by Entra Conditional Access on the tenant) ----
const cca = AUTH_AZURE && new msal.ConfidentialClientApplication({ auth: {
  clientId: process.env.CLIENT_ID, clientSecret: process.env.CLIENT_SECRET,
  authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}` } });
const REDIRECT = process.env.BASE_URL + '/auth/callback', SCOPES = ['openid', 'profile', 'email'];

app.get('/login', async (req, res) => {
  if (!AUTH_AZURE) return res.status(404).send('Microsoft sign-in is disabled');
  res.redirect(await cca.getAuthCodeUrl({ scopes: SCOPES, redirectUri: REDIRECT, prompt: 'select_account' }));
});
app.get('/auth/callback', async (req, res) => {
  if (!AUTH_AZURE) return res.status(404).end();
  try {
    const r = await cca.acquireTokenByCode({ code: req.query.code, scopes: SCOPES, redirectUri: REDIRECT });
    const c = r.idTokenClaims, email = (c.preferred_username || c.email || '').toLowerCase();
    const u = db.prepare('select * from users where email=? and active=1').get(email);
    if (!u) return res.status(403).send('Your account has not been added to TOIL Tracker. Ask an admin.');
    if (!u.name) db.prepare('update users set name=? where id=?').run(c.name, u.id);
    req.session.regenerate(() => { req.session.uid = u.id; res.redirect('/'); });
  } catch (e) { console.error(e); res.status(401).send('Sign-in failed'); }
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// ---- Local login (email + password) ----
app.get('/api/auth-options', (req, res) => res.json({ azure: AUTH_AZURE, local: AUTH_LOCAL }));
// Lockout (15 min window): 5 failures per IP+email, 20 per email (stops spread-out guessing), 30 per IP.
const WINDOW = 15 * 60e3, fails = new Map(), DUMMY = bcrypt.hashSync('x', 12);
const bucket = k => { const now = Date.now(); let f = fails.get(k);
  if (!f || f.t + WINDOW < now) { if (fails.size > 100000) fails.clear(); f = { n: 0, t: now }; fails.set(k, f); } return f; };
setInterval(() => { const now = Date.now(); for (const [k, f] of fails) if (f.t + WINDOW < now) fails.delete(k); }, 60e3).unref();
const pwOk = p => typeof p === 'string' && p.length >= 10 && p.length <= 200;
app.post('/auth/local', (req, res) => {
  if (!AUTH_LOCAL) return res.status(404).json({ error: 'Local login is disabled' });
  const email = String(req.body.email || '').toLowerCase().trim().slice(0, 254);
  const limits = [[req.ip + '|' + email, 5], ['e:' + email, 20], ['i:' + req.ip, 30]];
  if (limits.some(([k, max]) => bucket(k).n >= max)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const u = db.prepare('select * from users where email=? and active=1').get(email);
  const match = bcrypt.compareSync(String(req.body.password || ''), (u && u.password_hash) || DUMMY);
  if (!(u && u.password_hash && match)) { limits.forEach(([k]) => bucket(k).n++); return res.status(401).json({ error: 'Invalid email or password' }); }
  fails.delete(limits[0][0]);
  req.session.regenerate(() => { req.session.uid = u.id; res.json({ ok: true }); });
});

const me = req => req.session.uid && db.prepare('select * from users where id=? and active=1').get(req.session.uid);
const auth = (req, res, next) => (req.user = me(req)) ? next() : res.status(401).json({ error: 'Not signed in' });
const role = (...r) => (req, res, next) => r.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });
const BAL = `coalesce(sum(case e.type when 'earned' then e.hours else -e.hours end),0)`;

app.get('/healthz', (req, res) => { db.prepare('select 1').get(); res.send('ok'); });
app.use(express.static('public'));
app.get('/api/me', (req, res) => {
  const u = me(req); if (!u) return res.status(401).json({});
  const { password_hash, ...safe } = u;
  res.json({ ...safe, has_password: !!password_hash, is_manager: isManager(u), balance: db.prepare(`select ${BAL} b from entries e where user_id=?`).get(u.id).b });
});

app.post('/api/me/password', auth, (req, res) => { // only users who already have a local password
  const { current, password } = req.body;
  if (!pwOk(password)) return res.status(400).json({ error: 'Password must be at least 10 characters' });
  if (!req.user.password_hash || !bcrypt.compareSync(String(current || ''), req.user.password_hash))
    return res.status(400).json({ error: 'Current password is incorrect' });
  db.prepare('update users set password_hash=? where id=?').run(bcrypt.hashSync(password, 12), req.user.id);
  res.json({ ok: true });
});

// ---- Teams (many teams, many managers per team, users can be in many teams) ----
db.exec(`
create table if not exists teams(id integer primary key, name text unique not null);
create table if not exists team_members(team_id integer not null references teams(id) on delete cascade, user_id integer not null references users(id), primary key(team_id,user_id));
create table if not exists team_managers(team_id integer not null references teams(id) on delete cascade, user_id integer not null references users(id),
  title text not null default 'lead' check(title in('lead','director')), primary key(team_id,user_id));
create table if not exists audit(id integer primary key, entry_id integer, owner_id integer not null, actor_id integer not null,
  action text not null, before text, after text, note text, at text default current_timestamp);`);
if (!db.prepare('select 1 from teams limit 1').get()) { // one-time migration from the old single manager_id model
  for (const m of db.prepare('select distinct manager_id id from users where manager_id is not null').all()) {
    const mu = db.prepare('select * from users where id=?').get(m.id);
    const t = db.prepare('insert or ignore into teams(name) values(?)').run(`${mu.name || mu.email}'s team`).lastInsertRowid;
    db.prepare("insert or ignore into team_managers values(?,?,'lead')").run(t, m.id);
    db.prepare('insert or ignore into team_members select ?, id from users where manager_id=?').run(t, m.id);
  }
  db.exec("update users set role='member' where role='manager'");
}
const isTeamMgr = (u, tid) => u.role === 'admin' || !!db.prepare('select 1 from team_managers where team_id=? and user_id=?').get(tid, u.id);
const isManager = u => u.role === 'admin' || !!db.prepare('select 1 from team_managers where user_id=?').get(u.id);
const canManage = (u, uid) => u.role === 'admin' || (u.id !== uid && !!db.prepare(
  'select 1 from team_managers m join team_members t on t.team_id=m.team_id where m.user_id=? and t.user_id=?').get(u.id, uid));

// ---- Entries + audit trail (own entries, or corrections by a team manager / admin) ----
// ---- Settings + negative-balance guard ----
db.exec('create table if not exists settings(key text primary key, value text not null)');
const getSetting = (k, d) => { const r = db.prepare('select value from settings where key=?').get(k); return r ? r.value : d; };
const allowNegative = () => getSetting('allow_negative', 'true') === 'true';
const balOf = uid => db.prepare(`select ${BAL} b from entries e where user_id=?`).get(uid).b;
// Runs fn in a transaction; rolls back if it would lower the balance below zero while negatives are disallowed.
// (Changes that don't lower the balance, like adding earned time, are always allowed, so someone already below zero can recover.)
const guard = (uid, fn) => db.transaction(() => {
  const before = balOf(uid), out = fn(), after = balOf(uid);
  if (!allowNegative() && after < 0 && after < before - 1e-9)
    throw Object.assign(new Error(`This would take the balance to ${Math.round(after * 100) / 100}h. Negative balances are turned off.`), { status: 400 });
  return out;
})();
const MIN_DATE = '2026-01-01', MAX_DATE = '2100-12-31'; // allowed entry dates
const valid = b => b && /^\d{4}-\d{2}-\d{2}$/.test(b.date) && b.hours > 0 && b.hours <= 24 && b.date >= MIN_DATE && b.date <= MAX_DATE
  && ['earned', 'taken'].includes(b.type) && (b.type === 'taken' || (b.reason || '').trim().length > 0); // reason optional for time off
const pick = e => e && { date: e.date, hours: e.hours, type: e.type, reason: e.reason };
const log = (eid, owner, actor, action, before, after, note) => db.prepare(
  'insert into audit(entry_id,owner_id,actor_id,action,before,after,note) values(?,?,?,?,?,?,?)')
  .run(eid, owner, actor, action, before && JSON.stringify(before), after && JSON.stringify(after), (note || '').trim() || null);
const P = '/api/people/:uid';
const target = (req, res, next) => {
  const t = db.prepare('select id from users where id=? and active=1').get(+req.params.uid);
  if (!t) return res.status(404).json({ error: 'Not found' });
  req.uid = t.id; req.own = t.id === req.user.id;
  if (!req.own && !canManage(req.user, t.id)) return res.status(403).json({ error: 'Forbidden' });
  next();
};
const noNote = (req, res) => !req.own && !(req.body.note || '').trim()
  && (res.status(400).json({ error: 'A note explaining the correction is required' }), true);

app.get(P + '/entries', auth, target, (req, res) =>
  res.json(db.prepare('select * from entries where user_id=? order by date desc, id desc').all(req.uid)));
app.get(P + '/audit', auth, target, (req, res) =>
  res.json(db.prepare(`select a.*, u.name actor_name, u.email actor_email from audit a join users u on u.id=a.actor_id
    where a.owner_id=? order by a.id desc limit 200`).all(req.uid)));
app.post(P + '/entries', auth, target, (req, res) => {
  if (!valid(req.body)) return res.status(400).json({ error: 'Date, hours (0-24) and type are required, plus a reason for earned time. Dates must be between 2026 and 2100' });
  if (noNote(req, res)) return;
  const b = { ...req.body, reason: (req.body.reason || '').trim() };
  const id = guard(req.uid, () => {
    const id = db.prepare('insert into entries(user_id,date,hours,type,reason) values(?,?,?,?,?)').run(req.uid, b.date, b.hours, b.type, b.reason).lastInsertRowid;
    log(id, req.uid, req.user.id, 'create', null, pick(b), req.body.note); return id;
  });
  res.json({ id });
});
// Time off over several days: one 'taken' entry per day, so each can be edited/deleted on its own
app.post(P + '/entries/range', auth, target, (req, res) => {
  const { from, to, hours, skip_weekends = true } = req.body, reason = (req.body.reason || '').trim(), re = /^\d{4}-\d{2}-\d{2}$/;
  if (!re.test(from || '') || !re.test(to || '') || to < from) return res.status(400).json({ error: 'Choose a valid date range' });
  if (from < MIN_DATE || to > MAX_DATE) return res.status(400).json({ error: 'Dates must be between 2026 and 2100' });
  if (!(hours > 0 && hours <= 24)) return res.status(400).json({ error: 'Hours per day must be between 0 and 24' });
  if (noNote(req, res)) return;
  const days = [], skip = skip_weekends && from !== to; // an explicit single day is never skipped
  for (let d = new Date(from + 'T00:00:00Z'); d.toISOString().slice(0, 10) <= to && days.length <= 60; d.setUTCDate(d.getUTCDate() + 1)) {
    const w = d.getUTCDay(); if (!(skip && (w === 0 || w === 6))) days.push(d.toISOString().slice(0, 10));
  }
  if (!days.length) return res.status(400).json({ error: 'No working days in that range' });
  if (days.length > 60) return res.status(400).json({ error: 'Maximum 60 days at once' });
  guard(req.uid, () => { for (const date of days) {
    const b = { date, hours, type: 'taken', reason };
    const id = db.prepare('insert into entries(user_id,date,hours,type,reason) values(?,?,?,?,?)').run(req.uid, date, hours, 'taken', reason).lastInsertRowid;
    log(id, req.uid, req.user.id, 'create', null, pick(b), req.body.note);
  } });
  res.json({ created: days.length });
});
app.put(P + '/entries/:id', auth, target, (req, res) => {
  if (!valid(req.body)) return res.status(400).json({ error: 'Invalid entry' });
  if (noNote(req, res)) return;
  const old = db.prepare('select * from entries where id=? and user_id=?').get(req.params.id, req.uid);
  if (!old) return res.status(404).json({ error: 'Not found' });
  const b = { ...req.body, reason: (req.body.reason || '').trim() };
  guard(req.uid, () => {
    db.prepare('update entries set date=?,hours=?,type=?,reason=?,updated_at=current_timestamp where id=?').run(b.date, b.hours, b.type, b.reason, old.id);
    log(old.id, req.uid, req.user.id, 'update', pick(old), pick(b), req.body.note);
  });
  res.json({ ok: true });
});
app.delete(P + '/entries/:id', auth, target, (req, res) => {
  if (noNote(req, res)) return;
  const old = db.prepare('select * from entries where id=? and user_id=?').get(req.params.id, req.uid);
  if (!old) return res.status(404).json({ error: 'Not found' });
  guard(req.uid, () => {
    db.prepare('delete from entries where id=?').run(old.id);
    log(old.id, req.uid, req.user.id, 'delete', pick(old), null, req.body.note);
  });
  res.json({ ok: true });
});

// ---- Team views ----
app.get('/api/teams', auth, (req, res) => {
  if (!isManager(req.user)) return res.json([]);
  const ts = req.user.role === 'admin' ? db.prepare('select * from teams order by name').all()
    : db.prepare('select t.* from teams t join team_managers m on m.team_id=t.id where m.user_id=? order by t.name').all(req.user.id);
  const mem = db.prepare('select u.id,u.name,u.email from team_members m join users u on u.id=m.user_id where m.team_id=? and u.active=1 order by u.name,u.email');
  const man = db.prepare('select u.id,u.name,u.email,m.title from team_managers m join users u on u.id=m.user_id where m.team_id=? and u.active=1');
  res.json(ts.map(t => ({ ...t, members: mem.all(t.id), managers: man.all(t.id) })));
});
app.get('/api/teams/:id/summary', auth, (req, res) => {
  if (!isTeamMgr(req.user, +req.params.id)) return res.status(403).json({ error: 'Forbidden' });
  res.json(db.prepare(`select u.id,u.name,u.email, ${BAL} balance,
    coalesce(sum(case e.type when 'earned' then e.hours end),0) earned, coalesce(sum(case e.type when 'taken' then e.hours end),0) taken
    from team_members tm join users u on u.id=tm.user_id left join entries e on e.user_id=u.id
    where tm.team_id=? and u.active=1 group by u.id order by u.name`).all(req.params.id));
});

// ---- Reports: monthly earned/taken, running balance, per-person balances ----
app.get('/api/reports', auth, (req, res) => {
  let ids;
  if (req.query.team_id) {
    if (!isTeamMgr(req.user, +req.query.team_id)) return res.status(403).json({ error: 'Forbidden' });
    ids = db.prepare('select u.id from team_members m join users u on u.id=m.user_id where m.team_id=? and u.active=1').all(req.query.team_id).map(r => r.id);
  } else {
    const uid = +(req.query.user_id || req.user.id);
    if (uid !== req.user.id && !canManage(req.user, uid)) return res.status(403).json({ error: 'Forbidden' });
    ids = [uid];
  }
  const rows = ids.length ? db.prepare(`select u.id,u.name,u.email,e.date,e.hours,e.type from users u left join entries e on e.user_id=u.id
    where u.id in (${ids.map(() => '?').join()})`).all(...ids) : [];
  const people = {}, now = new Date(), months = [], ym = d => d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0'), cur = ym(now);
  // window: 9 months back to at least 3 months ahead, extended to the latest booked entry (max 12 months ahead)
  let last = new Date(now.getFullYear(), now.getMonth() + 3, 1);
  for (const r of rows) if (r.date) { const [y, mo] = r.date.split('-'); const d = new Date(+y, +mo - 1, 1); if (d > last) last = d; }
  const cap = new Date(now.getFullYear(), now.getMonth() + 12, 1); if (last > cap) last = cap;
  for (let d = new Date(now.getFullYear(), now.getMonth() - 8, 1); d <= last; d.setMonth(d.getMonth() + 1))
    months.push({ m: ym(d), future: ym(d) > cur, earned: 0, taken: 0, balance: 0 });
  const todayStr = /^\d{4}-\d{2}-\d{2}$/.test(req.query.today || '') ? req.query.today : new Date().toISOString().slice(0, 10);
  let opening = 0;
  for (const r of rows) {
    const p = people[r.id] ||= { id: r.id, name: r.name || r.email, earned: 0, taken: 0, balance: 0, bal_today: 0, upcoming: 0 };
    if (!r.type) continue;
    const sg = r.type === 'earned' ? 1 : -1; p[r.type] += r.hours; p.balance += sg * r.hours;
    if (r.date <= todayStr) p.bal_today += sg * r.hours; else if (r.type === 'taken') p.upcoming += r.hours; // remaining today vs booked ahead
    const m = months.find(x => x.m === r.date.slice(0, 7));
    if (m) m[r.type] += r.hours; else if (r.date < months[0].m) opening += sg * r.hours;
  }
  let run = opening; for (const m of months) { run += m.earned - m.taken; m.balance = run; }
  const ps = Object.values(people);
  res.json({ people: ps, months, total: { earned: ps.reduce((a, p) => a + p.earned, 0), taken: ps.reduce((a, p) => a + p.taken, 0), balance: ps.reduce((a, p) => a + p.balance, 0),
    bal_today: ps.reduce((a, p) => a + p.bal_today, 0), upcoming: ps.reduce((a, p) => a + p.upcoming, 0) } });
});

// ---- Admin: teams ----
const adm = [auth, role('admin')];
app.get('/api/settings', auth, (req, res) => res.json({ allow_negative: allowNegative() }));
app.put('/api/settings', ...adm, (req, res) => {
  db.prepare("insert into settings(key,value) values('allow_negative',?) on conflict(key) do update set value=excluded.value").run(req.body.allow_negative ? 'true' : 'false');
  res.json({ allow_negative: allowNegative() });
});
app.post('/api/teams', ...adm, (req, res) => {
  const n = (req.body.name || '').trim().slice(0, 80); if (!n) return res.status(400).json({ error: 'Team name required' });
  try { res.json({ id: db.prepare('insert into teams(name) values(?)').run(n).lastInsertRowid }); }
  catch { res.status(400).json({ error: 'A team with that name already exists' }); }
});
app.delete('/api/teams/:id', ...adm, (req, res) => { db.prepare('delete from teams where id=?').run(req.params.id); res.json({ ok: true }); });
app.post('/api/teams/:id/members', ...adm, (req, res) => {
  db.prepare('insert or ignore into team_members values(?,?)').run(req.params.id, req.body.user_id); res.json({ ok: true }); });
app.delete('/api/teams/:id/members/:uid', ...adm, (req, res) => {
  db.prepare('delete from team_members where team_id=? and user_id=?').run(req.params.id, req.params.uid); res.json({ ok: true }); });
app.post('/api/teams/:id/managers', ...adm, (req, res) => {
  const t = ['lead', 'director'].includes(req.body.title) ? req.body.title : 'lead';
  db.prepare('insert or replace into team_managers values(?,?,?)').run(req.params.id, req.body.user_id, t); res.json({ ok: true }); });
app.delete('/api/teams/:id/managers/:uid', ...adm, (req, res) => {
  db.prepare('delete from team_managers where team_id=? and user_id=?').run(req.params.id, req.params.uid); res.json({ ok: true }); });

// ---- Admin: users (one role + team list per person) ----
const LEVELS = ['member', 'lead', 'director', 'admin'];
const setAccess = db.transaction((uid, level, teamIds) => {
  const ids = [...new Set((teamIds || []).map(Number))].filter(id => db.prepare('select 1 from teams where id=?').get(id));
  db.prepare('delete from team_members where user_id=?').run(uid);
  db.prepare('delete from team_managers where user_id=?').run(uid);
  db.prepare('update users set role=? where id=?').run(level === 'admin' ? 'admin' : 'member', uid);
  if (level === 'admin') return; // admins see every team
  for (const t of ids) level === 'member'
    ? db.prepare('insert into team_members values(?,?)').run(t, uid)
    : db.prepare('insert into team_managers values(?,?,?)').run(t, uid, level);
});

// ---- Admin: users (listing) ----
app.get('/api/users', ...adm, (req, res) => {
  const us = db.prepare('select id,email,name,role,active,(password_hash is not null) has_password from users where active=1 order by name,email').all();
  const mem = db.prepare('select t.id,t.name from team_members m join teams t on t.id=m.team_id where m.user_id=? order by t.name');
  const man = db.prepare('select t.id,t.name,m.title from team_managers m join teams t on t.id=m.team_id where m.user_id=? order by t.name');
  res.json(us.map(u => { const mg = man.all(u.id);
    const level = u.role === 'admin' ? 'admin' : mg.some(x => x.title === 'director') ? 'director' : mg.length ? 'lead' : 'member';
    return { ...u, level, teams: level === 'member' ? mem.all(u.id) : mg }; }));
});
app.post('/api/users', ...adm, (req, res) => {
  const { email, name, level = 'member', team_ids = [], password } = req.body;
  if (!LEVELS.includes(level)) return res.status(400).json({ error: 'Invalid role' });
  if (!/^\S+@\S+$/.test(email || '')) return res.status(400).json({ error: 'Valid email required' });
  if (password && !pwOk(password)) return res.status(400).json({ error: 'Password must be at least 10 characters' });
  const e = email.toLowerCase().trim();
  db.prepare('insert into users(email) values(?) on conflict(email) do update set active=1').run(e);
  setAccess(db.prepare('select id from users where email=?').get(e).id, level, team_ids);
  if ((name || '').trim()) db.prepare('update users set name=? where email=?').run(name.trim(), e);
  if (password) db.prepare('update users set password_hash=? where email=?').run(bcrypt.hashSync(password, 12), e);
  res.json({ ok: true });
});
app.put('/api/users/:id/access', ...adm, (req, res) => {
  const { level, team_ids = [], name } = req.body;
  if (!LEVELS.includes(level)) return res.status(400).json({ error: 'Invalid role' });
  if (+req.params.id === req.user.id && level !== 'admin') return res.status(400).json({ error: "You can't remove your own admin role" });
  setAccess(+req.params.id, level, team_ids);
  if (typeof name === 'string') db.prepare('update users set name=? where id=?').run(name.trim() || null, +req.params.id);
  res.json({ ok: true });
});
app.patch('/api/users/:id', ...adm, (req, res) => {
  if (!['member', 'admin'].includes(req.body.role)) return res.status(400).json({ error: 'Invalid role' });
  if (+req.params.id === req.user.id && req.body.role !== 'admin') return res.status(400).json({ error: "You can't remove your own admin role" });
  db.prepare('update users set role=? where id=?').run(req.body.role, req.params.id); res.json({ ok: true });
});
app.post('/api/users/:id/password', ...adm, (req, res) => {
  if (!pwOk(req.body.password)) return res.status(400).json({ error: 'Password must be at least 10 characters' });
  db.prepare('update users set password_hash=? where id=?').run(bcrypt.hashSync(req.body.password, 12), req.params.id); res.json({ ok: true });
});
app.delete('/api/users/:id', ...adm, (req, res) => {
  if (+req.params.id === req.user.id) return res.status(400).json({ error: "You can't remove yourself" });
  db.prepare('update users set active=0 where id=?').run(req.params.id); res.json({ ok: true }); // soft delete keeps history
});

app.use((err, req, res, next) => { // turn thrown errors into JSON instead of an HTML error page
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Server error' });
});
app.listen(process.env.PORT || 3000, () => console.log('TOIL Tracker running'));
