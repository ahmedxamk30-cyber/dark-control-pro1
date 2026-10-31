/*
 * DARK CONTROL PRO: Worker entry + ControlRoom Durable Object (SQLite storage).
 * Secrets, set in Cloudflare and never written in code:
 *   MASTER_KEY  (32+ random characters) encrypts bot tokens and provider API keys.
 *   SETUP_TOKEN (random) is used once to create the owner account.
 */

const PERMS = ['bots', 'providers', 'services', 'orders', 'customers', 'logs'];
const SESSION_MS = 12 * 3600 * 1000;
const STATUS_AR = { pending: 'قيد الانتظار', processing: 'قيد التنفيذ', completed: 'مكتمل', partial: 'مكتمل جزئياً', canceled: 'ملغي', failed: 'فشل' };
const WELCOME = 'أهلاً بك. الأوامر المتاحة:\n/services عرض الخدمات\n/order <رقم الخدمة> <الكمية> <الرابط>\n/status <رقم الطلب>\n/balance رصيدك';
const DEFAULT_MAPPING = {
  key_field: 'key', action_field: 'action', format: 'form',
  actions: { add: 'add', status: 'status', balance: 'balance' },
  fields: { service: 'service', link: 'link', quantity: 'quantity', order: 'order' },
  response: { order: 'order', status: 'status', balance: 'balance', error: 'error' },
};
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, perms TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS providers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, api_url TEXT NOT NULL, api_key_enc TEXT NOT NULL, key_last4 TEXT NOT NULL, mapping TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS bots (id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_enc TEXT NOT NULL, token_last4 TEXT NOT NULL, username TEXT, provider_id INTEGER, require_balance INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'stopped', webhook_hash TEXT, last_update_id INTEGER, last_update_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, provider_id INTEGER NOT NULL, provider_service_id TEXT NOT NULL, name TEXT NOT NULL, price_per_1000 INTEGER NOT NULL, min_qty INTEGER NOT NULL DEFAULT 1, max_qty INTEGER NOT NULL DEFAULT 1000000, UNIQUE (provider_id, provider_service_id));
CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, bot_id INTEGER NOT NULL, tg_user_id TEXT NOT NULL, tg_username TEXT, balance INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE (bot_id, tg_user_id));
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, bot_id INTEGER NOT NULL, customer_id INTEGER NOT NULL, service_id INTEGER NOT NULL, quantity INTEGER NOT NULL, link TEXT NOT NULL, price INTEGER NOT NULL, charged INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, provider_order_id TEXT, provider_response TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS order_events (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, status TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, amount INTEGER NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, category TEXT NOT NULL, level TEXT NOT NULL, bot_id INTEGER, actor TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
`;

// ---------- helpers ----------
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256Hex = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const safeEq = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};
const scrub = (text, secrets = []) => {
  let out = String(text);
  for (const s of secrets) if (s) out = out.split(s).join('••••');
  return out.replace(/\d{5,}:[A-Za-z0-9_-]{20,}/g, '[token]');
};
const normalizeStatus = (s) => {
  const v = String(s ?? '').toLowerCase();
  if (v.includes('partial')) return 'partial';
  if (v.includes('complet')) return 'completed';
  if (v.includes('cancel')) return 'canceled';
  if (/fail|error|refund/.test(v)) return 'failed';
  return 'processing';
};
const cookie = (token, maxAge) => `dcp=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const mergeMapping = (m = {}) => ({
  ...DEFAULT_MAPPING, ...m,
  actions: { ...DEFAULT_MAPPING.actions, ...m.actions },
  fields: { ...DEFAULT_MAPPING.fields, ...m.fields },
  response: { ...DEFAULT_MAPPING.response, ...m.response },
});

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers },
});

// ---------- encryption (AES-GCM, key derived from MASTER_KEY) ----------
let keyMemo = null;
async function aesKey(env) {
  if (!env.MASTER_KEY || env.MASTER_KEY.length < 32) throw new HttpError(500, 'MASTER_KEY غير مضبوط في أسرار Cloudflare');
  if (!keyMemo || keyMemo.src !== env.MASTER_KEY) {
    const raw = await crypto.subtle.digest('SHA-256', enc.encode(env.MASTER_KEY));
    keyMemo = { src: env.MASTER_KEY, key: await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']) };
  }
  return keyMemo.key;
}
async function seal(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(env), enc.encode(text));
  return `${b64(iv)}.${b64(ct)}`;
}
async function unseal(env, value) {
  const [iv, ct] = value.split('.');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await aesKey(env), unb64(ct));
  return new TextDecoder().decode(plain);
}

// ---------- passwords (PBKDF2-SHA256) ----------
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256));
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$100000$${b64(salt)}$${b64(await pbkdf2(password, salt, 100000))}`;
}
async function checkPassword(password, stored) {
  const [, iterations, salt, hash] = stored.split('$');
  return safeEq(b64(await pbkdf2(password, unb64(salt), Number(iterations))), hash);
}

// ---------- Telegram Bot API ----------
async function tg(token, method, payload = {}) {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000),
  });
  const data = await res.json().catch(() => ({}));
  if (!data.ok) throw new Error(data.description || `فشل الطلب إلى تيليجرام (${res.status})`);
  return data.result;
}

// ---------- Durable Object ----------
export class ControlRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    state.blockConcurrencyWhile(async () => {
      for (const stmt of SCHEMA.split(';')) if (stmt.trim()) this.sql.exec(stmt);
    });
    this.table = this.routes();
  }

  q(text, ...args) { return this.sql.exec(text, ...args).toArray(); }
  one(text, ...args) { return this.q(text, ...args)[0] ?? null; }
  run(text, ...args) { return this.sql.exec(text, ...args); }
  need(text, args, message, status = 404) {
    const row = this.one(text, ...args);
    if (!row) throw new HttpError(status, message);
    return row;
  }
  money(n) { return `${(Number(n) / 100).toFixed(2)} ${this.env.CURRENCY || 'USD'}`; }
  log(category, level, message, o = {}) {
    this.run('INSERT INTO logs (category, level, bot_id, actor, message) VALUES (?, ?, ?, ?, ?)',
      category, level, o.bot_id ?? null, o.actor || 'system', scrub(message, o.secrets).slice(0, 600));
  }
  event(orderId, status, note) {
    this.run('INSERT INTO order_events (order_id, status, note) VALUES (?, ?, ?)', orderId, status, note);
  }

  checkName(name) {
    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(name)) throw new HttpError(400, 'اسم المستخدم من 3 إلى 32 حرفاً إنجليزياً أو أرقام');
  }
  checkPass(pw) {
    if (typeof pw !== 'string' || pw.length < 10) throw new HttpError(400, 'كلمة المرور 10 أحرف على الأقل');
  }
  providerOrNull(v) {
    if (v == null || v === '') return null;
    return this.need('SELECT id FROM providers WHERE id = ?', [Number(v) || 0], 'المزود غير موجود', 400).id;
  }
  async verifyToken(token) {
    try { return await tg(token, 'getMe'); }
    catch (e) { throw new HttpError(400, `فشل التحقق من التوكن لدى تيليجرام: ${e.message}`); }
  }

  async body(req) {
    if (!(req.headers.get('content-type') || '').includes('application/json')) throw new HttpError(415, 'أرسل البيانات بصيغة JSON');
    try { return (await req.json()) ?? {}; }
    catch { throw new HttpError(400, 'بيانات الطلب غير صالحة'); }
  }

  async session(req) {
    const m = /(?:^|;\s*)dcp=([a-f0-9]{64})/.exec(req.headers.get('cookie') || '');
    if (!m) return null;
    const tokenHash = await sha256Hex(m[1]);
    const s = this.one('SELECT s.expires_at, u.id, u.username, u.role, u.perms FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?', tokenHash);
    return s && s.expires_at > Date.now()
      ? { id: s.id, username: s.username, role: s.role, perms: JSON.parse(s.perms), tokenHash }
      : null;
  }
  // perm: undefined = any signed-in user, 'owner' = owner only, otherwise a permission name.
  async auth(req, perm) {
    const u = await this.session(req);
    if (!u) throw new HttpError(401, 'يجب تسجيل الدخول أولاً');
    if (perm && u.role !== 'owner' && (perm === 'owner' || !u.perms.includes(perm))) throw new HttpError(403, 'ليست لديك صلاحية لهذا الإجراء');
    return u;
  }

  providerInput(b, create) {
    const out = {};
    if (create || b.name !== undefined) {
      out.name = String(b.name ?? '').trim();
      if (!out.name || out.name.length > 60) throw new HttpError(400, 'اكتب اسماً للمزود (60 حرفاً كحد أقصى)');
    }
    if (create || b.api_url !== undefined) {
      let u = null;
      try { u = new URL(String(b.api_url ?? '').trim()); } catch {}
      if (!u || u.protocol !== 'https:') throw new HttpError(400, 'رابط الـ API يجب أن يبدأ بـ https://');
      out.api_url = u.href;
    }
    const apiKey = b.api_key == null ? '' : String(b.api_key).trim();
    if (apiKey) out.api_key = apiKey;
    else if (create) throw new HttpError(400, 'أدخل مفتاح الـ API');
    if (b.mapping !== undefined) {
      let m = {};
      try { m = String(b.mapping).trim() ? JSON.parse(String(b.mapping)) : {}; }
      catch { throw new HttpError(400, 'إعدادات الربط ليست JSON صالحاً'); }
      out.mapping = JSON.stringify(mergeMapping(m));
    } else if (create) out.mapping = JSON.stringify(mergeMapping({}));
    return out;
  }

  // Generic provider call. Field and action names come from the provider's mapping, so any API can be connected.
  async providerCall(providerId, action, params, meta = {}) {
    const p = this.need('SELECT * FROM providers WHERE id = ?', [providerId], 'المزود غير موجود');
    const m = JSON.parse(p.mapping);
    const apiKey = await unseal(this.env, p.api_key_enc);
    const body = { [m.key_field]: apiKey, [m.action_field]: m.actions[action] };
    for (const [k, v] of Object.entries(params)) body[m.fields[k] || k] = v;
    const asJson = m.format === 'json';
    const fail = (error) => {
      this.log('api', 'error', `${p.name} · ${action}: ${error}`, { bot_id: meta.bot_id, actor: meta.actor, secrets: [apiKey] });
      return { ok: false, error, fields: {}, raw: '' };
    };
    let res;
    let text;
    try {
      res = await fetch(p.api_url, {
        method: 'POST',
        headers: { 'content-type': asJson ? 'application/json' : 'application/x-www-form-urlencoded' },
        body: asJson ? JSON.stringify(body) : new URLSearchParams(Object.entries(body).map(([k, v]) => [k, String(v)])).toString(),
        signal: AbortSignal.timeout(20000),
      });
      text = await res.text();
    } catch (e) {
      return fail(`تعذر الاتصال بالمزود: ${e.message}`);
    }
    let data;
    try { data = JSON.parse(text); } catch { data = null; }
    if (!data || typeof data !== 'object') data = { raw: text };
    const r = m.response;
    const providerError = data[r.error];
    if (!res.ok || providerError) return fail(String(providerError || `HTTP ${res.status}`));
    this.log('api', 'info', `${p.name} · ${action}: نجح`, { bot_id: meta.bot_id, actor: meta.actor, secrets: [apiKey] });
    return {
      ok: true,
      error: '',
      fields: { order: data[r.order], status: data[r.status], balance: data[r.balance] },
      raw: scrub(text, [apiKey]).slice(0, 2000),
    };
  }

  async refreshOrder(id) {
    const o = this.need(
      'SELECT o.id, o.bot_id, o.status, o.provider_order_id, s.provider_id FROM orders o LEFT JOIN services s ON s.id = o.service_id WHERE o.id = ?',
      [id], 'الطلب غير موجود');
    if (!o.provider_order_id) throw new HttpError(400, 'لم يُرسل هذا الطلب إلى المزود بعد');
    const r = await this.providerCall(o.provider_id, 'status', { order: o.provider_order_id }, { bot_id: o.bot_id, actor: 'system' });
    if (!r.ok) throw new HttpError(502, r.error);
    const status = normalizeStatus(r.fields.status);
    if (status !== o.status) {
      this.run("UPDATE orders SET status = ?, provider_response = ?, updated_at = datetime('now') WHERE id = ?", status, r.raw, id);
      this.event(id, status, `حالة المزود: ${r.fields.status}`);
    }
    return status;
  }

  async webhook(req, url) {
    const bot = this.one('SELECT * FROM bots WHERE id = ?', Number(url.pathname.split('/')[2]) || 0);
    if (!bot || !bot.webhook_hash) return new Response('not found', { status: 404 });
    if (!safeEq(await sha256Hex(req.headers.get('x-telegram-bot-api-secret-token') || ''), bot.webhook_hash)) {
      return new Response('forbidden', { status: 403 });
    }
    if (!bot.enabled) return new Response('ok');
    const update = await req.json().catch(() => null);
    if (!update || !Number.isInteger(update.update_id)) return new Response('ok');
    // Telegram retries on failure: a repeated update_id is ignored, so no duplicate orders.
    const fresh = this.run(
      "UPDATE bots SET last_update_id = ?, last_update_at = datetime('now') WHERE id = ? AND (last_update_id IS NULL OR last_update_id < ?)",
      update.update_id, bot.id, update.update_id).rowsWritten;
    if (fresh) {
      this.state.waitUntil(this.handleUpdate(bot, update).catch((e) =>
        this.log('bot', 'error', `معالجة التحديث فشلت: ${e.message}`, { bot_id: bot.id, actor: 'telegram' })));
    }
    return new Response('ok');
  }

  async handleUpdate(bot, update) {
    const msg = update.message;
    if (!msg || typeof msg.text !== 'string' || !msg.chat || !msg.from?.id) return;
    const token = await unseal(this.env, bot.token_enc);
    const send = (text) => tg(token, 'sendMessage', { chat_id: msg.chat.id, text }).catch((e) =>
      this.log('bot', 'error', `تعذر إرسال الرد: ${e.message}`, { bot_id: bot.id, actor: 'telegram', secrets: [token] }));
    const tgId = String(msg.from.id);
    this.run(
      'INSERT INTO customers (bot_id, tg_user_id, tg_username) VALUES (?, ?, ?) ON CONFLICT (bot_id, tg_user_id) DO UPDATE SET tg_username = COALESCE(excluded.tg_username, customers.tg_username)',
      bot.id, tgId, msg.from.username || null);
    const cust = this.one('SELECT * FROM customers WHERE bot_id = ? AND tg_user_id = ?', bot.id, tgId);
    const [head = '', ...args] = msg.text.trim().split(/\s+/);
    const cmd = head.split('@')[0].toLowerCase();

    if (cmd === '/start' || cmd === '/help') return send(WELCOME);
    if (cmd === '/balance') return send(`رصيدك: ${this.money(cust.balance)}`);
    if (cmd === '/services') {
      const rows = bot.provider_id
        ? this.q('SELECT provider_service_id, name, price_per_1000 FROM services WHERE provider_id = ? ORDER BY id LIMIT 30', bot.provider_id)
        : [];
      return send(rows.length
        ? rows.map((s) => `${s.provider_service_id} — ${s.name} — ${this.money(s.price_per_1000)} لكل 1000`).join('\n')
        : 'لا توجد خدمات متاحة حالياً.');
    }
    if (cmd === '/status') {
      const o = this.one('SELECT id, status, provider_order_id FROM orders WHERE id = ? AND customer_id = ?', Number(args[0]) || 0, cust.id);
      if (!o) return send('لم أجد طلباً بهذا الرقم.');
      if (!o.provider_order_id) return send(`حالة الطلب ${o.id}: ${STATUS_AR[o.status] || o.status}`);
      try { return send(`حالة الطلب ${o.id}: ${STATUS_AR[await this.refreshOrder(o.id)]}`); }
      catch (e) { return send(`تعذر جلب الحالة الآن: ${e.message}`); }
    }
    if (cmd === '/order') {
      const [sid = '', qtyText = '', ...rest] = args;
      const link = rest.join(' ');
      const qty = Number(qtyText);
      const svc = bot.provider_id
        ? this.one('SELECT * FROM services WHERE provider_id = ? AND provider_service_id = ?', bot.provider_id, sid)
        : null;
      if (!svc) return send('هذه الخدمة غير متاحة. أرسل /services لعرض الخدمات.');
      if (!Number.isInteger(qty) || qty < svc.min_qty || qty > svc.max_qty) return send(`الكمية يجب أن تكون بين ${svc.min_qty} و${svc.max_qty}.`);
      if (!/^https?:\/\/\S+$/.test(link)) return send('أرسل الرابط بعد الكمية، ويبدأ بـ https://');
      const price = Math.ceil((qty * svc.price_per_1000) / 1000);
      const charge = bot.require_balance === 1;
      if (charge && cust.balance < price) return send(`رصيدك ${this.money(cust.balance)} غير كافٍ. سعر الطلب ${this.money(price)}.`);
      if (charge) {
        this.run('UPDATE customers SET balance = balance - ? WHERE id = ?', price, cust.id);
        this.run('INSERT INTO ledger (customer_id, amount, reason, actor) VALUES (?, ?, ?, ?)', cust.id, -price, 'خصم قيمة طلب', 'telegram');
      }
      this.run(
        'INSERT INTO orders (bot_id, customer_id, service_id, quantity, link, price, charged, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        bot.id, cust.id, svc.id, qty, link, price, charge ? 1 : 0, 'pending');
      const orderId = this.one('SELECT last_insert_rowid() AS id').id;
      this.event(orderId, 'pending', 'استُلم من البوت');
      const r = await this.providerCall(bot.provider_id, 'add', { service: svc.provider_service_id, link, quantity: qty }, { bot_id: bot.id, actor: 'telegram' });
      if (r.ok && r.fields.order != null && r.fields.order !== '') {
        this.run("UPDATE orders SET status = 'processing', provider_order_id = ?, provider_response = ?, updated_at = datetime('now') WHERE id = ?",
          String(r.fields.order), r.raw, orderId);
        this.event(orderId, 'processing', 'أُرسل إلى المزود');
        return send(`تم استلام طلبك رقم ${orderId}، وهو قيد التنفيذ.`);
      }
      this.run("UPDATE orders SET status = 'failed', provider_response = ?, updated_at = datetime('now') WHERE id = ?", r.raw, orderId);
      this.event(orderId, 'failed', r.error || 'لم يُرجع المزود رقم الطلب');
      if (charge) {
        this.run('UPDATE customers SET balance = balance + ? WHERE id = ?', price, cust.id);
        this.run('INSERT INTO ledger (customer_id, amount, reason, actor) VALUES (?, ?, ?, ?)', cust.id, price, `استرداد الطلب ${orderId}`, 'system');
      }
      return send(`تعذر تنفيذ الطلب${charge ? '، وأُعيد المبلغ إلى رصيدك' : ''}.`);
    }
    return send(WELCOME);
  }

  routes() {
    const R = [];
    const on = (method, path, fn) => R.push([method, new RegExp(`^${path}$`), fn]);
    const ID = '(\\d+)';
    const usersCount = () => this.one('SELECT COUNT(*) AS n FROM users').n;

    on('GET', '/api/me', async (req) => {
      const u = await this.session(req);
      return json({
        setup_required: usersCount() === 0,
        user: u && { username: u.username, role: u.role, perms: u.perms },
        currency: this.env.CURRENCY || 'USD',
      });
    });

    on('POST', '/api/setup', async (req) => {
      const { username = '', password = '', setup_token = '' } = await this.body(req);
      if (!this.env.SETUP_TOKEN || !safeEq(String(setup_token), this.env.SETUP_TOKEN)) throw new HttpError(403, 'رمز الإعداد غير صحيح');
      this.checkName(String(username));
      this.checkPass(password);
      const hash = await hashPassword(password);
      if (usersCount() > 0) throw new HttpError(403, 'تم إعداد النظام مسبقاً');
      this.run("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'owner')", String(username), hash);
      this.log('admin', 'info', `أُنشئ حساب المالك ${username}`, { actor: String(username) });
      return json({ ok: true }, 201);
    });

    on('POST', '/api/login', async (req) => {
      const { username = '', password = '' } = await this.body(req);
      const user = this.one('SELECT * FROM users WHERE username = ?', String(username));
      if (!user || typeof password !== 'string' || !(await checkPassword(password, user.password_hash))) {
        this.log('login', 'warn', 'محاولة دخول فاشلة', { actor: String(username).slice(0, 32) });
        throw new HttpError(401, 'اسم المستخدم أو كلمة المرور غير صحيحة');
      }
      const token = randHex(32);
      this.run('DELETE FROM sessions WHERE expires_at < ?', Date.now());
      this.run('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)', await sha256Hex(token), user.id, Date.now() + SESSION_MS);
      this.log('login', 'info', 'تسجيل دخول ناجح', { actor: user.username });
      return json({ ok: true }, 200, { 'set-cookie': cookie(token, SESSION_MS / 1000) });
    });

    on('POST', '/api/logout', async (req) => {
      const u = await this.session(req);
      if (u) this.run('DELETE FROM sessions WHERE token_hash = ?', u.tokenHash);
      return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
    });

    on('POST', '/api/account/password', async (req) => {
      const u = await this.auth(req);
      const { current = '', next = '' } = await this.body(req);
      const row = this.one('SELECT password_hash FROM users WHERE id = ?', u.id);
      if (typeof current !== 'string' || !(await checkPassword(current, row.password_hash))) throw new HttpError(403, 'كلمة المرور الحالية غير صحيحة');
      this.checkPass(next);
      this.run('UPDATE users SET password_hash = ? WHERE id = ?', await hashPassword(next), u.id);
      this.run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', u.id, u.tokenHash);
      this.log('admin', 'info', 'غُيّرت كلمة المرور', { actor: u.username });
      return json({ ok: true });
    });

    on('POST', '/api/account/revoke-sessions', async (req) => {
      const u = await this.auth(req);
      this.run('DELETE FROM sessions WHERE user_id = ?', u.id);
      this.log('admin', 'warn', 'أُنهيت جميع الجلسات', { actor: u.username });
      return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
    });

    on('GET', '/api/dashboard', async (req) => {
      await this.auth(req);
      const counts = (text) => Object.fromEntries(this.q(text).map((r) => [r.k, r.n]));
      const days = Array.from({ length: 7 }, (_, i) => new Date(Date.now() - (6 - i) * 864e5).toISOString().slice(0, 10));
      const perDay = counts("SELECT substr(created_at, 1, 10) AS k, COUNT(*) AS n FROM orders WHERE created_at >= datetime('now', '-6 days') GROUP BY k");
      return json({
        bots: counts('SELECT status AS k, COUNT(*) AS n FROM bots GROUP BY status'),
        orders: counts('SELECT status AS k, COUNT(*) AS n FROM orders GROUP BY status'),
        customers: this.one('SELECT COUNT(*) AS n FROM customers').n,
        series: days.map((d) => ({ day: d.slice(5), n: perDay[d] || 0 })),
        alerts: this.q("SELECT id, name FROM bots WHERE status = 'error'"),
        recent: this.q('SELECT category, level, message, created_at FROM logs ORDER BY id DESC LIMIT 8'),
      });
    });

    // ----- bots -----
    on('GET', '/api/bots', async (req) => {
      await this.auth(req, 'bots');
      return json(this.q('SELECT b.id, b.name, b.username, b.token_last4, b.provider_id, p.name AS provider_name, b.require_balance, b.enabled, b.status, b.last_update_at FROM bots b LEFT JOIN providers p ON p.id = b.provider_id ORDER BY b.id'));
    });

    on('POST', '/api/bots', async (req) => {
      const u = await this.auth(req, 'bots');
      const b = await this.body(req);
      const name = String(b.name ?? '').trim();
      const token = String(b.token ?? '').trim();
      if (!name || name.length > 60) throw new HttpError(400, 'اكتب اسماً للبوت (60 حرفاً كحد أقصى)');
      if (!/^\d{5,}:[A-Za-z0-9_-]{20,}$/.test(token)) throw new HttpError(400, 'صيغة توكن البوت غير صحيحة');
      const providerId = this.providerOrNull(b.provider_id);
      const me = await this.verifyToken(token);
      this.run(
        'INSERT INTO bots (name, token_enc, token_last4, username, provider_id, require_balance) VALUES (?, ?, ?, ?, ?, ?)',
        name, await seal(this.env, token), token.slice(-4), me.username || null, providerId, b.require_balance === false ? 0 : 1);
      this.log('admin', 'info', `أُضيف البوت @${me.username || name}`, { actor: u.username });
      return json({ ok: true }, 201);
    });

    on('PATCH', `/api/bots/${ID}`, async (req, url, id) => {
      const u = await this.auth(req, 'bots');
      const b = await this.body(req);
      this.need('SELECT id FROM bots WHERE id = ?', [Number(id)], 'البوت غير موجود');
      const sets = [];
      const args = [];
      if (b.name !== undefined) {
        const name = String(b.name).trim();
        if (!name || name.length > 60) throw new HttpError(400, 'اكتب اسماً للبوت (60 حرفاً كحد أقصى)');
        sets.push('name = ?');
        args.push(name);
      }
      if (b.provider_id !== undefined) { sets.push('provider_id = ?'); args.push(this.providerOrNull(b.provider_id)); }
      if (b.require_balance !== undefined) { sets.push('require_balance = ?'); args.push(b.require_balance ? 1 : 0); }
      const token = String(b.token ?? '').trim();
      if (token) {
        if (!/^\d{5,}:[A-Za-z0-9_-]{20,}$/.test(token)) throw new HttpError(400, 'صيغة توكن البوت غير صحيحة');
        const me = await this.verifyToken(token);
        sets.push('token_enc = ?', 'token_last4 = ?', 'username = ?', 'enabled = 0', "status = 'stopped'", 'webhook_hash = NULL');
        args.push(await seal(this.env, token), token.slice(-4), me.username || null);
      }
      if (sets.length) this.run(`UPDATE bots SET ${sets.join(', ')} WHERE id = ?`, ...args, Number(id));
      this.log('admin', 'info', 'حُدّثت إعدادات البوت', { actor: u.username });
      return json({ ok: true });
    });

    on('DELETE', `/api/bots/${ID}`, async (req, url, id) => {
      const u = await this.auth(req, 'bots');
      const bot = this.need('SELECT * FROM bots WHERE id = ?', [Number(id)], 'البوت غير موجود');
      if (bot.enabled) await tg(await unseal(this.env, bot.token_enc), 'deleteWebhook').catch(() => {});
      this.run('DELETE FROM customers WHERE bot_id = ?', bot.id);
      this.run('DELETE FROM bots WHERE id = ?', bot.id);
      this.log('admin', 'warn', `حُذف البوت @${bot.username || bot.name}`, { actor: u.username });
      return json({ ok: true });
    });

    on('POST', `/api/bots/${ID}/test`, async (req, url, id) => {
      await this.auth(req, 'bots');
      const bot = this.need('SELECT * FROM bots WHERE id = ?', [Number(id)], 'البوت غير موجود');
      const token = await unseal(this.env, bot.token_enc);
      try {
        const me = await tg(token, 'getMe');
        this.run('UPDATE bots SET username = ? WHERE id = ?', me.username || null, bot.id);
        return json({ ok: true, username: me.username, last_update_at: bot.last_update_at });
      } catch (e) {
        this.run("UPDATE bots SET status = 'error' WHERE id = ?", bot.id);
        this.log('bot', 'error', `فشل اختبار الاتصال: ${e.message}`, { bot_id: bot.id, actor: 'admin', secrets: [token] });
        return json({ ok: false, error: e.message });
      }
    });

    on('POST', `/api/bots/${ID}/webhook`, async (req, url, id) => {
      const u = await this.auth(req, 'bots');
      const { enabled } = await this.body(req);
      const bot = this.need('SELECT * FROM bots WHERE id = ?', [Number(id)], 'البوت غير موجود');
      const token = await unseal(this.env, bot.token_enc);
      try {
        if (enabled) {
          const secret = randHex(24);
          await tg(token, 'setWebhook', { url: `${new URL(req.url).origin}/webhook/${bot.id}`, secret_token: secret, allowed_updates: ['message'] });
          this.run("UPDATE bots SET enabled = 1, status = 'active', webhook_hash = ? WHERE id = ?", await sha256Hex(secret), bot.id);
        } else {
          await tg(token, 'deleteWebhook');
          this.run("UPDATE bots SET enabled = 0, status = 'stopped' WHERE id = ?", bot.id);
        }
      } catch (e) {
        this.run("UPDATE bots SET status = 'error' WHERE id = ?", bot.id);
        this.log('bot', 'error', `تعذر ${enabled ? 'تشغيل' : 'إيقاف'} الاستقبال: ${e.message}`, { bot_id: bot.id, actor: u.username, secrets: [token] });
        throw new HttpError(502, e.message);
      }
      this.log('bot', 'info', enabled ? 'بدأ استقبال التحديثات' : 'أُوقف استقبال التحديثات', { bot_id: bot.id, actor: u.username });
      return json({ ok: true });
    });

    // ----- providers -----
    on('GET', '/api/providers', async (req) => {
      await this.auth(req, 'providers');
      return json(this.q('SELECT id, name, api_url, key_last4, mapping, created_at FROM providers ORDER BY id'));
    });

    on('POST', '/api/providers', async (req) => {
      const u = await this.auth(req, 'providers');
      const p = this.providerInput(await this.body(req), true);
      this.run('INSERT INTO providers (name, api_url, api_key_enc, key_last4, mapping) VALUES (?, ?, ?, ?, ?)',
        p.name, p.api_url, await seal(this.env, p.api_key), p.api_key.slice(-4), p.mapping);
      this.log('admin', 'info', `أُضيف مزود ${p.name}`, { actor: u.username });
      return json({ ok: true }, 201);
    });

    on('PATCH', `/api/providers/${ID}`, async (req, url, id) => {
      const u = await this.auth(req, 'providers');
      const f = this.providerInput(await this.body(req), false);
      this.need('SELECT id FROM providers WHERE id = ?', [Number(id)], 'المزود غير موجود');
      const sets = [];
      const args = [];
      for (const k of ['name', 'api_url', 'mapping']) if (f[k] !== undefined) { sets.push(`${k} = ?`); args.push(f[k]); }
      if (f.api_key) { sets.push('api_key_enc = ?', 'key_last4 = ?'); args.push(await seal(this.env, f.api_key), f.api_key.slice(-4)); }
      if (sets.length) this.run(`UPDATE providers SET ${sets.join(', ')} WHERE id = ?`, ...args, Number(id));
      this.log('admin', 'info', 'حُدّث المزود', { actor: u.username });
      return json({ ok: true });
    });

    on('DELETE', `/api/providers/${ID}`, async (req, url, id) => {
      const u = await this.auth(req, 'providers');
      const used = this.one('SELECT COUNT(*) AS n FROM bots WHERE provider_id = ?', Number(id)).n;
      if (used) throw new HttpError(409, `المزود مرتبط بـ ${used} بوت. غيّر ربط البوتات أولاً.`);
      this.run('DELETE FROM services WHERE provider_id = ?', Number(id));
      this.run('DELETE FROM providers WHERE id = ?', Number(id));
      this.log('admin', 'warn', 'حُذف مزود API', { actor: u.username });
      return json({ ok: true });
    });

    on('POST', `/api/providers/${ID}/test`, async (req, url, id) => {
      await this.auth(req, 'providers');
      const r = await this.providerCall(Number(id), 'balance', {}, { actor: 'admin' });
      return json({ ok: r.ok, error: r.error, balance: r.fields.balance ?? null });
    });

    // ----- services -----
    on('GET', '/api/services', async (req) => {
      await this.auth(req, 'services');
      return json(this.q('SELECT s.*, p.name AS provider_name FROM services s JOIN providers p ON p.id = s.provider_id ORDER BY s.id DESC'));
    });

    on('POST', '/api/services', async (req) => {
      await this.auth(req, 'services');
      const b = await this.body(req);
      const pid = this.need('SELECT id FROM providers WHERE id = ?', [Number(b.provider_id) || 0], 'اختر مزوداً صالحاً', 400).id;
      const sid = String(b.provider_service_id ?? '').trim();
      const name = String(b.name ?? '').trim();
      const price = Number(b.price_per_1000);
      const min = Number(b.min_qty ?? 1);
      const max = Number(b.max_qty ?? 1000000);
      if (!sid || !name) throw new HttpError(400, 'أدخل رقم الخدمة لدى المزود واسمها');
      if (!Number.isInteger(price) || price < 0 || !Number.isInteger(min) || !Number.isInteger(max) || min < 1 || max < min) {
        throw new HttpError(400, 'تحقق من السعر والحد الأدنى والأقصى (أرقام صحيحة)');
      }
      try {
        this.run('INSERT INTO services (provider_id, provider_service_id, name, price_per_1000, min_qty, max_qty) VALUES (?, ?, ?, ?, ?, ?)', pid, sid, name, price, min, max);
      } catch (e) {
        if (/UNIQUE/i.test(e.message)) throw new HttpError(409, 'هذه الخدمة مضافة لهذا المزود بالفعل');
        throw e;
      }
      return json({ ok: true }, 201);
    });

    on('DELETE', `/api/services/${ID}`, async (req, url, id) => {
      await this.auth(req, 'services');
      this.run('DELETE FROM services WHERE id = ?', Number(id));
      return json({ ok: true });
    });

    // ----- orders -----
    on('GET', '/api/orders', async (req, url) => {
      await this.auth(req, 'orders');
      const where = [];
      const args = [];
      const status = url.searchParams.get('status');
      const botId = url.searchParams.get('bot_id');
      if (status) { where.push('o.status = ?'); args.push(status); }
      if (botId) { where.push('o.bot_id = ?'); args.push(Number(botId) || 0); }
      return json(this.q(
        `SELECT o.id, o.bot_id, b.name AS bot_name, c.tg_username, c.tg_user_id, s.name AS service_name, o.quantity, o.link, o.price, o.charged, o.status, o.provider_order_id, o.created_at, o.updated_at
         FROM orders o LEFT JOIN bots b ON b.id = o.bot_id LEFT JOIN customers c ON c.id = o.customer_id LEFT JOIN services s ON s.id = o.service_id
         ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY o.id DESC LIMIT 200`, ...args));
    });

    on('GET', `/api/orders/${ID}`, async (req, url, id) => {
      await this.auth(req, 'orders');
      const o = this.need('SELECT o.*, s.name AS service_name FROM orders o LEFT JOIN services s ON s.id = o.service_id WHERE o.id = ?', [Number(id)], 'الطلب غير موجود');
      return json({ ...o, events: this.q('SELECT status, note, created_at FROM order_events WHERE order_id = ? ORDER BY id', o.id) });
    });

    on('POST', `/api/orders/${ID}/refresh`, async (req, url, id) => {
      await this.auth(req, 'orders');
      return json({ ok: true, status: await this.refreshOrder(Number(id)) });
    });

    // ----- customers and balances -----
    on('GET', '/api/customers', async (req) => {
      await this.auth(req, 'customers');
      return json(this.q(
        'SELECT c.id, c.bot_id, b.name AS bot_name, c.tg_user_id, c.tg_username, c.balance, c.created_at, (SELECT COUNT(*) FROM orders o WHERE o.customer_id = c.id) AS orders_count FROM customers c LEFT JOIN bots b ON b.id = c.bot_id ORDER BY c.id DESC LIMIT 300'));
    });

    on('GET', `/api/customers/${ID}/ledger`, async (req, url, id) => {
      await this.auth(req, 'customers');
      return json(this.q('SELECT amount, reason, actor, created_at FROM ledger WHERE customer_id = ? ORDER BY id DESC LIMIT 200', Number(id)));
    });

    on('POST', `/api/customers/${ID}/balance`, async (req, url, id) => {
      const u = await this.auth(req, 'owner');
      const { amount, reason = '' } = await this.body(req);
      const amt = Number(amount);
      const note = String(reason).trim();
      if (!Number.isInteger(amt) || amt === 0) throw new HttpError(400, 'أدخل مبلغاً صحيحاً غير صفري');
      if (note.length < 3) throw new HttpError(400, 'اكتب سبب التعديل (3 أحرف على الأقل)');
      const cust = this.need('SELECT id FROM customers WHERE id = ?', [Number(id)], 'العميل غير موجود');
      const res = this.run('UPDATE customers SET balance = balance + ? WHERE id = ? AND balance + ? >= 0', amt, cust.id, amt);
      if (!res.rowsWritten) throw new HttpError(400, 'الرصيد لا يكفي لهذا الخصم');
      this.run('INSERT INTO ledger (customer_id, amount, reason, actor) VALUES (?, ?, ?, ?)', cust.id, amt, note.slice(0, 200), u.username);
      this.log('admin', 'warn', `عُدّل رصيد عميل بمقدار ${amt}`, { actor: u.username });
      return json({ ok: true });
    });

    // ----- logs -----
    on('GET', '/api/logs', async (req, url) => {
      await this.auth(req, 'logs');
      const where = [];
      const args = [];
      const category = url.searchParams.get('category');
      const botId = url.searchParams.get('bot_id');
      if (category) { where.push('category = ?'); args.push(category); }
      if (botId) { where.push('bot_id = ?'); args.push(Number(botId) || 0); }
      return json(this.q(
        `SELECT id, category, level, bot_id, actor, message, created_at FROM logs ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT 300`, ...args));
    });

    // ----- staff (owner only) -----
    on('GET', '/api/staff', async (req) => {
      await this.auth(req, 'owner');
      return json(this.q('SELECT id, username, role, perms FROM users ORDER BY id'));
    });

    on('POST', '/api/staff', async (req) => {
      const u = await this.auth(req, 'owner');
      const b = await this.body(req);
      const username = String(b.username ?? '').trim();
      this.checkName(username);
      this.checkPass(b.password);
      const perms = JSON.stringify((Array.isArray(b.perms) ? b.perms : []).filter((p) => PERMS.includes(p)));
      const hash = await hashPassword(b.password);
      try {
        this.run("INSERT INTO users (username, password_hash, role, perms) VALUES (?, ?, 'admin', ?)", username, hash, perms);
      } catch (e) {
        if (/UNIQUE/i.test(e.message)) throw new HttpError(409, 'اسم المستخدم مستخدم بالفعل');
        throw e;
      }
      this.log('admin', 'info', `أُضيف مشرف ${username}`, { actor: u.username });
      return json({ ok: true }, 201);
    });

    on('DELETE', `/api/staff/${ID}`, async (req, url, id) => {
      const u = await this.auth(req, 'owner');
      const target = this.need('SELECT id, username, role FROM users WHERE id = ?', [Number(id)], 'المستخدم غير موجود');
      if (target.role === 'owner') throw new HttpError(403, 'لا يمكن حذف حساب المالك');
      this.run('DELETE FROM sessions WHERE user_id = ?', target.id);
      this.run('DELETE FROM users WHERE id = ?', target.id);
      this.log('admin', 'warn', `حُذف المشرف ${target.username}`, { actor: u.username });
      return json({ ok: true });
    });

    return R;
  }

  async api(req, url) {
    const origin = req.headers.get('origin');
    if (req.method !== 'GET' && origin && origin !== `${url.protocol}//${url.host}`) throw new HttpError(403, 'طلب من مصدر غير مسموح');
    for (const [method, re, fn] of this.table) {
      const m = req.method === method ? url.pathname.match(re) : null;
      if (m) return fn(req, url, ...m.slice(1));
    }
    throw new HttpError(404, 'المسار غير موجود');
  }

  async fetch(req) {
    const url = new URL(req.url);
    try {
      if (req.method === 'POST' && url.pathname.startsWith('/webhook/')) return await this.webhook(req, url);
      if (url.pathname.startsWith('/api/')) return await this.api(req, url);
      return new Response('Not found', { status: 404 });
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      this.log('system', 'error', `خطأ داخلي: ${e.message}`);
      return json({ error: 'حدث خطأ داخلي، راجع سجل النظام.' }, 500);
    }
  }
}

// Worker entry: API and webhooks go to the Durable Object, everything else is the static admin UI.
export default {
  async fetch(req, env) {
    const { pathname } = new URL(req.url);
    if (pathname.startsWith('/api/') || pathname.startsWith('/webhook/')) {
      return env.CONTROL.get(env.CONTROL.idFromName('main')).fetch(req);
    }
    return env.ASSETS.fetch(req);
  },
};
