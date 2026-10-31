// Runs the real Worker code against in-memory SQLite (node:sqlite) with mocked Telegram and provider HTTP calls.
import { DatabaseSync } from 'node:sqlite';
import assert from 'node:assert/strict';
import { ControlRoom } from '../src/worker.js';

const db = new DatabaseSync(':memory:');
const sql = {
  exec(text, ...args) {
    const st = db.prepare(text);
    if (/^\s*(select|with|pragma)/i.test(text)) {
      const rows = st.all(...args);
      return { toArray: () => rows, rowsWritten: 0 };
    }
    const r = st.run(...args);
    return { toArray: () => [], rowsWritten: Number(r.changes) };
  },
};
const pending = [];
const state = { storage: { sql }, blockConcurrencyWhile: async (fn) => fn(), waitUntil: (p) => pending.push(p) };
const env = { MASTER_KEY: 'k'.repeat(40), SETUP_TOKEN: 'setup-token-test-value', CURRENCY: 'USD' };
const room = new ControlRoom(state, env);

const BOT_TOKEN = '123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123';
const API_KEY = 'PROVKEY-test-9876';
const tgCalls = [];
let nextProviderOrder = 555;

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  if (u.startsWith('https://api.telegram.org/bot')) {
    const method = u.split('/').pop();
    tgCalls.push({ method, payload: JSON.parse(init.body || '{}') });
    if (u.includes('BADTOKEN')) return Response.json({ ok: false, description: 'Unauthorized' }, { status: 401 });
    return Response.json({ ok: true, result: method === 'getMe' ? { username: 'shop_bot' } : true });
  }
  if (u === 'https://provider.example/api') {
    const p = new URLSearchParams(init.body);
    if (p.get('key') !== API_KEY) return Response.json({ error: 'Invalid key' });
    const action = p.get('action');
    if (action === 'add') {
      return Response.json((p.get('link') || '').includes('reject') ? { error: 'Service unavailable' } : { order: nextProviderOrder++ });
    }
    if (action === 'status') return Response.json({ status: 'Completed' });
    if (action === 'balance') return Response.json({ balance: '42.50' });
  }
  throw new Error(`unexpected request: ${u}`);
};

let cookie = '';
const call = async (method, path, body) => {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = `dcp=${cookie}`;
  const res = await room.fetch(new Request(`https://panel.example${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  }));
  const set = res.headers.get('set-cookie') || '';
  if (set.startsWith('dcp=')) cookie = set.slice(4).split(';')[0];
  return { status: res.status, data: await res.json() };
};
const hook = (secret, update) => room.fetch(new Request(`https://panel.example/webhook/${botId}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-telegram-bot-api-secret-token': secret },
  body: JSON.stringify(update),
}));
const settle = () => Promise.all(pending.splice(0));
const sentWith = (text) => tgCalls.filter((c) => c.method === 'sendMessage' && c.payload.text.includes(text)).length;
const msg = (update_id, text) => ({ update_id, message: { text, chat: { id: 77 }, from: { id: 77, username: 'buyer' } } });

let botId;
let providerId;
let secret;
let customerId;
const steps = [];
const it = (name, fn) => steps.push([name, fn]);

it('first run asks for setup; setup needs the token and runs once', async () => {
  assert.equal((await call('GET', '/api/me')).data.setup_required, true);
  assert.equal((await call('POST', '/api/setup', { username: 'owner', password: 'owner-password-1', setup_token: 'wrong' })).status, 403);
  assert.equal((await call('POST', '/api/setup', { username: 'owner', password: 'owner-password-1', setup_token: env.SETUP_TOKEN })).status, 201);
  assert.equal((await call('POST', '/api/setup', { username: 'other', password: 'other-password-2', setup_token: env.SETUP_TOKEN })).status, 403);
});

it('login rejects a wrong password and sets a session cookie on success', async () => {
  assert.equal((await call('POST', '/api/login', { username: 'owner', password: 'nope-nope-nope' })).status, 401);
  assert.equal((await call('POST', '/api/login', { username: 'owner', password: 'owner-password-1' })).status, 200);
  assert.equal((await call('GET', '/api/me')).data.user.role, 'owner');
});

it('provider key is encrypted, never returned, and the connection test reads the balance', async () => {
  assert.equal((await call('POST', '/api/providers', { name: 'مزود تجريبي', api_url: 'https://provider.example/api', api_key: API_KEY })).status, 201);
  const list = (await call('GET', '/api/providers')).data;
  providerId = list[0].id;
  assert.ok(!JSON.stringify(list).includes(API_KEY));
  const test = (await call('POST', `/api/providers/${providerId}/test`)).data;
  assert.equal(test.ok, true);
  assert.equal(test.balance, '42.50');
});

it('bot token is verified with Telegram and stored encrypted', async () => {
  assert.equal((await call('POST', '/api/bots', { name: 'بوت', token: '999999:BADTOKENBADTOKENBADTOKEN0000', provider_id: providerId })).status, 400);
  assert.equal((await call('POST', '/api/bots', { name: 'بوت المتجر', token: BOT_TOKEN, provider_id: providerId })).status, 201);
  const bot = (await call('GET', '/api/bots')).data[0];
  botId = bot.id;
  assert.equal(bot.username, 'shop_bot');
  assert.ok(!room.one('SELECT token_enc FROM bots WHERE id = ?', botId).token_enc.includes('ABCDEFGHIJ'));
});

it('enabling a bot registers its webhook with a per-bot secret (only the hash is stored)', async () => {
  assert.equal((await call('POST', `/api/bots/${botId}/webhook`, { enabled: true })).status, 200);
  const set = tgCalls.filter((c) => c.method === 'setWebhook').pop();
  assert.equal(set.payload.url, `https://panel.example/webhook/${botId}`);
  secret = set.payload.secret_token;
  assert.notEqual(room.one('SELECT webhook_hash FROM bots WHERE id = ?', botId).webhook_hash, secret);
});

it('webhook rejects a wrong secret and answers /start through the bot', async () => {
  assert.equal((await hook('wrong', msg(1, '/start'))).status, 403);
  assert.equal((await hook(secret, msg(2, '/start'))).status, 200);
  await settle();
  assert.equal(sentWith('/order'), 1);
});

it('owner adds a service and credits a customer balance', async () => {
  assert.equal((await call('POST', '/api/services', {
    provider_id: providerId, provider_service_id: '101', name: 'متابعون', price_per_1000: 150, min_qty: 10, max_qty: 5000,
  })).status, 201);
  customerId = room.one('SELECT id FROM customers WHERE bot_id = ? AND tg_user_id = ?', botId, '77').id;
  assert.equal((await call('POST', `/api/customers/${customerId}/balance`, { amount: 1000, reason: 'شحن تجريبي' })).status, 200);
});

it('/order deducts the price, forwards it to the provider and tracks status', async () => {
  await hook(secret, msg(3, '/order 101 100 https://t.me/shop/1'));
  await settle();
  const order = room.one('SELECT * FROM orders ORDER BY id DESC LIMIT 1');
  assert.equal(order.status, 'processing');
  assert.equal(order.price, 15);
  assert.equal(room.one('SELECT balance FROM customers WHERE id = ?', customerId).balance, 985);
  assert.equal((await call('POST', `/api/orders/${order.id}/refresh`)).data.status, 'completed');
});

it('a replayed Telegram update creates no second order', async () => {
  const before = room.one('SELECT COUNT(*) AS n FROM orders').n;
  await hook(secret, msg(3, '/order 101 100 https://t.me/shop/1'));
  await settle();
  assert.equal(room.one('SELECT COUNT(*) AS n FROM orders').n, before);
});

it('provider rejection marks the order failed and refunds the balance', async () => {
  await hook(secret, msg(4, '/order 101 100 https://t.me/reject'));
  await settle();
  assert.equal(room.one('SELECT status FROM orders ORDER BY id DESC LIMIT 1').status, 'failed');
  assert.equal(room.one('SELECT balance FROM customers WHERE id = ?', customerId).balance, 985);
});

it('insufficient balance is refused before any order is created', async () => {
  await call('POST', `/api/customers/${customerId}/balance`, { amount: -985, reason: 'تصفير تجريبي' });
  const before = room.one('SELECT COUNT(*) AS n FROM orders').n;
  await hook(secret, msg(5, '/order 101 5000 https://t.me/shop/2'));
  await settle();
  assert.equal(room.one('SELECT COUNT(*) AS n FROM orders').n, before);
  assert.equal(sentWith('غير كافٍ'), 1);
});

it('secrets never reach the logs or the database in plain text', async () => {
  const logs = JSON.stringify(room.q('SELECT message FROM logs'));
  assert.ok(!logs.includes(API_KEY) && !logs.includes('ABCDEFGHIJ'));
  assert.ok(!JSON.stringify(room.q('SELECT api_key_enc FROM providers')).includes(API_KEY));
});

it('roles: an admin without customer rights is blocked; balance changes stay owner-only', async () => {
  const ownerCookie = cookie;
  assert.equal((await call('POST', '/api/staff', { username: 'support1', password: 'support-pass-123', perms: ['orders'] })).status, 201);
  await call('POST', '/api/login', { username: 'support1', password: 'support-pass-123' });
  assert.equal((await call('GET', '/api/orders')).status, 200);
  assert.equal((await call('GET', '/api/customers')).status, 403);
  assert.equal((await call('POST', `/api/customers/${customerId}/balance`, { amount: 100, reason: 'محاولة' })).status, 403);
  assert.equal((await call('GET', '/api/staff')).status, 403);
  cookie = ownerCookie;
});

let failures = 0;
for (const [name, fn] of steps) {
  try {
    await fn();
    console.log('✓', name);
  } catch (e) {
    failures++;
    console.error('✗', name, '\n   ', e.message);
  }
}
console.log(failures ? `\n${failures} check(s) failed` : `\nAll ${steps.length} checks passed`);
process.exitCode = failures ? 1 : 0;
