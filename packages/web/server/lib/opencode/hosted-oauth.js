import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { sessionCookieNameForRequest } from '../ui-auth/session-cookie.js';
import { isNetworkAccessBlocked } from '../enterprise-mode.js';
import { readBoundedResponseText } from '../guests/response-body.js';

const CALLBACK = '/oauth/mcp/callback';
const COOKIE = '__Host-oc_mcp_oauth';
const TTL = 5 * 60_000;
const digest = (value) => createHash('sha256').update(value).digest();
const equal = (a, b) => timingSafeEqual(digest(a), digest(b));
const cookie = (req) => {
  const values = (req.headers.cookie || '').split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${COOKIE}=`));
  return values.length === 1 ? values[0].slice(COOKIE.length + 1) : '';
};

// Registration is opt-in. A partial/invalid configuration must not fall through to localhost OAuth.
export const registerHostedMcpOAuth = (app, {
  express, getUiAuthController, buildOpenCodeUrl, getOpenCodeAuthHeaders,
  env = process.env, fetchImpl = fetch, now = Date.now, networkBlocked = isNetworkAccessBlocked,
}) => {
  if (!['REDIRECT_URI', 'CALLBACK_PORT', 'SERVER', 'ISSUER'].some((key) => env[`OPENCHAMBER_MCP_OAUTH_${key}`])) return;
  const redirect = new URL(env.OPENCHAMBER_MCP_OAUTH_REDIRECT_URI);
  const port = Number(env.OPENCHAMBER_MCP_OAUTH_CALLBACK_PORT);
  const server = env.OPENCHAMBER_MCP_OAUTH_SERVER;
  const issuer = env.OPENCHAMBER_MCP_OAUTH_ISSUER;
  const issuerUrl = new URL(issuer);
  if (redirect.protocol !== 'https:' || redirect.pathname !== CALLBACK || redirect.search || redirect.hash
    || redirect.username || redirect.password || redirect.port || !Number.isInteger(port) || port < 1024 || port > 65535
    || !server || issuerUrl.protocol !== 'https:' || issuerUrl.username || issuerUrl.password
    || issuerUrl.search || issuerUrl.hash || issuerUrl.port) throw new Error('Invalid hosted MCP OAuth configuration');
  let pending = null;
  const forget = (record) => {
    if (pending === record) { clearTimeout(record.timer); pending = null; }
  };
  const safeHeaders = (res) => res.set({
    'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
  });
  const fail = (res, status) => { safeHeaders(res); return res.status(status).json({ error: 'Hosted MCP authorization unavailable. Start a fresh connection.' }); };
  const clearCookie = (res) => res.append('Set-Cookie', `${COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
  const valid = (record) => record && record.expires > now();
  const native = async (path, options = {}, record = null) => {
    const base = buildOpenCodeUrl('/api/info');
    if (record && record.base !== base) { forget(record); throw new Error('Backend changed'); }
    const response = await fetchImpl(buildOpenCodeUrl(path), {
      ...options, headers: { ...getOpenCodeAuthHeaders(), ...options.headers },
      redirect: 'error', signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) { await response.body?.cancel(); throw new Error('Native authorization request failed'); }
    const result = await readBoundedResponseText(response, 64_000);
    if (result.tooLarge) throw new Error('Native authorization response too large');
    return result.text ? JSON.parse(result.text) : null;
  };
  const sameBackend = async (record) => {
    const info = await native('/api/info', {}, record);
    const matches = info.pid === record.pid && info.version === record.version && pending === record;
    if (!matches) forget(record);
    return matches;
  };
  const resolveOwner = async (req, res) => {
    const auth = getUiAuthController();
    if (!auth?.enabled) return null;
    const context = await auth.resolveAuthContext(req, res, { allowClientAuth: false, allowUrlToken: false });
    return context?.type === 'session' ? context.token : null;
  };
  const scope = (req) => {
    const url = new URL(req.originalUrl, redirect.origin);
    for (const key of url.searchParams.keys()) if (key !== 'location[directory]') throw new Error('Unsupported scope');
    if (url.searchParams.getAll('location[directory]').length > 1) throw new Error('Duplicate scope');
    const directory = req.headers['x-opencode-directory'];
    if (directory && url.search) throw new Error('Ambiguous scope');
    return { query: url.search, headers: directory ? { 'x-opencode-directory': directory } : {} };
  };
  const statusPath = (record) => `${record.path}/${encodeURIComponent(record.attemptID)}${record.scope.query}`;
  const cancel = async (record) => {
    if (record.attemptID && await sameBackend(record)) await native(statusPath(record), { method: 'DELETE', headers: record.scope.headers }, record);
  };
  const expire = async () => {
    const record = pending;
    if (record && !valid(record)) {
      try { await cancel(record); } catch { /* The next start fails closed if the old listener is still bound. */ }
      forget(record);
    }
  };

  app.all(CALLBACK, async (req, res) => {
    safeHeaders(res);
    if (req.originalUrl.split('?')[0] !== CALLBACK) return fail(res, 404);
    if (req.method !== 'GET') return fail(res, 405);
    if (networkBlocked()) return fail(res, 403);
    const record = pending;
    if (!valid(record) || record.consumed || !record.attemptID || !equal(cookie(req), record.browser)) return fail(res, 400);
    try {
      if (req.originalUrl.length > 8192 || req.headers['transfer-encoding']
        || (req.headers['content-length'] && req.headers['content-length'] !== '0')) return fail(res, 400);
      const params = new URL(req.originalUrl, redirect.origin).searchParams;
      const allowed = new Set(['state', 'code', 'iss', 'error', 'error_description', 'error_uri']);
      for (const [key, value] of params) {
        if (!allowed.has(key) || params.getAll(key).length !== 1 || value.length > 4096 || /[\x00-\x1f\x7f]/.test(value)) return fail(res, 400);
      }
      if (!equal(params.get('state') || '', record.state)
        || Boolean(params.get('code')) === Boolean(params.get('error'))
        || (params.has('iss') && params.get('iss') !== issuer)
        || (!params.has('error') && (params.has('error_description') || params.has('error_uri')))) return fail(res, 400);
      record.checks = (record.checks || 0) + 1;
      if (record.checks > 16) return fail(res, 429);
      // UI cookies are Strict. The Lax one-time nonce binds this redirect to the
      // browser whose still-valid authenticated session started the attempt.
      const owner = await resolveOwner({ headers: { host: record.authHost, cookie: `${record.cookieName}=${encodeURIComponent(record.owner)}` } }, res);
      if (!owner || !equal(owner, record.owner) || !await sameBackend(record)) return fail(res, 403);
      const status = await native(statusPath(record), { headers: record.scope.headers }, record);
      if (status.data?.status !== 'pending' || pending !== record || record.consumed || !valid(record)) return fail(res, 409);
      record.consumed = true;
      const fields = new URLSearchParams();
      for (const key of ['state', 'code', 'iss']) if (params.has(key)) fields.set(key, params.get(key));
      // Native logs authorization failures. Provider/browser error text must not reach those logs.
      if (params.has('error')) fields.set('error', 'access_denied');
      const response = await fetchImpl(`http://127.0.0.1:${port}${CALLBACK}?${fields}`, {
        redirect: 'error', signal: AbortSignal.timeout(15_000),
      });
      await response.body?.cancel();
      return res.status(response.ok ? 200 : 400).type('html').send('<!doctype html><title>Authorization</title><p>Return to OpenChamber to check the connection.</p>');
    } catch {
      return fail(res, 502);
    }
  });

  // Mount the callback before body parsing/logging; mount initiation after API auth.
  return () => {
  // OpenCode accepts path aliases that Express does not. They must not bypass serialization.
  app.use((req, res, next) => {
    try {
      const parts = decodeURIComponent(req.path).split(/[?#;]/, 1)[0].split(/[\\/]/).filter(Boolean);
      if (parts[0]?.toLowerCase() === 'api' && parts[1]?.toLowerCase() === 'integration'
        && /^mcp_/i.test(parts[2] || '') && parts[3]?.toLowerCase() === 'connect' && parts[4]?.toLowerCase() === 'oauth') {
        if (parts.length > 6 || req.path !== `/${parts.join('/')}` || parts.slice(0, 2).join('/') !== 'api/integration'
          || parts[3] !== 'connect' || parts[4] !== 'oauth') return fail(res, 400);
      }
    } catch { return fail(res, 400); }
    return next();
  });
  // This route is behind the ordinary API auth gate and ahead of the native proxy.
  app.all('/api/integration/:integrationID/connect/oauth{/:attemptID}', async (req, res, next) => {
    if (!/^mcp_[0-9a-f]{16}$/.test(req.params.integrationID)) return next();
    try {
      const requestScope = scope(req);
      const path = `/api/integration/${encodeURIComponent(req.params.integrationID)}/connect/oauth`;
      const integration = await native(`/api/integration/${encodeURIComponent(req.params.integrationID)}${requestScope.query}`, { headers: requestScope.headers });
      if (integration.data?.name !== server || integration.data?.metadata?.source !== 'mcp') return next();
      safeHeaders(res);
      if (networkBlocked()) return fail(res, 403);
      const owner = await resolveOwner(req, res);
      if (!owner) return fail(res, 401);
      if ((req.method !== 'GET' && req.headers.origin !== redirect.origin)
        || (req.headers.origin && req.headers.origin !== redirect.origin)
        || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin')) return fail(res, 403);
      await expire();
      if (req.params.attemptID) {
        const record = pending;
        if (!valid(record) || record.attemptID !== req.params.attemptID || record.path !== path || !equal(owner, record.owner) || !equal(cookie(req), record.browser)
          || requestScope.query !== record.scope.query || JSON.stringify(requestScope.headers) !== JSON.stringify(record.scope.headers)) return fail(res, 404);
        if (!await sameBackend(record)) { forget(record); return fail(res, 409); }
        if (req.method === 'DELETE') {
          record.consumed = true;
          await cancel(record);
          forget(record);
          clearCookie(res);
          return res.status(204).end();
        }
        if (req.method !== 'GET') return fail(res, 405);
        const result = await native(statusPath(record), { headers: record.scope.headers }, record);
        if (result.data?.status !== 'pending' && pending === record) { forget(record); clearCookie(res); }
        return res.json(result);
      }
      if (req.method !== 'POST') return fail(res, 405);
      const previous = pending;
      if (previous?.consumed && await sameBackend(previous)) {
        const result = await native(statusPath(previous), { headers: previous.scope.headers }, previous);
        if (result.data?.status !== 'pending') forget(previous);
      }
      if (pending) return fail(res, 409);
      if (!req.is('application/json')) return fail(res, 415);
      try {
        await new Promise((resolve, reject) => express.json({ limit: '4kb' })(req, res, (error) => error ? reject(error) : resolve()));
      } catch { return fail(res, 400); }
      if (!req.body || Object.keys(req.body).some((key) => !['methodID', 'answer', 'label'].includes(key))
        || !integration.data.methods?.some((method) => method.id === req.body.methodID && method.type === 'oauth')) return fail(res, 400);
      if (pending) return fail(res, 409);
      const record = { owner, cookieName: sessionCookieNameForRequest(req, 'oc_ui_session'), authHost: (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim(),
        browser: randomBytes(32).toString('base64url'),
        path, scope: requestScope, base: buildOpenCodeUrl('/api/info'), expires: now() + TTL, consumed: false };
      pending = record;
      record.timer = setTimeout(() => { void expire(); }, TTL);
      record.timer.unref?.();
      try {
        const info = await native('/api/info', {}, record);
        if (!Number.isInteger(info.pid) || info.pid < 1 || !/^\d+\.\d+\.\d+/.test(info.version)) throw new Error('Unsupported native identity');
        record.pid = info.pid; record.version = info.version;
        const result = await native(`${path}${requestScope.query}`, { method: 'POST', headers: { ...requestScope.headers, 'content-type': 'application/json' }, body: JSON.stringify(req.body) }, record);
        const attempt = result.data;
        record.attemptID = attempt?.attemptID;
        const url = new URL(attempt.url);
        if (attempt.mode !== 'auto' || !/^[A-Za-z0-9_-]+$/.test(record.attemptID)
          || url.protocol !== 'https:' || url.origin !== issuerUrl.origin || url.username || url.password || url.hash
          || url.searchParams.getAll('redirect_uri').length !== 1 || url.searchParams.get('redirect_uri') !== redirect.href
          || url.searchParams.getAll('state').length !== 1 || !/^[A-Za-z0-9_-]{40,128}$/.test(url.searchParams.get('state'))
          || url.searchParams.get('code_challenge_method') !== 'S256'
          || url.searchParams.getAll('code_challenge').length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('code_challenge'))
          || !Number.isFinite(attempt.time?.expires) || attempt.time.expires <= now() || !await sameBackend(record)) throw new Error('Unsupported native attempt');
        record.state = url.searchParams.get('state');
        record.expires = Math.min(record.expires, attempt.time.expires);
        clearTimeout(record.timer);
        record.timer = setTimeout(() => { void expire(); }, Math.max(1, record.expires - now()));
        record.timer.unref?.();
        res.append('Set-Cookie', `${COOKIE}=${record.browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.max(0, Math.floor((record.expires - now()) / 1000))}`);
        return res.json(result);
      } catch {
        try { await cancel(record); } catch { /* Native attempt expires independently. */ }
        forget(record);
        return fail(res, 502);
      }
    } catch { return fail(res, 502); }
  });
  };
};
