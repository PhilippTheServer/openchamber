import { afterAll, afterEach, describe, expect, it } from 'bun:test';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import request from 'supertest';
import { registerCommonRequestMiddleware } from './core-routes.js';
import { registerHostedMcpOAuth } from './hosted-oauth.js';
import { registerOpenCodeProxy } from './proxy.js';

const previousData = process.env.OPENCHAMBER_DATA_DIR;
const previousSecret = process.env.OPENCODE_JWT_SECRET;
const dataDir = mkdtempSync(path.join(os.tmpdir(), 'oc-hosted-oauth-'));
process.env.OPENCHAMBER_DATA_DIR = dataDir;
process.env.OPENCODE_JWT_SECRET = 'fixture-only-session-secret';
const { createUiAuth } = await import('../ui-auth/ui-auth.js');
afterAll(() => {
  if (previousData === undefined) delete process.env.OPENCHAMBER_DATA_DIR; else process.env.OPENCHAMBER_DATA_DIR = previousData;
  if (previousSecret === undefined) delete process.env.OPENCODE_JWT_SECRET; else process.env.OPENCODE_JWT_SECRET = previousSecret;
  rmSync(dataDir, { recursive: true, force: true });
});

const ORIGIN = 'https://hosted.invalid';
const PATH = '/api/integration/mcp_0123456789abcdef/connect/oauth';
const REDIRECT = `${ORIGIN}/oauth/mcp/callback`;
const STATE = 'a'.repeat(43);
const cleanups = [];
afterEach(() => { for (const cleanup of cleanups.splice(0)) cleanup(); });

const setup = async (options = {}) => {
  const auth = createUiAuth({ password: options.password ?? 'fixture-password' });
  cleanups.push(() => auth.dispose());
  const calls = [];
  let clock = Date.now();
  let pid = 123;
  let nativeStatus = 'pending';
  let holdStart;
  const startGate = options.hold ? new Promise((resolve) => { holdStart = resolve; }) : null;
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    const path = new URL(url).pathname;
    if (url.startsWith('http://127.0.0.1:42819')) {
      if (options.callbackThrows) throw new Error('fixture timeout with sensitive code');
      return new Response('native page must not be reflected', { status: options.callbackStatus ?? 200 });
    }
    if (path === '/api/info') return Response.json({ pid, version: '2.1.4' });
    if (path.endsWith('/connect/oauth') && init.method === 'POST') {
      if (startGate) await startGate;
      return Response.json({ data: { attemptID: 'attempt-1', mode: 'auto', url: `https://issuer.invalid/authorize?${new URLSearchParams({ state: STATE, redirect_uri: options.redirect ?? REDIRECT, code_challenge_method: 'S256', code_challenge: 'b'.repeat(43) })}`, time: { expires: clock + 600_000 } } });
    }
    if (path.endsWith('/connect/oauth/attempt-1')) {
      if (init.method === 'DELETE') return new Response(null, { status: 204 });
      return Response.json({ data: { status: nativeStatus } });
    }
    return Response.json({ data: { name: 'monday', metadata: { source: 'mcp' }, methods: [{ id: 'oauth', type: 'oauth' }] } });
  };
  const app = express();
  app.use((req, _res, next) => { req.headers.host = 'hosted.invalid'; next(); });
  const registerApi = registerHostedMcpOAuth(app, { express, getUiAuthController: () => auth, buildOpenCodeUrl: (path) => `http://127.0.0.1:43871${path}`,
    getOpenCodeAuthHeaders: () => ({ Authorization: 'Basic fixture-only' }), fetchImpl, now: () => clock,
    networkBlocked: () => options.blocked ?? false,
    env: { OPENCHAMBER_MCP_OAUTH_REDIRECT_URI: REDIRECT, OPENCHAMBER_MCP_OAUTH_CALLBACK_PORT: '42819', OPENCHAMBER_MCP_OAUTH_SERVER: 'monday', OPENCHAMBER_MCP_OAUTH_ISSUER: 'https://issuer.invalid' },
  });
  registerCommonRequestMiddleware(app, { express, verboseRequestLogs: options.verbose ?? false });
  app.post('/auth/session', auth.handleSessionCreate);
  app.get('/auth/session', auth.handleSessionStatus);
  app.use('/api', auth.requireAuth);
  app.post('/api/auth/reset', auth.handleResetAuth);
  registerOpenCodeProxy(app, {
    fs: {}, os: {}, path, OPEN_CODE_READY_GRACE_MS: 0,
    getRuntime: () => ({ openCodePort: 43871, isOpenCodeReady: true, openCodeNotReadySince: 0, isRestartingOpenCode: false }),
    getOpenCodeAuthHeaders: () => ({ Authorization: 'Basic fixture-only' }),
    buildOpenCodeUrl: (url) => `http://127.0.0.1:43871${url}`, ensureOpenCodeApiPrefix: () => {},
    openCodeTrust: { refusalFor: async () => options.untrusted ? { status: 403, body: { code: 'opencode_trust_required' } } : null },
    registerHostedMcpOAuthApi: registerApi,
  });
  app.use((_req, res) => res.status(418).end());
  const login = async (trustDevice = false) => (await request(app).post('/auth/session').send({ password: 'fixture-password', trustDevice })).headers['set-cookie'][0].split(';')[0];
  const owner = await login();
  const start = () => request(app).post(PATH).set('Origin', ORIGIN).set('Cookie', owner).send({ methodID: 'oauth' });
  const begun = options.noStart ? null : await start();
  const browser = begun?.headers['set-cookie']?.[0]?.split(';')[0];
  const callback = (query = { state: STATE, code: 'fixture-code' }, browserCookie = browser) => {
    const req = request(app).get('/oauth/mcp/callback').query(query);
    return browserCookie ? req.set('Cookie', browserCookie) : req;
  };
  return { app, owner, browser, begun, callback, calls, start, login, release: () => holdStart?.(), advance: () => { clock += 301_000; }, restart: () => { pid += 1; }, finish: () => { nativeStatus = 'complete'; }, disableOwner: () => { auth.enabled = false; } };
};

describe('hosted MCP OAuth routes', () => {
  it('binds a real authenticated UI session and relays only allowlisted fields to the fixed listener', async () => {
    const t = await setup();
    expect(t.begun.status).toBe(200);
    expect(t.begun.headers['set-cookie'][0]).toContain('Secure; HttpOnly; SameSite=Lax');
    const result = await t.callback({ state: STATE, code: 'fixture-code', iss: 'https://issuer.invalid' });
    expect(result.status).toBe(200);
    expect(result.text).not.toContain('fixture-code');
    expect(result.text).not.toContain('native page');
    expect(result.headers['cache-control']).toBe('no-store');
    expect(result.headers['referrer-policy']).toBe('no-referrer');
    expect(result.headers['content-security-policy']).toContain("default-src 'none'");
    const sent = t.calls.find((call) => call.url.startsWith('http://127.0.0.1:42819'));
    expect(new URL(sent.url).pathname).toBe('/oauth/mcp/callback');
    expect(sent.init.redirect).toBe('error');
    expect(sent.init.headers).toBeUndefined();
    expect((await t.callback()).status).toBe(400);
    expect(t.calls.filter((call) => call.url.startsWith('http://127.0.0.1:42819'))).toHaveLength(1);
  });
  for (const query of [
    { state: 'wrong', code: 'code' }, { code: 'code' }, { state: STATE, error: 'denied', code: 'code' },
    { state: 'wrong', error: 'denied' }, { state: STATE, code: 'code', target: 'http://evil.invalid' },
    { state: [STATE, STATE], code: 'code' }, { state: STATE, code: 'code', iss: 'https://evil.invalid' },
    { state: STATE, code: 'x'.repeat(5000) }, { state: STATE, code: 'code', error_description: 'denied' },
  ]) it(`rejects invalid response ${JSON.stringify(query).slice(0, 100)} without consuming the real attempt`, async () => {
    const t = await setup();
    expect((await t.callback(query)).status).toBe(400);
    expect(t.calls.some((call) => call.url.startsWith('http://127.0.0.1:42819'))).toBe(false);
    expect((await t.callback()).status).toBe(200);
  });
  it('rejects an absent/wrong browser cookie without consuming the attempt', async () => {
    const t = await setup();
    expect((await t.callback(undefined, '')).status).toBe(400);
    expect((await t.callback(undefined, '__Host-oc_mcp_oauth=wrong')).status).toBe(400);
    expect((await t.callback()).status).toBe(200);
  });
  it('forwards a validated provider error without reflecting its text', async () => {
    const t = await setup({ callbackStatus: 400 });
    const result = await t.callback({ state: STATE, error: 'untrusted-private-error', error_description: '<script>secret</script>' });
    expect(result.status).toBe(400);
    expect(result.text).not.toContain('secret');
    const native = new URL(t.calls.find((call) => call.url.startsWith('http://127.0.0.1:42819')).url);
    expect(native.searchParams.get('error')).toBe('access_denied');
    expect(native.searchParams.has('error_description')).toBe(false);
    expect(native.href).not.toContain('untrusted-private-error');
  });
  it('preserves ordinary UI status polling without an Origin header through terminal completion', async () => {
    const t = await setup();
    expect((await t.callback()).status).toBe(200);
    t.finish();
    const status = await request(t.app).get(`${PATH}/attempt-1`).set('Cookie', `${t.owner}; ${t.browser}`);
    expect(status.status).toBe(200);
    expect(status.body.data.status).toBe('complete');
    expect((await t.start()).status).toBe(200);
  });
  it('rejects disabled owner authentication and bounds callbacks for an unusable session', async () => {
    const t = await setup(); t.disableOwner();
    for (let i = 0; i < 16; i += 1) expect((await t.callback()).status).toBe(403);
    expect((await t.callback()).status).toBe(429);
    expect(t.calls.some((call) => call.url.startsWith('http://127.0.0.1:42819'))).toBe(false);
  });
  it('does not retry an uncertain callback or expose the transport error', async () => {
    const t = await setup({ callbackThrows: true });
    const response = await t.callback();
    expect(response.status).toBe(502);
    expect(response.text).not.toContain('sensitive');
    expect((await t.callback()).status).toBe(400);
    expect(t.calls.filter((call) => call.url.startsWith('http://127.0.0.1:42819'))).toHaveLength(1);
  });
  it('handles callback methods before parsers/loggers and never logs callback codes or state', async () => {
    const logs = [];
    const log = console.log;
    console.log = (...args) => logs.push(args.join(' '));
    try {
      const t = await setup({ verbose: true });
      const response = await request(t.app).post('/oauth/mcp/callback').set('Content-Type', 'application/json').send('{"code":"private-code"');
      expect(response.status).toBe(405);
      expect((await t.callback({ state: STATE, code: 'private-code' })).status).toBe(200);
      expect(logs.join('\n')).not.toContain('private-code');
      expect(logs.join('\n')).not.toContain(STATE);
      expect(logs.join('\n')).not.toContain('/oauth/mcp/callback');
    } finally { console.log = log; }
  });
  it('requires authenticated same-origin initiation and owner-bound cancellation/status', async () => {
    const t = await setup();
    expect((await request(t.app).post(PATH).set('Origin', ORIGIN).send({ methodID: 'oauth' })).status).toBe(401);
    expect((await request(t.app).post(PATH).set('Cookie', t.owner).set('Origin', 'https://evil.invalid').send({ methodID: 'oauth' })).status).toBe(403);
    const other = await t.login(true);
    expect(other).not.toBe(t.owner);
    expect((await request(t.app).get('/auth/session').set('Cookie', other)).body.authenticated).toBe(true);
    expect((await request(t.app).get(`${PATH}/attempt-1`).set('Cookie', `${other}; ${t.browser}`).set('Origin', ORIGIN)).status).toBe(404);
    expect((await request(t.app).delete(`${PATH}/attempt-1`).set('Cookie', `${other}; ${t.browser}`).set('Origin', ORIGIN)).status).toBe(404);
    expect(t.calls.some((call) => call.init.method === 'DELETE')).toBe(false);
    expect((await request(t.app).delete(`${PATH}/attempt-1`).set('Cookie', `${t.owner}; ${t.browser}`).set('Origin', ORIGIN)).status).toBe(204);
    expect((await t.callback()).status).toBe(400);
    expect(t.calls.some((call) => call.init.method === 'DELETE')).toBe(true);
  });
  it('rejects a pending callback after actual UI JWT-secret rotation', async () => {
    const secret = process.env.OPENCODE_JWT_SECRET;
    delete process.env.OPENCODE_JWT_SECRET;
    try {
      const t = await setup();
      expect(t.begun.status).toBe(200);
      expect(existsSync(path.join(dataDir, 'jwt-secret'))).toBe(true);
      const reset = await request(t.app).post('/api/auth/reset').set('Cookie', t.owner);
      expect(reset.status).toBe(200);
      expect(reset.body.signedOutEverywhere).toBe(true);
      expect((await request(t.app).get('/auth/session').set('Cookie', t.owner)).status).toBe(401);
      expect((await t.callback()).status).toBe(403);
      expect(t.calls.some((call) => call.url.startsWith('http://127.0.0.1:42819'))).toBe(false);
    } finally {
      if (secret === undefined) delete process.env.OPENCODE_JWT_SECRET; else process.env.OPENCODE_JWT_SECRET = secret;
    }
  });
  it('serializes concurrent starts before native authorization', async () => {
    const t = await setup({ noStart: true, hold: true });
    const first = t.start().then((result) => result);
    while (!t.calls.some((call) => call.init.method === 'POST')) await new Promise((resolve) => setTimeout(resolve, 5));
    expect((await t.start()).status).toBe(409);
    t.release();
    expect((await first).status).toBe(200);
    expect(t.calls.filter((call) => call.init.method === 'POST')).toHaveLength(1);
  });
  for (const change of ['advance', 'restart', 'finish']) it(`rejects callback after ${change}`, async () => {
    const t = await setup(); t[change]();
    expect((await t.callback()).status).not.toBe(200);
    expect(t.calls.some((call) => call.url.startsWith('http://127.0.0.1:42819'))).toBe(false);
  });
  it('cancels an expired native attempt before a new start', async () => {
    const t = await setup(); t.advance();
    expect((await t.start()).status).toBe(200);
    expect(t.calls.some((call) => call.init.method === 'DELETE')).toBe(true);
  });
  it('has no pending state after an application restart', async () => {
    const before = await setup();
    const after = await setup({ noStart: true });
    expect((await after.callback(undefined, before.browser)).status).toBe(400);
  });
  it('fails closed under network policy and invalid redirect setup', async () => {
    expect((await setup({ blocked: true })).begun.status).toBe(403);
    const t = await setup({ redirect: 'http://127.0.0.1:19876/callback' });
    expect(t.begun.status).toBe(502);
    expect(t.calls.some((call) => call.init.method === 'DELETE')).toBe(true);
  });
  it('retains the real proxy folder-trust gate before any native integration reads', async () => {
    const t = await setup({ untrusted: true });
    expect(t.begun.status).toBe(403);
    expect(t.begun.body.code).toBe('opencode_trust_required');
    expect(t.calls).toHaveLength(0);
  });
  it('refuses native path aliases that could bypass the pending slot', async () => {
    const t = await setup();
    for (const path of [PATH.replace('/api/', '/api//'), PATH.replace('integration', 'INTEGRATION'), `${PATH};ignored`, `${PATH}/attempt-1/complete`]) {
      expect((await request(t.app).post(path).set('Cookie', t.owner).set('Origin', ORIGIN).send({ methodID: 'oauth' })).status).toBe(400);
    }
  });
});
