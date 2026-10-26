import { afterAll, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oc-entrypoint-password-'));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
const source = fs.readFileSync(new URL('./docker-entrypoint.sh', import.meta.url), 'utf8');
// Execute the real password/startup segment without the unrelated hard-coded HOME SSH setup.
const segment = source.slice(source.indexOf('# Handle UI password environment variables.'));
fs.writeFileSync(path.join(dir, 'bun'), '#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE_ARGS"\nprintf "%s" "$OPENCHAMBER_UI_PASSWORD" > "$FIXTURE_PASSWORD"\n', { mode: 0o700 });

for (const variable of ['OPENCHAMBER_UI_PASSWORD', 'UI_PASSWORD']) it(`keeps ${variable} in the environment, never process arguments`, () => {
  const args = path.join(dir, `${variable}.args`);
  const password = path.join(dir, `${variable}.password`);
  const secret = 'fixture password $with-specials';
  execFileSync('sh', ['-eu', '-c', segment], {
    env: { PATH: `${dir}:/usr/bin:/bin`, HOME: dir, [variable]: secret, OH_MY_OPENCODE: 'false', FIXTURE_ARGS: args, FIXTURE_PASSWORD: password },
    stdio: 'pipe',
  });
  expect(fs.readFileSync(args, 'utf8')).toBe('packages/web/bin/cli.js\npackages/web/bin/cli.js logs\n');
  expect(fs.readFileSync(password, 'utf8')).toBe(secret);
});
