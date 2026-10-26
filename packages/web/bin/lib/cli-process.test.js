import { afterAll, describe, expect, it } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readInstanceOptions, writeInstanceOptions } from './cli-process.js';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oc-instance-options-'));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('instance option password files', () => {
  for (const existing of [false, true]) it(`writes owner-only options with existing=${existing}`, () => {
    const file = path.join(dir, `${existing}.json`);
    if (existing) {
      fs.writeFileSync(file, 'old content that must be truncated'.repeat(1000));
      fs.chmodSync(file, 0o666);
    }
    const notices = [];
    writeInstanceOptions(file, { port: 3000, uiPassword: 'fixture-password' }, (notice) => notices.push(notice));
    expect(notices).toHaveLength(0);
    expect(readInstanceOptions(file).uiPassword).toBe('fixture-password');
    if (process.getuid) {
      expect(fs.statSync(file).mode & 0o777).toBe(0o600);
      expect(fs.statSync(file).uid).toBe(process.getuid());
    }
  });
  it('refuses a symlink without changing its target', () => {
    if (process.platform === 'win32') return;
    const target = path.join(dir, 'target.json');
    const link = path.join(dir, 'link.json');
    fs.writeFileSync(target, 'leave this alone', { mode: 0o644 });
    fs.symlinkSync(target, link);
    const notices = [];
    writeInstanceOptions(link, { port: 3000, uiPassword: 'fixture-password' }, (notice) => notices.push(notice));
    expect(notices[0].code).toBe('INSTANCE_FILE_WRITE_FAILED');
    expect(fs.readFileSync(target, 'utf8')).toBe('leave this alone');
    expect(fs.statSync(target).mode & 0o777).toBe(0o644);
  });
});
