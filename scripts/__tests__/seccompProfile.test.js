'use strict';

// the shipped compose runs the gateway under deploy/docker/seccomp.json (defaultAction ERRNO,
// defaultErrnoRet EPERM). The local witness claims each position with fs.linkSync, which the profile did not allow, so
// every cosignature failed with EPERM and from the first checkpoint on every restart failed closed
// (ANCHOR_NOT_WITNESSED). Any runtime use of hard links must be matched by link/linkat in the profile.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const profile = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy', 'docker', 'seccomp.json'), 'utf8'));
const allowed = new Set(profile.syscalls.filter((r) => r.action === 'SCMP_ACT_ALLOW').flatMap((r) => r.names));

function runtimeFiles(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (e.name !== '__tests__' && e.name !== 'node_modules') runtimeFiles(p, out); }
    else if (e.name.endsWith('.js') && !e.name.endsWith('.test.js')) out.push(p);
  }
  return out;
}

describe('seccomp profile allows the syscalls the runtime uses', () => {
  test('the profile is deny-by-default (the premise of this guard)', () => {
    expect(profile.defaultAction).toBe('SCMP_ACT_ERRNO');
  });

  test('runtime hard-link use ⇒ link and linkat are allowed', () => {
    const users = ['src', 'services', 'server'].flatMap((d) => runtimeFiles(path.join(ROOT, d)))
      .filter((f) => /\bfs(?:\.promises)?\.link(?:Sync)?\s*\(|\blinkSync\s*\(/.test(fs.readFileSync(f, 'utf8')));
    expect(users.map((f) => path.relative(ROOT, f).replace(/\\/g, '/'))).toContain('src/core/audit/anchoring/witness.js');
    expect(allowed.has('link')).toBe(true);
    expect(allowed.has('linkat')).toBe(true);
  });
});
