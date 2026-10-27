'use strict';

// a fresh Docker named volume copies the ownership of the image directory it is mounted on. The
// shipped compose mounted qodiqa-anchors at /opt/qodiqa/anchors, which the image did not create, so the volume was
// root:root and the non-root gateway could never write its anchor export; after 2 x QODIQA_AUDIT_CHECKPOINT_EVERY
// entries the next boot failed closed (AUDIT_ANCHOR_BOOT_FAILED). Found by the rc-077f3fc7 isolated deployment run.
// Every NAMED volume the gateway service mounts under /opt/qodiqa must be pre-created and chowned in the Dockerfile.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const COMPOSE = path.join(ROOT, 'deploy', 'docker', 'docker-compose.prod.yml');
const DOCKERFILE = path.join(ROOT, 'Dockerfile');

function gatewayNamedVolumeTargets() {
  const lines = fs.readFileSync(COMPOSE, 'utf8').split(/\r?\n/);
  const start = lines.findIndex((l) => /^ {2}qodiqa:\s*$/.test(l));
  expect(start).toBeGreaterThan(-1);
  const out = [];
  let inVolumes = false;
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (/^ {2}\S/.test(l)) break; // next service
    if (/^ {4}volumes:\s*$/.test(l)) { inVolumes = true; continue; }
    if (inVolumes && /^ {4}\S/.test(l)) inVolumes = false;
    const m = inVolumes && l.match(/^\s+-\s+([A-Za-z0-9_-]+):(\/opt\/qodiqa\/[^:\s]+)/);
    if (m) out.push(m[2]); // a bare name (not ./ or ../) is a named volume
  }
  return out;
}

function dockerfileRuntimeDirs() {
  const text = fs.readFileSync(DOCKERFILE, 'utf8');
  const m = text.match(/RUN mkdir -p ((?:\/opt\/qodiqa\/\S+\s*)+)\\\s*\n\s*&& chown -R qodiqa:qodiqa \/opt\/qodiqa/);
  expect(m).not.toBeNull();
  return m[1].trim().split(/\s+/);
}

describe('every named volume the gateway mounts exists in the image, owned by qodiqa', () => {
  test('the gateway mounts the expected named volumes', () => {
    expect(gatewayNamedVolumeTargets()).toEqual(expect.arrayContaining(['/opt/qodiqa/data', '/opt/qodiqa/logs', '/opt/qodiqa/anchors']));
  });

  test('each is created by the Dockerfile mkdir that is chowned to qodiqa', () => {
    const created = dockerfileRuntimeDirs();
    const missing = gatewayNamedVolumeTargets().filter((t) => !created.includes(t));
    expect(missing).toEqual([]);
  });
});
