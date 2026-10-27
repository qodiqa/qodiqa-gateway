'use strict';

const fs   = require('fs');
const path = require('path');

const PROBES_DOC = path.resolve(__dirname, '../../../../docs/deployment/kubernetes-probes.md');

describe('Kubernetes probes documentation', () => {
  it('docs/deployment/kubernetes-probes.md exists at the project root', () => {
    expect(fs.existsSync(PROBES_DOC)).toBe(true);
  });

  it('file is non-empty', () => {
    const content = fs.readFileSync(PROBES_DOC, 'utf8');
    expect(content.trim().length).toBeGreaterThan(0);
  });
});
