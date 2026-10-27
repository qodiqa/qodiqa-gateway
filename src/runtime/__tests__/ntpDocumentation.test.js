'use strict';

const fs   = require('fs');
const path = require('path');

const NTP_DOC_PATH = path.resolve(__dirname, '../../..', 'docs', 'deployment', 'ntp-clock-requirements.md');

describe('NTP clock requirements documentation', () => {
  it('docs/deployment/ntp-clock-requirements.md exists at the project root', () => {
    expect(fs.existsSync(NTP_DOC_PATH)).toBe(true);
  });

  it('file is non-empty', () => {
    const content = fs.readFileSync(NTP_DOC_PATH, 'utf8');
    expect(content.trim().length).toBeGreaterThan(0);
  });
});
