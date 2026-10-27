'use strict';

// Re-audit A3-05: git and the OTS/TSA adapters do not receive the gateway's secrets.
const { childEnv } = require('../externalAnchors');

describe('external anchor child environment', () => {
  const secretKey = ['QODIQA', 'PG', 'PASSWORD'].join('_');
  const env = { PATH: '/usr/bin', HOME: '/h', [secretKey]: 'x', OPENAI_API_KEY: 'y', QODIQA_KEK_FILE: '/k', QODIQA_ANCHOR_GIT_AUTHOR: 'A <a@b.c>', QODIQA_ANCHOR_OTS_EXEC: '/bin/ots', CUSTOM_PROXY: 'p' };

  test('AE-01 base variables and QODIQA_ANCHOR_* pass, secrets do not', () => {
    const out = childEnv(env);
    expect(out).toMatchObject({ PATH: '/usr/bin', HOME: '/h', QODIQA_ANCHOR_GIT_AUTHOR: 'A <a@b.c>', QODIQA_ANCHOR_OTS_EXEC: '/bin/ots' });
    expect(Object.keys(out)).not.toContain(secretKey);
    expect(Object.keys(out)).not.toContain('OPENAI_API_KEY');
    expect(Object.keys(out)).not.toContain('QODIQA_KEK_FILE');
  });

  test('AE-02 the operator can name extra variables explicitly, and extra values win', () => {
    const out = childEnv({ ...env, QODIQA_ANCHOR_EXEC_ENV_PASS: 'CUSTOM_PROXY' }, { GIT_AUTHOR_NAME: 'n' });
    expect(out.CUSTOM_PROXY).toBe('p');
    expect(out.GIT_AUTHOR_NAME).toBe('n');
  });
});
