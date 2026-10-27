'use strict';

/** DSR export/restriction must read EVERY page, never silently stop at 200/500 rows. */

jest.mock('../../consent/ConsentStore', () => ({ list: jest.fn(), suspend: jest.fn(), resume: jest.fn(), getAuditLog: jest.fn() }));
jest.mock('../DSRStore', () => ({ findById: jest.fn(), updateStatus: jest.fn(async (x) => x), list: jest.fn() }));
jest.mock('../identityVerification', () => ({ assertApproved: jest.fn() }));
jest.mock('../../../infra/postgres/pool', () => ({ query: jest.fn(async () => ({ rows: [{ id: 'exp-1' }], rowCount: 1 })) }));
jest.mock('../ErasureTargetRegistry', () => ({ getTargets: () => [] }));

const ConsentStore = require('../../consent/ConsentStore');
const DSRStore = require('../DSRStore');
const { pageAll } = require('../pageAll');
const Restriction = require('../RestrictionService');
const Portability = require('../PortabilityService');

const rows = (n, mk) => Array.from({ length: n }, (_, i) => mk(i));
const paged = (all) => async ({ limit = 200, offset = 0 }) => all.slice(offset, offset + limit);

describe('pageAll', () => {
  test('PA-01 reads every page in order', async () => {
    const all = rows(450, (i) => i);
    const out = await pageAll(paged(all), 200);
    expect(out).toEqual(all);
  });
  test('PA-02 exact multiple of the page size ends with one empty page, not an infinite loop', async () => {
    const all = rows(400, (i) => i);
    const calls = [];
    const out = await pageAll(async (o) => { calls.push(o.offset); return all.slice(o.offset, o.offset + o.limit); }, 200);
    expect(out).toHaveLength(400);
    expect(calls).toEqual([0, 200, 400]);
  });
  test('PA-03 exceeding the safety bound throws instead of truncating', async () => {
    await expect(pageAll(async () => rows(5, (i) => i), 5, 10)).rejects.toMatchObject({ code: 'DSR_RESULT_TOO_LARGE' });
  });
});

describe('RestrictionService / PortabilityService with a subject that has > 200 consent records', () => {
  const consent = rows(450, (i) => ({ id: `c${i}`, state: 'ACTIVE', actor_id: 'a1', tenant_id: null }));

  test('PA-04 restrict() suspends ALL 450 active records (was: only the first 200)', async () => {
    DSRStore.findById.mockResolvedValue({ id: 'r1', request_type: 'RESTRICTION', actor_id: 'a1', tenant_id: null, status: 'APPROVED' });
    ConsentStore.list.mockImplementation(async (o) => ({ records: consent.slice(o.offset || 0, (o.offset || 0) + o.limit), total: consent.length }));
    ConsentStore.suspend.mockImplementation(async ({ id }) => ({ id, state: 'SUSPENDED' }));
    await Restriction.restrict({ requestId: 'r1', restrictedBy: 'op' });
    expect(ConsentStore.suspend).toHaveBeenCalledTimes(450);
  });

  test('PA-05 the portability export contains ALL 450 consent records and the full audit history', async () => {
    DSRStore.findById.mockResolvedValue({ id: 'p1', request_type: 'PORTABILITY', actor_id: 'a1', tenant_id: null, status: 'APPROVED' });
    ConsentStore.list.mockImplementation(async (o) => ({ records: consent.slice(o.offset || 0, (o.offset || 0) + o.limit), total: consent.length }));
    const history = rows(1200, (i) => ({ id: `h${i}` }));
    ConsentStore.getAuditLog.mockImplementation(async (o) => history.slice(o.offset || 0, (o.offset || 0) + o.limit));
    DSRStore.list.mockImplementation(async (o) => ({ requests: [], total: 0 }));
    const out = await Portability.generateExport({ requestId: 'p1', generatedBy: 'op', format: 'JSON' });
    const payload = JSON.parse(out.payload);
    expect(payload.consentRecords).toHaveLength(450);
    expect(payload.consentHistory).toHaveLength(1200);
  });
});
