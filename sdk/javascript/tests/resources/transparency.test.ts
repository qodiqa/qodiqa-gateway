import { MockServer } from '../mock-server';
import { QodiqaClient, AuthenticationError } from '../../src/index';
import type {
  ApiResponse,
  TransparencyEntry,
  TransparencyRegisterResult,
  TransparencyRoot,
  TransparencyRootList,
  TransparencyRootGenerated,
  TransparencyChainValidation,
  TransparencyVerifyResult,
  InclusionProof,
  PaginatedResponse,
} from '../../src/types';

const VALID_API_KEY = 'ok_' + 'b'.repeat(64);

// the server's real public entry — verification fields only.
const MOCK_ENTRY: TransparencyEntry = {
  id: '1',
  transparency_id: 'entry-001',
  entry_type: 'ARTIFACT',
  artifact_id: 'art-1',
  evidence_chain_id: null,
  verification_id: null,
  payload_hash: 'a'.repeat(64),
  previous_entry_hash: null,
  entry_hash: 'b'.repeat(64),
  signer_key_id: 'tlk-1',
  signature: 'sig-entry',
  created_at: '2024-01-01T00:00:00.000Z',
};

const MOCK_REGISTERED: TransparencyRegisterResult = {
  transparencyId: 'entry-001',
  entryHash: 'b'.repeat(64),
  keyId: 'tlk-1',
  persisted: true,
  createdAt: '2024-01-01T00:00:00.000Z',
};

// fixtures are real server bodies captured by scripts/contract/live-contract.js,
// not invented shapes — the previous invented ones are how the wrong root/proof/verify types went unnoticed.
const MOCK_ROOT: TransparencyRoot = {
  id: '1',
  root_id: '49d25ba4-5f5f-4f63-85cf-b2c5c851ac76',
  seq_from: '1',
  seq_to: '2',
  entry_count: 2,
  root_hash: '9c48368c91610b89c176fe494001d9e9c6b1df676d56c621e03eda20ba28590f',
  previous_root_hash: null,
  signature: '1VTz9v7Wp01IiPL74arhTn83FWUQ2Xu94Bs62Rg0S/kghjPREYMzMKrCcql1N4Bngv1QGr17oLCeMrrUjllODQ==',
  signer_key_id: 'tr-dev-local:key_v1',
  generated_by: 'admin',
  generated_at: '2026-10-02T07:11:13.340Z',
};
const { signature: _omitted, ...MOCK_ROOT_LIST_ROW } = MOCK_ROOT;

function mockApiResponse<T>(data: T): ApiResponse<T> {
  return {
    status: 'success',
    timestamp: new Date().toISOString(),
    requestId: 'req-transparency',
    data,
  };
}

describe('TransparencyResource', () => {
  let server: MockServer;
  let baseUrl: string;

  beforeAll(async () => {
    server = new MockServer();
    baseUrl = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    server.reset();
  });

  function makeClient(withApiKey = false) {
    return new QodiqaClient({
      baseUrl,
      timeout: 5000,
      maxRetries: 0,
      ...(withApiKey ? { apiKey: VALID_API_KEY } : {}),
    });
  }

  // -------------------------------------------------------------------------
  // getEntry()
  // -------------------------------------------------------------------------

  describe('getEntry()', () => {
    it('returns a transparency entry', async () => {
      server.mock('GET', '/v1/transparency/entry/:id', {
        status: 200,
        body: mockApiResponse({ entry: MOCK_ENTRY }),
      });

      const client = makeClient();
      const res = await client.transparency.getEntry('entry-001');
      expect(res.data.entry.transparency_id).toBe('entry-001');
      expect(res.data.entry.entry_hash).toHaveLength(64);
      // no payload / tenant on the public entry
      expect(res.data.entry).not.toHaveProperty('payload');
      expect(res.data.entry).not.toHaveProperty('tenant_id');
    });

    it('throws on empty id', async () => {
      const client = makeClient();
      await expect(client.transparency.getEntry('')).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // listEntries()
  // -------------------------------------------------------------------------

  describe('listEntries()', () => {
    it('returns paginated entries', async () => {
      const paginated: PaginatedResponse<TransparencyEntry> = {
        records: [MOCK_ENTRY],
        page: 1,
        pageSize: 50,
        total: 1,
        hasMore: false,
      };

      server.mock('GET', '/v1/transparency/entries', {
        status: 200,
        body: mockApiResponse(paginated),
      });

      const client = makeClient();
      const res = await client.transparency.listEntries({ page: 1 });
      expect(res.data.records).toHaveLength(1);
      expect(res.data.total).toBe(1);
    });

    it('passes pagination params as query params', async () => {
      server.mock('GET', '/v1/transparency/entries', {
        status: 200,
        body: mockApiResponse({
          records: [],
          page: 2,
          pageSize: 10,
          total: 0,
          hasMore: false,
        }),
      });

      const client = makeClient();
      await client.transparency.listEntries({ page: 2, pageSize: 10 });
      const log = server.getCallLog();
      expect(log[0]!.path).toContain('page=2');
      expect(log[0]!.path).toContain('pageSize=10');
    });
  });

  // -------------------------------------------------------------------------
  // verifyEntry()
  // -------------------------------------------------------------------------

  describe('verifyEntry()', () => {
    it('returns the server verification document', async () => {
      const result: TransparencyVerifyResult = {
        transparencyId: 'a681a50b-8dc1-4f08-a25d-f5e2867642c3',
        verifiedAt: '2026-10-02T07:11:13.430Z',
        durationMs: 1,
        result: 'VALID',
        signatureValid: null,
        signerKeyStatus: null,
        integrityChecks: [{ check: 'PAYLOAD_HASH', result: 'PASS' }, { check: 'ENTRY_HASH', result: 'PASS' }, { check: 'CHAIN_LINK', result: 'PASS' }],
        firstFailure: null,
      };
      server.mock('GET', '/v1/transparency/verify/:id', { status: 200, body: mockApiResponse(result) });
      const res = await makeClient().transparency.verifyEntry('a681a50b-8dc1-4f08-a25d-f5e2867642c3');
      expect(res.data.result).toBe('VALID');
      expect(res.data.integrityChecks).toHaveLength(3);
      expect(res.data.firstFailure).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // getProof()
  // -------------------------------------------------------------------------

  describe('getProof()', () => {
    it('returns the RFC 6962 inclusion proof document', async () => {
      const proof: InclusionProof = {
        transparencyId: 'a681a50b-8dc1-4f08-a25d-f5e2867642c3',
        proof: {
          proofVersion: '2',
          proofType: 'TRANSPARENCY_INCLUSION',
          generatedAt: '2026-10-02T07:11:13.414Z',
          entry: { transparencyId: 'a681a50b-8dc1-4f08-a25d-f5e2867642c3', id: 2, entryType: 'AUDIT' },
          root: { rootId: MOCK_ROOT.root_id, rootHash: MOCK_ROOT.root_hash },
          proof: { leafIndex: 1, treeSize: 2, merklePath: [{ hash: '9dd93afd14da6dc509c7612c2259cdce916a1cdf8d490800e77cc18a4747e2db', side: 'left' }], merkleRoot: MOCK_ROOT.root_hash },
          verifiable: true,
        },
        proofVerification: { valid: true, checks: [{ check: 'MERKLE_PATH', result: 'PASS' }], failedCheck: null, failureReason: null },
      };
      server.mock('GET', '/v1/transparency/proof/:id', { status: 200, body: mockApiResponse(proof) });
      const res = await makeClient().transparency.getProof('a681a50b-8dc1-4f08-a25d-f5e2867642c3');
      expect(res.data.proof?.proof.merklePath[0]?.side).toBe('left');
      expect(res.data.proof?.proof.merkleRoot).toBe(MOCK_ROOT.root_hash);
      expect(res.data.proofVerification?.valid).toBe(true);
    });

    it('carries a null proof with a message before a root covers the entry', async () => {
      server.mock('GET', '/v1/transparency/proof/:id', { status: 200, body: mockApiResponse({ transparencyId: 'x', proof: null, message: 'no root covers this entry yet' }) });
      const res = await makeClient().transparency.getProof('x');
      expect(res.data.proof).toBeNull();
      expect(res.data.message).toMatch(/root/);
    });
  });

  // -------------------------------------------------------------------------
  // getRoot() / listRoots() —
  // -------------------------------------------------------------------------

  describe('getRoot()', () => {
    it('returns the latest root under data.root', async () => {
      server.mock('GET', '/v1/transparency/root', { status: 200, body: mockApiResponse({ root: MOCK_ROOT }) });
      const res = await makeClient().transparency.getRoot();
      expect(res.data.root?.root_id).toBe(MOCK_ROOT.root_id);
      expect(server.getCallLog()[0]!.path).toBe('/v1/transparency/root');
    });

    it('passes rootId as a query parameter', async () => {
      server.mock('GET', '/v1/transparency/root', { status: 200, body: mockApiResponse({ root: MOCK_ROOT }) });
      await makeClient().transparency.getRoot(MOCK_ROOT.root_id);
      expect(server.getCallLog()[0]!.path).toBe(`/v1/transparency/root?rootId=${MOCK_ROOT.root_id}`);
    });

    it('returns root: null before the first root', async () => {
      server.mock('GET', '/v1/transparency/root', { status: 200, body: mockApiResponse({ root: null, message: 'No roots generated yet' }) });
      const res = await makeClient().transparency.getRoot();
      expect(res.data.root).toBeNull();
    });
  });

  describe('listRoots()', () => {
    it('calls GET /v1/transparency/roots (not the latest-root endpoint) and returns data.roots', async () => {
      const list: TransparencyRootList = { roots: [MOCK_ROOT_LIST_ROW], total: 1, page: 1, pageSize: 5, totalItems: 1, totalPages: 1, hasNextPage: false, hasPreviousPage: false };
      server.mock('GET', '/v1/transparency/roots', { status: 200, body: mockApiResponse(list) });
      const res = await makeClient().transparency.listRoots({ page: 1, pageSize: 5 });
      const log = server.getCallLog();
      expect(log[0]!.path.startsWith('/v1/transparency/roots?')).toBe(true);
      expect(log[0]!.path).toContain('page=1');
      expect(log[0]!.path).toContain('pageSize=5');
      expect(res.data.roots).toHaveLength(1);
      expect(res.data.roots[0]!.root_hash).toBe(MOCK_ROOT.root_hash);
      expect(res.data.roots[0]).not.toHaveProperty('signature');
    });
  });

  // -------------------------------------------------------------------------
  // generateRoot() / validateChain() — ops protected
  // -------------------------------------------------------------------------

  describe('generateRoot()', () => {
    it('returns the generated root (camelCase result)', async () => {
      const gen: TransparencyRootGenerated = { rootId: MOCK_ROOT.root_id, seqFrom: 1, seqTo: 2, entryCount: 2, rootHash: MOCK_ROOT.root_hash, previousRootHash: null, keyId: 'tr-dev-local:key_v1', persisted: true, generatedAt: '2026-10-02T07:11:13.340Z' };
      server.mock('POST', '/v1/transparency/admin/roots/generate', { status: 201, body: mockApiResponse(gen) });
      const res = await makeClient(true).transparency.generateRoot();
      expect(res.data.rootHash).toBe(MOCK_ROOT.root_hash);
      expect(server.getCallLog()[0]!.headers['authorization']).toMatch(/^Bearer ok_/);
    });
  });

  describe('validateChain()', () => {
    it('calls the TRANSPARENCY chain validator, not the audit-chain endpoint', async () => {
      const v: TransparencyChainValidation = { chainValidation: { valid: true, checkedCount: 2, failureId: null, failureDetail: null }, startId: null, endId: null, limit: 1000, validatedAt: '2026-10-02T07:11:13.462Z', validatedBy: 'admin' };
      server.mock('GET', '/v1/transparency/admin/chain/validate', { status: 200, body: mockApiResponse(v) });
      const res = await makeClient(true).transparency.validateChain();
      expect(server.getCallLog()[0]!.path).toBe('/v1/transparency/admin/chain/validate');
      expect(res.data.chainValidation.valid).toBe(true);
    });

    it('throws AuthenticationError without apiKey', async () => {
      await expect(makeClient(false).transparency.validateChain()).rejects.toBeInstanceOf(AuthenticationError);
    });
  });

  // -------------------------------------------------------------------------
  // register() — ops protected
  // -------------------------------------------------------------------------

  describe('register()', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(
        client.transparency.register({ type: 'attestation' }),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('registers an entry with ops key', async () => {
      server.mock('POST', '/v1/transparency/register', {
        status: 201,
        body: mockApiResponse(MOCK_REGISTERED),
      });

      const client = makeClient(true);
      const res = await client.transparency.register({ entryType: 'ARTIFACT', artifactId: 'art-1' });
      expect(res.data.transparencyId).toBe('entry-001');
      expect(res.data.persisted).toBe(true);
    });

    it('sends Authorization header', async () => {
      server.mock('POST', '/v1/transparency/register', {
        status: 200,
        body: mockApiResponse(MOCK_ENTRY),
      });

      const client = makeClient(true);
      await client.transparency.register({ type: 'test' });
      const log = server.getCallLog();
      expect(log[0]!.headers['authorization']).toMatch(/^Bearer ok_/);
    });
  });

  // -------------------------------------------------------------------------
  // stats() — ops protected
  // -------------------------------------------------------------------------

  describe('stats()', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.transparency.stats()).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });
  });
});
