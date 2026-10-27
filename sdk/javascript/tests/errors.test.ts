import {
  QodiqaError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  VerificationError,
  NotFoundError,
  RateLimitError,
  ServerError,
  NetworkError,
  TimeoutError,
  UnknownError,
  createError,
} from '../src/errors';

describe('Error classes', () => {
  // -------------------------------------------------------------------------
  // Inheritance
  // -------------------------------------------------------------------------

  describe('inheritance', () => {
    const cases: [string, QodiqaError][] = [
      ['AuthenticationError', new AuthenticationError('auth')],
      ['AuthorizationError', new AuthorizationError('authz')],
      ['ValidationError', new ValidationError('validation')],
      ['VerificationError', new VerificationError('verification')],
      ['NotFoundError', new NotFoundError('not found')],
      ['RateLimitError', new RateLimitError('rate limit')],
      ['ServerError', new ServerError('server error')],
      ['NetworkError', new NetworkError('network')],
      ['TimeoutError', new TimeoutError('timeout')],
      ['UnknownError', new UnknownError('unknown')],
    ];

    it.each(cases)('%s inherits from QodiqaError', (_name, err) => {
      expect(err).toBeInstanceOf(QodiqaError);
      expect(err).toBeInstanceOf(Error);
    });

    it.each(cases)('%s has correct name', (name, err) => {
      expect(err.name).toBe(name);
    });
  });

  // -------------------------------------------------------------------------
  // Properties
  // -------------------------------------------------------------------------

  describe('error properties', () => {
    it('stores message', () => {
      const err = new QodiqaError('hello world');
      expect(err.message).toBe('hello world');
    });

    it('stores status', () => {
      const err = new AuthenticationError('msg', { status: 401 });
      expect(err.status).toBe(401);
    });

    it('stores requestId', () => {
      const err = new NotFoundError('not found', { requestId: 'req-123' });
      expect(err.requestId).toBe('req-123');
    });

    it('stores details', () => {
      const err = new ValidationError('bad input', {
        details: { field: 'email', issue: 'invalid' },
      });
      expect(err.details).toEqual({ field: 'email', issue: 'invalid' });
    });

    it('defaults details to empty object', () => {
      const err = new QodiqaError('no details');
      expect(err.details).toEqual({});
    });

    it('AuthenticationError defaults status to 401', () => {
      const err = new AuthenticationError('unauthorized');
      expect(err.status).toBe(401);
    });

    it('AuthorizationError defaults status to 403', () => {
      const err = new AuthorizationError('forbidden');
      expect(err.status).toBe(403);
    });

    it('ValidationError defaults status to 400', () => {
      const err = new ValidationError('invalid');
      expect(err.status).toBe(400);
    });

    it('NotFoundError defaults status to 404', () => {
      const err = new NotFoundError('missing');
      expect(err.status).toBe(404);
    });

    it('RateLimitError defaults status to 429', () => {
      const err = new RateLimitError('rate limited');
      expect(err.status).toBe(429);
    });

    it('RateLimitError stores retryAfter', () => {
      const err = new RateLimitError('slow down', { retryAfter: 30 });
      expect(err.retryAfter).toBe(30);
    });

    it('VerificationError defaults status to 400', () => {
      const err = new VerificationError('signature invalid');
      expect(err.status).toBe(400);
    });

    it('VerificationError stores requestId', () => {
      const err = new VerificationError('tampered', { requestId: 'req-v1' });
      expect(err.requestId).toBe('req-v1');
    });
  });

  // -------------------------------------------------------------------------
  // createError
  // -------------------------------------------------------------------------

  describe('createError()', () => {
    it('maps 401 to AuthenticationError', () => {
      const err = createError(401, 'UNAUTHORIZED', 'Not authorized');
      expect(err).toBeInstanceOf(AuthenticationError);
    });

    it('maps UNAUTHORIZED reason to AuthenticationError', () => {
      const err = createError(200, 'UNAUTHORIZED', 'Token invalid');
      expect(err).toBeInstanceOf(AuthenticationError);
    });

    it('maps 403 to AuthorizationError', () => {
      const err = createError(403, 'FORBIDDEN', 'No access');
      expect(err).toBeInstanceOf(AuthorizationError);
    });

    it('maps 404 to NotFoundError', () => {
      const err = createError(404, 'NOT_FOUND', 'Resource missing');
      expect(err).toBeInstanceOf(NotFoundError);
    });

    it('maps 429 to RateLimitError', () => {
      const err = createError(429, 'RATE_LIMITED', 'Slow down');
      expect(err).toBeInstanceOf(RateLimitError);
    });

    it('maps 400 to ValidationError', () => {
      const err = createError(400, 'VALIDATION_ERROR', 'Bad input');
      expect(err).toBeInstanceOf(ValidationError);
    });

    it('maps 422 to ValidationError', () => {
      const err = createError(422, 'INVALID_REQUEST', 'Unprocessable');
      expect(err).toBeInstanceOf(ValidationError);
    });

    it('maps 500 to ServerError', () => {
      const err = createError(500, 'INTERNAL_ERROR', 'Server exploded');
      expect(err).toBeInstanceOf(ServerError);
    });

    it('maps 502 to ServerError', () => {
      const err = createError(502, 'BAD_GATEWAY', 'Gateway bad');
      expect(err).toBeInstanceOf(ServerError);
    });

    it('maps 503 to ServerError', () => {
      const err = createError(503, 'SERVICE_UNAVAILABLE', 'Down');
      expect(err).toBeInstanceOf(ServerError);
    });

    it('maps INVALID_SIGNATURE reason to VerificationError', () => {
      const err = createError(400, 'INVALID_SIGNATURE', 'Bad signature');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('maps EXPIRED reason to VerificationError', () => {
      const err = createError(400, 'EXPIRED', 'Artifact has expired');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('maps KEY_NOT_FOUND reason to VerificationError', () => {
      const err = createError(400, 'KEY_NOT_FOUND', 'Public key not registered');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('maps REQUEST_MISMATCH reason to VerificationError', () => {
      const err = createError(400, 'REQUEST_MISMATCH', 'Request content does not match signed hash');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('maps REPLAY_DETECTED reason to VerificationError', () => {
      const err = createError(400, 'REPLAY_DETECTED', 'Request ID already used');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('maps INVALID_ARTIFACT reason to VerificationError', () => {
      const err = createError(400, 'INVALID_ARTIFACT', 'Invalid artifact structure');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('maps unknown status to UnknownError', () => {
      const err = createError(418, 'IM_A_TEAPOT', 'Brew tea');
      expect(err).toBeInstanceOf(UnknownError);
    });

    it('populates requestId', () => {
      const err = createError(404, 'NOT_FOUND', 'Missing', 'req-xyz');
      expect(err.requestId).toBe('req-xyz');
    });

    it('populates details', () => {
      const err = createError(400, 'VALIDATION_ERROR', 'Bad', undefined, {
        field: 'prompt',
      });
      expect(err.details).toEqual({ field: 'prompt' });
    });

    it('RateLimitError retryAfter comes from details', () => {
      const err = createError(429, 'RATE_LIMITED', 'Slow', undefined, {
        retryAfter: 60,
      });
      expect(err).toBeInstanceOf(RateLimitError);
      expect((err as RateLimitError).retryAfter).toBe(60);
    });

    // (SDK half): reason-code is now checked before the blanket
    // status===403 branch. Every VerificationError reason maps to HTTP 403
    // server-side (src/errors/catalog.js) — previously this exact case
    // (status 403 + a VerificationError reason) always fell into
    // AuthorizationError instead, because the status check ran first.
    it('status 403 + REQUEST_MISMATCH reason maps to VerificationError, not AuthorizationError', () => {
      const err = createError(403, 'REQUEST_MISMATCH', 'Request content does not match signed hash');
      expect(err).toBeInstanceOf(VerificationError);
    });

    it('status 403 + FORBIDDEN reason still maps to AuthorizationError (no misclassification)', () => {
      const err = createError(403, 'FORBIDDEN', 'No access');
      expect(err).toBeInstanceOf(AuthorizationError);
      expect(err).not.toBeInstanceOf(VerificationError);
    });

    it('status 401 is unaffected by the reorder', () => {
      const err = createError(401, 'UNAUTHORIZED', 'Not authorized');
      expect(err).toBeInstanceOf(AuthenticationError);
      expect(err).not.toBeInstanceOf(VerificationError);
    });
  });
});
