import { withRetry, isRetryable } from '../src/utils/retry';
import {
  ServerError,
  RateLimitError,
  AuthenticationError,
  NotFoundError,
  ValidationError,
} from '../src/errors';

// ---------------------------------------------------------------------------
// Helper: create an error with a status property
// ---------------------------------------------------------------------------

function serverErr(status: number): ServerError {
  return new ServerError('error', { status });
}

// ---------------------------------------------------------------------------
// isRetryable
// ---------------------------------------------------------------------------

describe('isRetryable()', () => {
  it('returns true for 429', () => expect(isRetryable(429)).toBe(true));
  it('returns true for 500', () => expect(isRetryable(500)).toBe(true));
  it('returns true for 502', () => expect(isRetryable(502)).toBe(true));
  it('returns true for 503', () => expect(isRetryable(503)).toBe(true));
  it('returns true for 504', () => expect(isRetryable(504)).toBe(true));

  it('returns false for 400', () => expect(isRetryable(400)).toBe(false));
  it('returns false for 401', () => expect(isRetryable(401)).toBe(false));
  it('returns false for 403', () => expect(isRetryable(403)).toBe(false));
  it('returns false for 404', () => expect(isRetryable(404)).toBe(false));
  it('returns false for 200', () => expect(isRetryable(200)).toBe(false));
});

// ---------------------------------------------------------------------------
// withRetry
// ---------------------------------------------------------------------------

describe('withRetry()', () => {
  // Use zero jitter and tiny base delay to keep tests fast
  const fastConfig = {
    maxRetries: 3,
    baseDelay: 1,
    maxDelay: 10,
    jitter: false,
  };

  it('returns the result on first success', async () => {
    const fn = jest.fn().mockResolvedValue('ok');
    const result = await withRetry(fn, fastConfig);
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on 500 and eventually succeeds', async () => {
    let attempts = 0;
    const fn = jest.fn(async () => {
      attempts++;
      if (attempts < 3) throw serverErr(500);
      return 'done';
    });

    const result = await withRetry(fn, fastConfig);
    expect(result).toBe('done');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('retries on 502', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(serverErr(502))
      .mockResolvedValue('ok');

    await expect(withRetry(fn, fastConfig)).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries on 503', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(serverErr(503))
      .mockResolvedValue('ok');

    await expect(withRetry(fn, fastConfig)).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries on 504', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(serverErr(504))
      .mockResolvedValue('ok');

    await expect(withRetry(fn, fastConfig)).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries on RateLimitError (429)', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(new RateLimitError('slow down'))
      .mockResolvedValue('ok');

    await expect(withRetry(fn, fastConfig)).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('does NOT retry 400 ValidationError', async () => {
    const fn = jest.fn().mockRejectedValue(new ValidationError('bad input'));
    await expect(withRetry(fn, fastConfig)).rejects.toBeInstanceOf(ValidationError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry 401 AuthenticationError', async () => {
    const fn = jest.fn().mockRejectedValue(new AuthenticationError('unauth'));
    await expect(withRetry(fn, fastConfig)).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry 404 NotFoundError', async () => {
    const fn = jest.fn().mockRejectedValue(new NotFoundError('missing'));
    await expect(withRetry(fn, fastConfig)).rejects.toBeInstanceOf(NotFoundError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('respects maxRetries and throws the last error', async () => {
    const fn = jest.fn().mockRejectedValue(serverErr(500));

    await expect(withRetry(fn, { ...fastConfig, maxRetries: 2 })).rejects.toBeInstanceOf(
      ServerError,
    );
    // Initial attempt + 2 retries = 3 total calls
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('calls onRetry callback for each retry', async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(serverErr(500))
      .mockRejectedValueOnce(serverErr(500))
      .mockResolvedValue('ok');

    const onRetry = jest.fn();
    await withRetry(fn, fastConfig, onRetry);

    expect(onRetry).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenNthCalledWith(
      1,
      1,
      expect.any(Number),
      expect.any(ServerError),
    );
    expect(onRetry).toHaveBeenNthCalledWith(
      2,
      2,
      expect.any(Number),
      expect.any(ServerError),
    );
  });

  it('exponential backoff: subsequent delays grow', async () => {
    const delays: number[] = [];
    const fn = jest
      .fn()
      .mockRejectedValueOnce(serverErr(500))
      .mockRejectedValueOnce(serverErr(500))
      .mockResolvedValue('ok');

    await withRetry(
      fn,
      { maxRetries: 3, baseDelay: 100, maxDelay: 10_000, jitter: false },
      (_attempt, delay) => delays.push(delay),
    );

    expect(delays).toHaveLength(2);
    // delay[1] should be >= delay[0] (exponential growth, no jitter)
    expect(delays[1]!).toBeGreaterThanOrEqual(delays[0]!);
  });
});
