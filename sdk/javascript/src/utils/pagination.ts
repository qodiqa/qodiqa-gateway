import type { PaginatedResponse } from '../types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A function that fetches one page given page number and size */
export type PageFetcher<T> = (
  page: number,
  pageSize: number,
) => Promise<PaginatedResponse<T>>;

// ---------------------------------------------------------------------------
// PagePage — iterates pages
// ---------------------------------------------------------------------------

/**
 * Async iterator that yields one `PaginatedResponse<T>` per page.
 *
 * @example
 * const iter = new PagePage(fetcher, { pageSize: 50 });
 * for await (const page of iter) {
 *   console.log(page.entries);
 * }
 */
export class PagePage<T> implements AsyncIterableIterator<PaginatedResponse<T>> {
  private currentPage: number;
  private readonly pageSize: number;
  private done = false;

  constructor(
    private readonly fetcher: PageFetcher<T>,
    options: { startPage?: number; pageSize?: number } = {},
  ) {
    this.currentPage = options.startPage ?? 1;
    this.pageSize = options.pageSize ?? 50;
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<PaginatedResponse<T>> {
    return this;
  }

  async next(): Promise<IteratorResult<PaginatedResponse<T>>> {
    if (this.done) {
      return { value: undefined as unknown as PaginatedResponse<T>, done: true };
    }

    const page = await this.fetcher(this.currentPage, this.pageSize);

    if (!page.hasNextPage) {
      this.done = true;
    } else {
      this.currentPage += 1;
    }

    return { value: page, done: false };
  }

  return(): Promise<IteratorResult<PaginatedResponse<T>>> {
    this.done = true;
    return Promise.resolve({
      value: undefined as unknown as PaginatedResponse<T>,
      done: true,
    });
  }
}

// ---------------------------------------------------------------------------
// PageIterator — iterates individual items across all pages
// ---------------------------------------------------------------------------

/**
 * Async iterator that transparently fetches successive pages and yields
 * individual items one at a time.
 *
 * @example
 * const iter = new PageIterator(fetcher, { pageSize: 50 });
 * for await (const item of iter) {
 *   console.log(item);
 * }
 */
export class PageIterator<T> implements AsyncIterableIterator<T> {
  private readonly pager: PagePage<T>;
  private buffer: T[] = [];
  private bufferIndex = 0;
  private done = false;

  constructor(
    fetcher: PageFetcher<T>,
    options: { startPage?: number; pageSize?: number } = {},
  ) {
    this.pager = new PagePage(fetcher, options);
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<T> {
    return this;
  }

  async next(): Promise<IteratorResult<T>> {
    // Still items remaining in the current buffer
    if (this.bufferIndex < this.buffer.length) {
      const value = this.buffer[this.bufferIndex++] as T;
      return { value, done: false };
    }

    if (this.done) {
      return { value: undefined as unknown as T, done: true };
    }

    // Fetch next page
    const result = await this.pager.next();
    if (result.done) {
      this.done = true;
      return { value: undefined as unknown as T, done: true };
    }

    this.buffer = result.value.entries;
    this.bufferIndex = 0;

    // The page iterator signals "done" after the last page is consumed
    if (!result.value.hasNextPage) {
      this.done = true;
    }

    if (this.buffer.length === 0) {
      return { value: undefined as unknown as T, done: true };
    }

    const value = this.buffer[this.bufferIndex++] as T;
    return { value, done: false };
  }

  return(): Promise<IteratorResult<T>> {
    this.done = true;
    return Promise.resolve({ value: undefined as unknown as T, done: true });
  }
}
