'use strict';

/**
 * Runtime Process Hardening Tests
 *
 * Validates that applyProcessHardening() applies the expected controls
 * without breaking the process or throwing errors.
 */

const { applyProcessHardening, SAFE_PROCESS_TITLE } = require('../processHardening');

describe('Process Hardening', () => {
  describe('SAFE_PROCESS_TITLE', () => {
    test('is a non-empty string', () => {
      expect(typeof SAFE_PROCESS_TITLE).toBe('string');
      expect(SAFE_PROCESS_TITLE.length).toBeGreaterThan(0);
    });

    test('does not contain environment variable expansions', () => {
      expect(SAFE_PROCESS_TITLE).not.toMatch(/\$\{/);
      expect(SAFE_PROCESS_TITLE).not.toMatch(/process\.env/);
    });
  });

  describe('applyProcessHardening()', () => {
    test('does not throw', () => {
      expect(() => applyProcessHardening(() => {})).not.toThrow();
    });

    test('accepts a custom emit function', () => {
      const events = [];
      const emit = (level, event, data) => events.push({ level, event, data });
      applyProcessHardening(emit);
      expect(events.length).toBeGreaterThan(0);
    });

    test('emits PROCESS_HARDENING_APPLIED event', () => {
      const events = [];
      applyProcessHardening((level, event, data) => events.push({ level, event, data }));
      const applied = events.find(e => e.event === 'PROCESS_HARDENING_APPLIED');
      expect(applied).toBeDefined();
      expect(applied.level).toBe('INFO');
    });

    test('emits event with title and umask', () => {
      const events = [];
      applyProcessHardening((level, event, data) => events.push({ level, event, data }));
      const applied = events.find(e => e.event === 'PROCESS_HARDENING_APPLIED');
      expect(applied.data.title).toBe(SAFE_PROCESS_TITLE);
      expect(applied.data.umask).toBeDefined();
    });

    test('sets process.title to SAFE_PROCESS_TITLE', () => {
      applyProcessHardening(() => {});
      // process.title may differ after setTitle if the OS truncates it
      expect(process.title).toBe(SAFE_PROCESS_TITLE);
    });

    test('emits WARN event if NODE_ENV is not set', () => {
      const orig = process.env.NODE_ENV;
      delete process.env.NODE_ENV;
      try {
        const events = [];
        applyProcessHardening((level, event) => events.push({ level, event }));
        const warn = events.find(e => e.event === 'NODE_ENV_NOT_SET');
        expect(warn).toBeDefined();
        expect(warn.level).toBe('WARN');
      } finally {
        if (orig !== undefined) process.env.NODE_ENV = orig;
      }
    });

    test('does not warn about NODE_ENV when set to production', () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        const events = [];
        applyProcessHardening((level, event) => events.push({ level, event }));
        const warn = events.find(e => e.event === 'NODE_ENV_NOT_SET');
        expect(warn).toBeUndefined();
      } finally {
        process.env.NODE_ENV = orig;
      }
    });

    test('does not warn about NODE_ENV when set to test', () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      try {
        const events = [];
        applyProcessHardening((level, event) => events.push({ level, event }));
        const warn = events.find(e => e.event === 'NODE_ENV_NOT_SET');
        expect(warn).toBeUndefined();
      } finally {
        process.env.NODE_ENV = orig;
      }
    });

    test('emits WARN for unrecognised NODE_ENV value', () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'staging-special';
      try {
        const events = [];
        applyProcessHardening((level, event) => events.push({ level, event }));
        const warn = events.find(e => e.event === 'NODE_ENV_UNRECOGNISED');
        expect(warn).toBeDefined();
      } finally {
        process.env.NODE_ENV = orig;
      }
    });

    test('is idempotent (can be called multiple times without error)', () => {
      expect(() => {
        applyProcessHardening(() => {});
        applyProcessHardening(() => {});
      }).not.toThrow();
    });
  });
});
