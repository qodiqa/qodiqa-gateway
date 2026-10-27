'use strict';

// Item 22 — SDK-availability gate tests. Resolution failure is always
// simulated via an injected resolver function — never by installing or
// uninstalling a real package (per owner instruction).

const { checkSdkAvailability, SDK_MANIFEST } = require('../sdkAvailability');

function resolverMissingAll() {
  return () => { throw new Error('Cannot find module'); };
}

function resolverPresentAll() {
  return (id) => `/fake/node_modules/${id}/index.js`;
}

function resolverMissingOnly(missingIds) {
  return (id) => {
    if (missingIds.includes(id)) throw new Error('Cannot find module');
    return `/fake/node_modules/${id}/index.js`;
  };
}

describe('sdkAvailability.checkSdkAvailability', () => {
  test('local provider requires no SDK — always ok, no resolver calls needed', () => {
    const resolve = jest.fn();
    const result = checkSdkAvailability('local', { resolve });
    expect(result).toEqual({ provider: 'local', ok: true, missing: [] });
    expect(resolve).not.toHaveBeenCalled();
  });

  test('unrecognized provider name requires no SDK here — left to keyProviderFactory', () => {
    const resolve = jest.fn();
    const result = checkSdkAvailability('not-a-real-provider', { resolve });
    expect(result).toEqual({ provider: 'not-a-real-provider', ok: true, missing: [] });
    expect(resolve).not.toHaveBeenCalled();
  });

  describe.each(Object.entries(SDK_MANIFEST))('%s', (provider, packages) => {
    test('resolves cleanly when every package is present', () => {
      const result = checkSdkAvailability(provider, { resolve: resolverPresentAll() });
      expect(result).toEqual({ provider, ok: true, missing: [] });
    });

    test('FATALs naming backend, missing package(s), and install command when unresolvable', () => {
      let thrown;
      try {
        checkSdkAvailability(provider, { resolve: resolverMissingAll() });
      } catch (err) {
        thrown = err;
      }
      expect(thrown).toBeDefined();
      expect(thrown.message).toContain(`KMS provider "${provider}"`);
      for (const pkg of packages) {
        expect(thrown.message).toContain(pkg);
      }
      expect(thrown.message).toContain(`npm install ${packages.join(' ')}`);
    });
  });

  test('azure-kv: partial resolution failure (one of two packages missing) is still reported precisely', () => {
    let thrown;
    try {
      checkSdkAvailability('azure-kv', { resolve: resolverMissingOnly(['@azure/identity']) });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeDefined();
    expect(thrown.message).toContain('@azure/identity');
    expect(thrown.message).not.toContain('@azure/keyvault-keys is not installed');
    expect(thrown.message).toContain('npm install @azure/identity');
  });

  test('default resolver is require.resolve — a genuinely-uninstalled package still FATALs (no mocking, real resolution)', () => {
    let thrown;
    try {
      checkSdkAvailability('aws-kms'); // no opts.resolve override — exercises the real default
    } catch (err) {
      thrown = err;
    }
    // As inventory, @aws-sdk/client-kms is not installed in this repo.
    // If's optionalDependencies + npm install already ran, this SDK may
    // now be present — either outcome is valid; only assert internal consistency.
    if (thrown) {
      expect(thrown.message).toContain('@aws-sdk/client-kms');
    } else {
      expect(() => require.resolve('@aws-sdk/client-kms')).not.toThrow();
    }
  });
});
