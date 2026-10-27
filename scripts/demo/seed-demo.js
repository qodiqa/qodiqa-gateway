'use strict';

/**
 * Public-demo seed CLI (launch plan R-03). See scripts/demo/seedDemoLib.js for exactly what it provisions.
 *
 * Usage:
 *   node scripts/demo/seed-demo.js --gateway http://127.0.0.1:3000 --environment production \
 *     --maker-key-file <ok_ file> --reviewer-key-file <ok_ file> --approver-key-file <ok_ file> \
 *     --out-dir <dir for 0600 sk_ key files> [--provider local] [--dry-run] \
 *     [--maker-otp-file f] [--reviewer-otp-file f] [--approver-otp-file f]
 *
 * OTP files (production, where operator MFA step-up is mandatory for every mutating admin call) are JSON:
 *   {"totpSecret": "<base32 secret from /rbac/me/mfa/enroll>", "recoveryCodes": ["...", ...]}
 * Either field may be omitted. Recovery codes are spent first; consumed codes are not written back.
 *
 * Operator keys are read from files (never from argv, which is visible in process listings). Output is JSON lines
 * with identity ids and actions only; no key material is ever printed.
 */

const fs = require('fs');
const { seedDemo, createApi, createOtpProvider, SeedError } = require('./seedDemoLib');

function parseArgs(argv) {
  const out = { dryRun: false, provider: 'local' };
  const map = {
    '--gateway': 'gateway', '--environment': 'environment', '--maker-key-file': 'makerFile',
    '--reviewer-key-file': 'reviewerFile', '--approver-key-file': 'approverFile', '--out-dir': 'outDir', '--provider': 'provider',
    '--maker-otp-file': 'makerOtp', '--reviewer-otp-file': 'reviewerOtp', '--approver-otp-file': 'approverOtp',
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dry-run') { out.dryRun = true; continue; }
    if (map[argv[i]]) { out[map[argv[i]]] = argv[++i]; continue; }
    throw new SeedError('args', `unknown argument ${argv[i]}`);
  }
  for (const k of ['gateway', 'environment', 'makerFile', 'reviewerFile', 'approverFile', 'outDir']) {
    if (!out[k]) throw new SeedError('args', `missing --${k.replace(/File$/, '-key-file').replace(/([A-Z])/g, '-$1').toLowerCase()}`);
  }
  if (!/^https?:\/\/[^\s]+$/.test(out.gateway)) throw new SeedError('args', '--gateway must be an http(s) URL');
  return out;
}

function readOperatorKey(file) {
  const v = String(fs.readFileSync(file, 'utf8')).trim();
  if (!/^ok_[A-Za-z0-9_-]{16,}$/.test(v)) throw new SeedError('args', `${file} does not hold an ok_ operator key`);
  return v;
}

function readOtp(file) {
  if (!file) return null;
  let j;
  try { j = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { throw new SeedError('args', `${file} is not a JSON OTP file`); }
  return createOtpProvider({ totpSecret: j.totpSecret || null, recoveryCodes: Array.isArray(j.recoveryCodes) ? j.recoveryCodes : [] });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await seedDemo({
    api: createApi({ gatewayUrl: args.gateway }),
    operators: { maker: readOperatorKey(args.makerFile), reviewer: readOperatorKey(args.reviewerFile), approver: readOperatorKey(args.approverFile) },
    otp: { maker: readOtp(args.makerOtp), reviewer: readOtp(args.reviewerOtp), approver: readOtp(args.approverOtp) },
    outDir: args.outDir,
    environment: args.environment,
    provider: args.provider,
    dryRun: args.dryRun,
    report: (line) => process.stdout.write(`${JSON.stringify(line)}\n`),
  });
  process.stdout.write(`${JSON.stringify({ status: args.dryRun ? 'DRY_RUN' : 'SEEDED', identities: result.identities, changes: result.actions.length })}\n`);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`${JSON.stringify({ status: 'ERROR', message: String(err && err.message).replace(/(sk|ok)_[A-Za-z0-9_-]+/g, '$1_[REDACTED]') })}\n`);
    process.exit(1);
  });
}

module.exports = { parseArgs };
