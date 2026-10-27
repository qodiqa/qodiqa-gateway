#!/usr/bin/env node
'use strict';

/**
 * qodiqa - command line of the gateway repository.
 *
 *   qodiqa dev [--port 3000] [--redis-url ...] [--no-docker-redis]    local sandbox (scripts/dev/qodiqa-dev.js)
 *   qodiqa help
 */

const path = require('path');
const { spawn } = require('child_process');

const [cmd, ...rest] = process.argv.slice(2);
const COMMANDS = { dev: path.join(__dirname, '..', 'scripts', 'dev', 'qodiqa-dev.js') };

if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') {
  process.stdout.write('usage: qodiqa <command>\n\ncommands:\n  dev    run the real gateway locally with a built-in sandbox provider (qodiqa dev --help)\n');
  process.exit(cmd ? 0 : 1);
}
if (!COMMANDS[cmd]) {
  process.stderr.write(`qodiqa: unknown command "${cmd}" (try: qodiqa help)\n`);
  process.exit(2);
}
const child = spawn(process.execPath, [COMMANDS[cmd], ...rest], { stdio: 'inherit' });
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { if (!child.killed) child.kill(sig); });
child.on('exit', (code) => process.exit(code ?? 0));
