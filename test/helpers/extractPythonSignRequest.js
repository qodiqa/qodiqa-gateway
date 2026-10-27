'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT_PATH = path.join(__dirname, 'extract_python_sign_calls.py');

let cachedExe; // null = "checked, none found"; undefined = "not checked yet"

function resolvePythonExe() {
  if (cachedExe !== undefined) return cachedExe;
  for (const exe of ['python3', 'python', 'py']) {
    const probe = spawnSync(exe, ['--version'], { encoding: 'utf8' });
    if (!probe.error && probe.status === 0) {
      cachedExe = exe;
      return cachedExe;
    }
  }
  cachedExe = null;
  return cachedExe;
}

/**
 * Extracts every `.sign.sign(<dict>)` call bound to /ai/chat from Python
 * `source`, evaluated with test/helpers/extract_python_sign_calls.py, and
 * returns them as real JS objects (via JSON) — the actual request each
 * Python example would send, not a hand-copied duplicate of it.
 *
 * Requires a Python 3 interpreter on PATH (python3, python, or py — GitHub
 * Actions' ubuntu-latest runner images ship python3 by default; this repo's
 * own sdk-python CI job also installs one). Throws loudly if none is found
 * rather than silently skipping — this test exists specifically to be a
 * hard CI gate, so an environment that can't run it should fail, not pass
 * silently.
 */
function extractPythonAiChatSignRequests(source) {
  const exe = resolvePythonExe();
  if (!exe) {
    throw new Error(
      'No Python interpreter found (tried python3, python, py) — required to validate ' +
      'Python SDK examples against the real /sign contract. Install Python 3, or skip this ' +
      'suite explicitly if your environment genuinely cannot run it.',
    );
  }
  const result = spawnSync(exe, [SCRIPT_PATH, '-'], { input: source, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`Python sign-call extraction failed (${exe}): ${result.stderr || result.error}`);
  }
  return JSON.parse(result.stdout);
}

module.exports = { extractPythonAiChatSignRequests };
