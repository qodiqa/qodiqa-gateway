'use strict';

/**
 * per-request output cap carried by a V2 artifact (`payload.qodiqa.limits.maxTokens`, V2-FREEZE 4).
 * The effective cap is the smaller of the operator-configured provider cap and the artifact's cap; either may be absent.
 * The router passes the artifact's cap to adapters as `body.maxTokens` (a number the artifact signed; never caller-controlled).
 */
function capMaxTokens(configured, body) {
  const fromArtifact = body && Number.isSafeInteger(body.maxTokens) && body.maxTokens >= 1 ? body.maxTokens : null;
  const fromConfig = Number.isSafeInteger(configured) && configured >= 1 ? configured : null;
  if (fromArtifact === null) return fromConfig;
  return fromConfig === null ? fromArtifact : Math.min(fromArtifact, fromConfig);
}

module.exports = { capMaxTokens };
