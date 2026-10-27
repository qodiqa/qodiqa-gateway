'use strict';

/** one canonical route resolver for /sign and the /ai/chat verifier. */

const { resolveRoute, isAiChatRoute, AI_CHAT_ALIASES } = require('../canonicalRoute');

describe('canonicalRoute — every alias the router maps to the AI handler resolves to ai_chat', () => {
  test.each([
    '/ai/chat', '/v1/ai/chat', '/ai/chat/stream', '/v1/ai/chat/stream',
    '/ai/chat/', '/v1/ai/chat/', '/ai/chat//', '//ai//chat',
    '/AI/Chat', '/V1/AI/CHAT', '/Ai/Chat/Stream',
    '/%61i/chat', '/ai%2Fchat', '/ai/%63hat', '/%2561i/chat',          // encoded, double-encoded
    '/ai/./chat', '/x/../ai/chat', '/ai/chat/.', '\\ai\\chat', '/ai\\chat/stream',
    '/ai/chat?x=1', '/ai/chat#frag', '/ai/chat%3Fx=1',
  ])('%s → ai_chat', (p) => {
    expect(resolveRoute(p).route).toBe('ai_chat');
    expect(isAiChatRoute(p)).toBe(true);
  });

  test('an undecodable path is treated as the AI route (strict branch)', () => {
    expect(resolveRoute('/ai/chat%E0%A4%A')).toMatchObject({ route: 'ai_chat', decodable: false });
    expect(resolveRoute('/whatever/%ZZ')).toMatchObject({ route: 'ai_chat', decodable: false });
  });

  test.each(['/verify', '/sign', '/ai/chatx', '/ai/chat/other', '/v2/ai/chat', '/ai', ''])('%s → other', (p) => {
    expect(resolveRoute(p).route).toBe('other');
  });

  test('non-string input → other', () => {
    expect(resolveRoute(undefined).route).toBe('other');
    expect(resolveRoute(42).route).toBe('other');
  });

  test('the alias list is exactly the four mounted AI paths', () => {
    expect([...AI_CHAT_ALIASES].sort()).toEqual(['/ai/chat', '/ai/chat/stream', '/v1/ai/chat', '/v1/ai/chat/stream']);
  });
});
