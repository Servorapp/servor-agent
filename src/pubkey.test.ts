import { describe, expect, test } from 'bun:test';
import { AGENT_UPDATE_PUBKEY } from './protocol/agent-constants';
import { UPDATE_PUBKEY } from './pubkey';

describe('update public key', () => {
  // The dashboard checks a build against the shared copy before signing the
  // command that installs it. If the two drift, it either refuses every real
  // release or accepts builds this agent would never install on its own.
  test('matches the copy the dashboard verifies builds against', () => {
    expect(UPDATE_PUBKEY).toBe(AGENT_UPDATE_PUBKEY);
  });
});
