/**
 * Sign the freshly built agent binaries. Run by CI before shipping the API.
 *
 * ```sh
 * AGENT_RELEASE_SIGNING_KEY=… bun run apps/agent/scripts/sign-release.ts agent-signatures.json
 * ```
 *
 * @remarks
 * Reads the binaries in apps/agent/dist, signs their digests with the release
 * key (base64 PKCS#8 Ed25519, the GitHub secret AGENT_UPDATE_PRIVATE_KEY,
 * passed in as AGENT_RELEASE_SIGNING_KEY) and writes the signatures —
 * never the key — to the given file, which travels to the API image. See
 * release-signatures.ts for why the key stays out of the API.
 *
 * Exits non-zero without a key or without a single binary, so a misconfigured
 * pipeline does not ship a release no agent can install.
 *
 * @module
 */
import { createPrivateKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { BUILD_VERSION } from '../src/version';
import { digestBuilds, signBuilds } from './release-signatures';

const out = process.argv[2];
const raw = process.env.AGENT_RELEASE_SIGNING_KEY;
delete process.env.AGENT_RELEASE_SIGNING_KEY;

if (!out || !raw) {
  console.error('usage: AGENT_RELEASE_SIGNING_KEY=… sign-release.ts <out.json>');
  process.exit(1);
}

const der = Buffer.from(raw, 'base64');
let key: ReturnType<typeof createPrivateKey>;
try {
  key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
} catch {
  console.error('AGENT_RELEASE_SIGNING_KEY is not a base64 PKCS#8 key');
  process.exit(1);
} finally {
  der.fill(0);
}

const builds = digestBuilds(join(import.meta.dir, '..', 'dist'));
if (Object.keys(builds).length === 0) {
  console.error('no agent binary in apps/agent/dist — build first');
  process.exit(1);
}

writeFileSync(out, JSON.stringify({ version: BUILD_VERSION, builds: signBuilds(builds, key) }));
console.log(`signed ${Object.keys(builds).length} agent builds for ${BUILD_VERSION}`);
