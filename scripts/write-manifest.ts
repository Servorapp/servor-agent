/**
 * Write dist/manifest.json, the version and signed digests the API advertises.
 *
 * @remarks
 * Deliberately the last step of the build, after the binaries exist. The
 * manifest is what tells agents a newer version is available, so writing it
 * from the source constant at any earlier point would let a bumped-but-unbuilt
 * version send every agent chasing a download that is not there.
 *
 * Signatures come from CI (agent-signatures.json at the repository root, or
 * AGENT_RELEASE_SIGNATURES) and are kept only for binaries byte-identical to
 * the ones CI signed — see release-signatures.ts. A build without one is still
 * written, and agents refuse to install it.
 *
 * @module
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { BUILD_VERSION } from '../src/version';
import { applySignatures, digestBuilds, type ReleaseSignatures } from './release-signatures';

const dist = join(import.meta.dir, '..', 'dist');
const out = join(dist, 'manifest.json');
const signaturesPath =
  process.env.AGENT_RELEASE_SIGNATURES ??
  join(import.meta.dir, '..', '..', '..', 'agent-signatures.json');

const signed: ReleaseSignatures | null = existsSync(signaturesPath)
  ? (JSON.parse(readFileSync(signaturesPath, 'utf8')) as ReleaseSignatures)
  : null;
const { builds, unsigned } = applySignatures(BUILD_VERSION, digestBuilds(dist), signed);

mkdirSync(dirname(out), { recursive: true });
writeFileSync(
  out,
  JSON.stringify({ version: BUILD_VERSION, builtAt: new Date().toISOString(), builds }),
);
process.stdout.write(`manifest written: ${BUILD_VERSION}\n`);
if (!signed) {
  process.stdout.write('no release signatures: agents will not install these builds\n');
} else if (unsigned.length > 0) {
  process.stdout.write(
    `unsigned (differs from the build CI signed, or other version): ${unsigned.join(', ')}\n`,
  );
}
