/**
 * Release signatures: made in CI, matched against the binaries the API serves.
 *
 * @remarks
 * The key that signs agent binaries decides what a customer's machine installs
 * as root, so it must not live on the API host: whoever takes the API over must
 * not be able to sign a build. CI builds the binaries, signs their digests with
 * a key held only as a CI secret, and hands the API image nothing but those
 * signatures. The image rebuilds the binaries from the same sources with the
 * same Bun and keeps a signature only for a byte-identical build. If the two
 * builds ever diverge, the build ships unsigned and agents refuse it — the safe
 * way to fail.
 *
 * The signed message stays the raw SHA-256 digest: it is what every deployed
 * agent verifies, and a new format would stop them updating at all.
 *
 * @module
 */
import { createHash, type KeyObject, sign } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const AGENT_PLATFORMS = [
  'linux-x64',
  'linux-arm64',
  'linux-x64-musl',
  'linux-arm64-musl',
  'darwin-x64',
  'darwin-arm64',
  'windows-x64',
] as const;

export type ReleaseBuilds = Record<string, { sha256: string; signature?: string }>;
export type ReleaseSignatures = { version: string; builds: ReleaseBuilds };

export const binaryName = (platform: string): string =>
  `servor-agent-${platform}${platform.startsWith('windows') ? '.exe' : ''}`;

export const sha256Hex = (bytes: Uint8Array): string =>
  createHash('sha256').update(bytes).digest('hex');

/** Digest of every binary present in `dir`, by platform. */
export const digestBuilds = (dir: string): ReleaseBuilds => {
  const builds: ReleaseBuilds = {};
  for (const platform of AGENT_PLATFORMS) {
    const path = join(dir, binaryName(platform));
    if (existsSync(path)) builds[platform] = { sha256: sha256Hex(readFileSync(path)) };
  }
  return builds;
};

/** Sign each digest — Ed25519 over the raw 32 bytes, as the agent verifies it. */
export const signBuilds = (builds: ReleaseBuilds, key: KeyObject): ReleaseBuilds =>
  Object.fromEntries(
    Object.entries(builds).map(([platform, { sha256 }]) => [
      platform,
      { sha256, signature: sign(null, Buffer.from(sha256, 'hex'), key).toString('base64') },
    ]),
  );

/**
 * Carry CI's signatures onto the locally built binaries.
 *
 * @returns The local builds, each signed only where CI signed the very same
 * bytes for the very same version, and the platforms that did not match.
 */
export const applySignatures = (
  version: string,
  local: ReleaseBuilds,
  signed: ReleaseSignatures | null,
): { builds: ReleaseBuilds; unsigned: string[] } => {
  const usable = signed?.version === version ? signed.builds : {};
  const builds: ReleaseBuilds = {};
  const unsigned: string[] = [];
  for (const [platform, { sha256 }] of Object.entries(local)) {
    const ci = usable[platform];
    if (ci?.signature && ci.sha256 === sha256) {
      builds[platform] = { sha256, signature: ci.signature };
    } else {
      builds[platform] = { sha256 };
      unsigned.push(platform);
    }
  }
  return { builds, unsigned };
};
