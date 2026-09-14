import { afterAll, describe, expect, test } from 'bun:test';
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  applySignatures,
  binaryName,
  digestBuilds,
  type ReleaseBuilds,
  sha256Hex,
  signBuilds,
} from './release-signatures';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const spki = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

// Exactly the check in src/updater.ts.
const agentAccepts = (sha256: string, signature: string) =>
  verify(
    null,
    Buffer.from(sha256, 'hex'),
    createPublicKey({ key: Buffer.from(spki, 'base64'), format: 'der', type: 'spki' }),
    Buffer.from(signature, 'base64'),
  );

const dir = join(tmpdir(), `servor-release-${process.pid}`);
mkdirSync(dir, { recursive: true });
writeFileSync(join(dir, binaryName('linux-x64')), 'linux build');
writeFileSync(join(dir, binaryName('windows-x64')), 'windows build');
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('digesting the built binaries', () => {
  test('every binary present is digested under its platform, and only those', () => {
    const builds = digestBuilds(dir);
    expect(Object.keys(builds).sort()).toEqual(['linux-x64', 'windows-x64']);
    expect(builds['linux-x64']?.sha256).toBe(sha256Hex(Buffer.from('linux build')));
  });

  test('the Windows binary is found under its .exe name', () => {
    expect(binaryName('windows-x64')).toBe('servor-agent-windows-x64.exe');
    expect(binaryName('linux-arm64-musl')).toBe('servor-agent-linux-arm64-musl');
  });
});

describe('signing a release', () => {
  // The format every deployed agent verifies; changing it would strand them.
  test('a signed build is one the agent’s updater accepts', () => {
    const signed = signBuilds(digestBuilds(dir), privateKey);
    for (const { sha256, signature } of Object.values(signed)) {
      expect(agentAccepts(sha256, signature ?? '')).toBe(true);
    }
  });
});

describe('carrying CI signatures onto the image build', () => {
  const version = '1.2.8';
  const local: ReleaseBuilds = { 'linux-x64': { sha256: 'a'.repeat(64) } };
  const ci = (over: Partial<ReleaseBuilds[string]> = {}, v = version) => ({
    version: v,
    builds: { 'linux-x64': { sha256: 'a'.repeat(64), signature: 'c2ln', ...over } },
  });

  test('a byte-identical build keeps its signature', () => {
    const { builds, unsigned } = applySignatures(version, local, ci());
    expect(builds['linux-x64']?.signature).toBe('c2ln');
    expect(unsigned).toEqual([]);
  });

  // The image built something else than what CI signed: never lend it the
  // signature, whatever the reason.
  test('a build that differs from the one CI signed ships unsigned', () => {
    const { builds, unsigned } = applySignatures(version, local, ci({ sha256: 'b'.repeat(64) }));
    expect(builds['linux-x64']?.signature).toBeUndefined();
    expect(unsigned).toEqual(['linux-x64']);
  });

  test('signatures made for another version are ignored', () => {
    const { builds } = applySignatures(version, local, ci({}, '1.2.7'));
    expect(builds['linux-x64']?.signature).toBeUndefined();
  });

  test('no signatures at all leaves every build unsigned but still listed', () => {
    const { builds, unsigned } = applySignatures(version, local, null);
    expect(builds['linux-x64']).toEqual({ sha256: 'a'.repeat(64) });
    expect(unsigned).toEqual(['linux-x64']);
  });

  test('a platform CI did not sign stays unsigned', () => {
    const both = { ...local, 'darwin-arm64': { sha256: 'd'.repeat(64) } };
    expect(applySignatures(version, both, ci()).unsigned).toEqual(['darwin-arm64']);
  });
});
