/**
 * Generate the Ed25519 keypair that signs agent auto-update binaries.
 *
 * ```sh
 * bun run apps/agent/scripts/gen-update-key.ts
 * ```
 *
 * The public half goes in apps/agent/src/pubkey.ts and in AGENT_UPDATE_PUBKEY
 * (@servor/shared/constants), both committed; the private half becomes the
 * GitHub secret AGENT_UPDATE_PRIVATE_KEY, and nowhere else.
 *
 * @remarks
 * The split is the entire point of the scheme. The public key is compiled into
 * every agent, so each machine can check for itself who produced the binary it
 * is about to run. The private key must live somewhere an attacker who takes
 * over the API host still cannot reach — which is why CI signs the builds
 * (scripts/sign-release.ts) and the API only relays the signatures. A
 * compromised control plane can serve a modified binary, but cannot make one
 * the fleet accepts.
 *
 * Both keys are printed to stdout, which means this belongs on a trusted
 * machine and not in CI logs. Rotating the pair requires shipping a new agent
 * build: agents already deployed only trust the key they were compiled with.
 *
 * @module
 */
import { generateKeyPairSync } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pub = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');

process.stdout.write('\n— apps/agent/src/pubkey.ts and @servor/shared/constants —\n');
process.stdout.write(`export const UPDATE_PUBKEY = '${pub}';\n`);
process.stdout.write(`export const AGENT_UPDATE_PUBKEY = '${pub}';\n`);
process.stdout.write('\n— CI secret only (gh secret set AGENT_UPDATE_PRIVATE_KEY) —\n');
process.stdout.write(`${priv}\n\n`);
