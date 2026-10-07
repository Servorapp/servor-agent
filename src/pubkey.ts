// ed25519 public key (base64 SPKI/DER) verifying auto-update binaries.
// Generate the keypair with: bun run scripts/gen-update-key.ts
//   → put the public key here, the private key in the GitHub secret AGENT_UPDATE_PRIVATE_KEY
//     (never on the API host: CI signs, the API only relays the signatures).
// Empty string = the agent REFUSES to self-update (fail closed). A release
// build must set this, or auto-update is inert.
// Mirrored as AGENT_UPDATE_PUBKEY in packages/shared/src/constants/agent.ts;
// rotate both. The agent reads that constant through its vendored copy
// (src/protocol/agent-constants.ts), refreshed by `bun run protocol:sync`.
export const UPDATE_PUBKEY = 'MCowBQYDK2VwAyEAMk9aHGN/6q08ivnExsZSRGWOJ2ZRTbePkRGqwka9mFw=';
