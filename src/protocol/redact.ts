// Vendored from packages/shared/src/utils/redact.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

/**
 * Strip credentials out of command output before it is shown to a model.
 *
 * @remarks
 * This runs in the browser, on the plaintext, before anything leaves the
 * client — redacting server-side would be pointless, since the server would
 * already have read what it is redacting.
 *
 * It is a net, not a proof. Pattern matching cannot recognise a secret it has
 * never seen a shape for, and a determined leak will get through. It is here to
 * stop the routine cases — a `cat` of a key file, an `env` dump, a connection
 * string in a log line — not to make sending output safe in principle.
 *
 * Replacements are labelled rather than blanked, because a model that sees
 * `[redacted:aws-access-key-id]` can still reason about the situation, while
 * `xxxx` only tells it that something was there. The secret is equally gone
 * either way.
 */

/** What a rule recognises, used as the label in the replacement. */
export type RedactionKind =
  | 'private-key'
  | 'ssh-private-key'
  | 'certificate-request'
  | 'aws-access-key-id'
  | 'aws-secret-access-key'
  | 'gcp-service-account'
  | 'github-token'
  | 'gitlab-token'
  | 'slack-token'
  | 'stripe-key'
  | 'openai-key'
  | 'anthropic-key'
  | 'jwt'
  | 'bearer-token'
  | 'basic-auth'
  | 'connection-string'
  | 'shadow-hash'
  | 'env-secret'
  | 'generic-api-key';

type Rule = {
  kind: RedactionKind;
  pattern: RegExp;
  /**
   * Rebuild the line keeping whatever identifies it — a variable name, a URL
   * host — so the output still reads. Defaults to replacing the whole match.
   */
  replace?: (match: string, ...groups: string[]) => string;
};

// No space inside the marker: several rules capture the secret as `\S+`, so a
// marker containing a space would be split in half by a later rule and the
// tail left dangling in the output.
const mark = (kind: RedactionKind) => `[redacted:${kind}]`;

/** Recognises a replacement this module already made, anywhere in a match. */
const MARKER = /\[redacted:[a-z-]+\]/;

/**
 * Order matters: multi-line blocks are consumed before the single-line rules
 * get a chance to match fragments of them.
 */
const RULES: Rule[] = [
  // ── Key material ────────────────────────────────────────────────────────
  {
    kind: 'ssh-private-key',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
  },
  {
    kind: 'private-key',
    pattern:
      /-----BEGIN (?:RSA |DSA |EC |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    kind: 'certificate-request',
    pattern: /-----BEGIN CERTIFICATE REQUEST-----[\s\S]*?-----END CERTIFICATE REQUEST-----/g,
  },

  // ── Provider-shaped tokens, recognisable by prefix ──────────────────────
  { kind: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  {
    kind: 'aws-secret-access-key',
    pattern: /\baws_secret_access_key\s*=\s*\S+/gi,
    replace: () => `aws_secret_access_key = ${mark('aws-secret-access-key')}`,
  },
  { kind: 'github-token', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g },
  { kind: 'github-token', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { kind: 'gitlab-token', pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { kind: 'slack-token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: 'stripe-key', pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { kind: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { kind: 'openai-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/g },
  { kind: 'gcp-service-account', pattern: /"private_key_id"\s*:\s*"[^"]+"/g },

  // ── Transport-level credentials ─────────────────────────────────────────
  {
    kind: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    kind: 'bearer-token',
    pattern: /\b(Authorization|Proxy-Authorization)\s*:\s*(Bearer|Token)\s+\S+/gi,
    replace: (_m, header, scheme) => `${header}: ${scheme} ${mark('bearer-token')}`,
  },
  {
    kind: 'basic-auth',
    pattern: /\b(Authorization)\s*:\s*Basic\s+\S+/gi,
    replace: (_m, header) => `${header}: Basic ${mark('basic-auth')}`,
  },

  // Credentials embedded in a URL: keep the scheme and the host, drop the pair.
  {
    kind: 'connection-string',
    pattern: /\b([a-z][a-z0-9+.-]*):\/\/([^\s:/@]+):([^\s@]+)@/gi,
    replace: (_m, scheme, user) => `${scheme}://${user}:${mark('connection-string')}@`,
  },

  // ── System files ────────────────────────────────────────────────────────
  // /etc/shadow: user:hash:… — keep the user, drop the hash.
  {
    kind: 'shadow-hash',
    pattern: /^([a-z_][a-z0-9_-]{0,31}):(\$[0-9a-z]\$[^:]+):/gim,
    replace: (_m, user) => `${user}:${mark('shadow-hash')}:`,
  },

  // ── Environment-style assignments, matched on the name ──────────────────
  {
    kind: 'env-secret',
    pattern:
      /^(\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|PASSPHRASE|SESSION_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*(.+)$/gim,
    replace: (_m, name) => `${name}=${mark('env-secret')}`,
  },
  // Same idea in JSON or YAML.
  {
    kind: 'generic-api-key',
    pattern:
      /("(?:[a-z_]*(?:password|secret|token|api_?key|private_?key|credential|passphrase)[a-z_]*)"\s*:\s*)"[^"]*"/gi,
    replace: (_m, prefix) => `${prefix}"${mark('generic-api-key')}"`,
  },
  {
    kind: 'generic-api-key',
    pattern:
      /^(\s*[a-z_]*(?:password|secret|token|api_?key|private_?key|credential|passphrase)[a-z_]*\s*:\s+)(?!\s*$)\S.*$/gim,
    replace: (_m, prefix) => `${prefix}${mark('generic-api-key')}`,
  },
];

/** What was removed, and how much of it. */
export type RedactionSummary = { kind: RedactionKind; count: number };

export type RedactionResult = {
  /** The text with every match replaced. */
  text: string;
  /** One entry per kind that matched, so the UI can say what was withheld. */
  redactions: RedactionSummary[];
  /** Total replacements, zero when nothing matched. */
  total: number;
};

/**
 * Replace anything that looks like a credential with a labelled marker.
 *
 * @param input - Raw command output, straight from the agent.
 * @returns The redacted text plus a per-kind tally. `total === 0` means no rule
 * matched, which is not the same as "contains no secret".
 */
export const redactSecrets = (input: string): RedactionResult => {
  if (!input) return { text: input, redactions: [], total: 0 };

  const counts = new Map<RedactionKind, number>();
  let text = input;

  for (const rule of RULES) {
    // Each rule carries the global flag; reset lastIndex so a rule reused
    // across calls cannot skip the start of the next input.
    rule.pattern.lastIndex = 0;
    text = text.replace(rule.pattern, (...args) => {
      const whole = args[0] as string;
      // A later, broader rule would otherwise overwrite the precise label an
      // earlier one produced (`aws-secret-access-key` becoming `env-secret`),
      // and a second pass over already-redacted text would keep rewriting it.
      // Nothing is lost by skipping: the secret is already gone.
      if (MARKER.test(whole)) return whole;
      counts.set(rule.kind, (counts.get(rule.kind) ?? 0) + 1);
      const groups = args.slice(1, -2) as string[];
      return rule.replace ? rule.replace(whole, ...groups) : mark(rule.kind);
    });
  }

  const redactions = [...counts.entries()].map(([kind, count]) => ({ kind, count }));
  return {
    text,
    redactions,
    total: redactions.reduce((sum, r) => sum + r.count, 0),
  };
};
