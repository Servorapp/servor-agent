// Vendored from packages/shared/src/constants/agent.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

export const AGENT_VERSION = '1';
// Compiled agent binary version — keep in sync with apps/agent/src/index.ts BUILD_VERSION.
export const AGENT_BUILD_VERSION = '1.0.3';

export const AGENT_INTERVAL_MIN_SECONDS = 15;
export const AGENT_INTERVAL_MAX_SECONDS = 300;
export const AGENT_INTERVAL_DEFAULT_SECONDS = 60;

// How often the agent re-fetches its config (check list) — kept short so new
// monitors start being evaluated quickly.
export const AGENT_CONFIG_INTERVAL_SECONDS = 30;

// Anti-replay window for signed ingestion requests.
export const AGENT_SIGNATURE_SKEW_SECONDS = 300;

// Heartbeat misses before an agent is considered offline (× interval).
export const AGENT_OFFLINE_MISS_FACTOR = 3;

// Retention.
export const AGENT_METRICS_RAW_RETENTION_DAYS = 7;
export const AGENT_METRICS_HOURLY_RETENTION_DAYS = 90;

export const AGENT_DEFAULT_THRESHOLDS = {
  cpuPct: 90,
  ramPct: 90,
  diskPct: 90,
  sustainedSamples: 3,
  // Points below the limit a metric must reach before its breach can clear. A
  // metric parked on its threshold would otherwise re-alert on every dip.
  recoveryMarginPct: 5,
} as const;

// After a command that changed what the host facts describe, the agent pushes a
// fresh sample instead of waiting out its interval. The short delay lets the
// machine settle — `docker restart` returns before the container is up again —
// and coalesces a burst of actions into one push.
export const AGENT_FACTS_PUSH_DELAY_MS = 1_500;

// When the dashboard refetches the server after such an action. Spread rather
// than a single shot: the push has to land and be written before a refetch can
// see it, and a slow machine pushes late.
export const AGENT_FACTS_REFETCH_STEPS_MS = [2_500, 5_000, 9_000] as const;

export const AGENT_SIGNATURE_HEADER = 'x-servor-signature';
export const AGENT_TIMESTAMP_HEADER = 'x-servor-timestamp';

// A healthy agent picks up a new release on its next config poll, about thirty
// seconds after the API ships it, and restarts as soon as it is idle. Still
// behind after this long, it is not coming by itself: the dashboard says so and
// offers to push the update.
export const AGENT_UPDATE_STALL_MINUTES = 30;

// Past this, the team admins get one email listing every stuck agent.
export const AGENT_UPDATE_EMAIL_AFTER_HOURS = 24;

// Ed25519 key (base64 SPKI/DER) that verifies released agent binaries — the
// same key compiled into the agent as UPDATE_PUBKEY (apps/agent/src/pubkey.ts;
// a test there keeps the two equal). The browser checks a build against it
// before signing a command that installs it, so that command installs only
// what the agent's own updater would have accepted.
export const AGENT_UPDATE_PUBKEY = 'MCowBQYDK2VwAyEAMk9aHGN/6q08ivnExsZSRGWOJ2ZRTbePkRGqwka9mFw=';
