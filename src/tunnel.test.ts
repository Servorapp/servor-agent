import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { createHmac } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519';
import type { AgentConfig } from './config';
import { canonicalAgentMessage } from './protocol/agent-hmac';
import { type ExecGrant, execPublicKeyFromVault, signExecGrant } from './protocol/exec-sign';
import { setExecPolicy, startTunnel } from './tunnel';

const SERVER_ID = '019ecd37-5979-72ce-8960-fc9454880973';
const SECRET = 'per-server-enrollment-secret';
const API = 'https://api.servor.test';
const GRACE_MS = 10 * 60 * 1000;
const OFFLINE_BUF_MAX = 256_000;

const config = (over: Partial<AgentConfig> = {}): AgentConfig => ({
  serverId: SERVER_ID,
  secret: SECRET,
  apiUrl: API,
  intervalSeconds: 60,
  mode: 'tunnel',
  version: '1',
  ...over,
});

const encoder = new TextEncoder();
/** Yield to the real event loop while `setTimeout` is stubbed out. */
const realSetTimeout = globalThis.setTimeout;
const tick = () => new Promise<void>((resolve) => realSetTimeout(resolve, 1));

/** A spawned process the test drives by hand: what it prints, and when it ends. */
const fakeProc = () => {
  let outCtl: ReadableStreamDefaultController<Uint8Array> | null = null;
  let errCtl: ReadableStreamDefaultController<Uint8Array> | null = null;
  const stdout = new ReadableStream<Uint8Array>({
    start: (c) => {
      outCtl = c;
    },
  });
  const stderr = new ReadableStream<Uint8Array>({
    start: (c) => {
      errCtl = c;
    },
  });
  let settle: (code: number) => void = () => {};
  const exited = new Promise<number>((resolve) => {
    settle = resolve;
  });
  const writes: string[] = [];
  let closed = false;
  let kills = 0;

  return {
    stdin: {
      write: (data: string) => {
        writes.push(data);
      },
      flush: () => {},
    },
    stdout,
    stderr,
    exited,
    kill: () => {
      kills++;
    },
    writes,
    kills: () => kills,
    out: (data: string) => outCtl?.enqueue(encoder.encode(data)),
    err: (data: string) => errCtl?.enqueue(encoder.encode(data)),
    end: (code = 0) => {
      if (!closed) {
        closed = true;
        outCtl?.close();
        errCtl?.close();
      }
      settle(code);
    },
  };
};

type FakeProc = ReturnType<typeof fakeProc>;

/** The control plane's end of the socket, driven by the test. */
class FakeSocket {
  readyState = 0;
  readonly sent: Record<string, unknown>[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(readonly url: string) {
    sockets.push(this);
  }

  send(raw: string) {
    this.sent.push(JSON.parse(raw) as Record<string, unknown>);
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.();
  }

  accept() {
    this.readyState = 1;
    this.onopen?.();
  }

  deliver(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }

  raw(data: string) {
    this.onmessage?.({ data });
  }

  of(type: string) {
    return this.sent.filter((m) => m.type === type);
  }
}

let sockets: FakeSocket[] = [];
let scheduled: { fn: () => void; ms: number }[] = [];
let spawns: string[][] = [];
let procs: FakeProc[] = [];
let spawnThrows = false;
let restoreTimers = () => {};

const spawn = ((argv: string[]) => {
  spawns.push(argv);
  if (spawnThrows) throw new Error('spawn refused');
  const proc = fakeProc();
  procs.push(proc);
  return proc;
}) as unknown as typeof Bun.spawn;

const vaultKey = x25519.utils.randomPrivateKey();
const PUBKEY = Buffer.from(execPublicKeyFromVault(vaultKey)).toString('base64');
const otherKey = x25519.utils.randomPrivateKey();

let nonceCounter = 0;

/** A tunnel message carrying a real grant signed by `key`. */
const signed = (
  kind: 'exec' | 'shell',
  command: string,
  extra: Record<string, unknown> = {},
  key: Uint8Array = vaultKey,
): Record<string, unknown> => {
  const grant: ExecGrant = {
    serverId: SERVER_ID,
    kind,
    command,
    nonce: `nonce-${++nonceCounter}`,
    ts: String(Math.floor(Date.now() / 1000)),
  };
  return {
    type: kind === 'exec' ? 'exec' : 'shell.open',
    id: 'req-1',
    command,
    nonce: grant.nonce,
    ts: grant.ts,
    sig: Buffer.from(signExecGrant(key, grant)).toString('base64'),
    ...extra,
  };
};

/** Start a tunnel against the fake socket and hand back the live connection. */
const open = (keys: string[] = [PUBKEY], over: Partial<AgentConfig> = {}) => {
  setExecPolicy(keys);
  const tunnel = startTunnel(config(over), {
    WebSocket: FakeSocket as unknown as typeof WebSocket,
    spawn,
  });
  const socket = () => {
    const live = sockets[sockets.length - 1];
    if (!live) throw new Error('the tunnel opened no socket');
    return live;
  };
  return { tunnel, socket };
};

/** Bring a fresh tunnel all the way up: handshake sent, handshake accepted. */
const online = (keys: string[] = [PUBKEY], over: Partial<AgentConfig> = {}) => {
  const conn = open(keys, over);
  conn.socket().accept();
  conn.socket().deliver({ type: 'init.ok' });
  return conn;
};

/** Run the last timer the tunnel scheduled, as the event loop eventually would. */
const fire = (ms?: number) => {
  const timer =
    ms === undefined ? scheduled[scheduled.length - 1] : scheduled.filter((s) => s.ms === ms).pop();
  timer?.fn();
  return timer;
};

beforeEach(() => {
  sockets = [];
  scheduled = [];
  spawns = [];
  procs = [];
  spawnThrows = false;
  const spy = spyOn(globalThis, 'setTimeout');
  spy.mockImplementation(((fn: () => void, ms?: number) => {
    scheduled.push({ fn, ms: ms ?? 0 });
    return scheduled.length as unknown as ReturnType<typeof setTimeout>;
  }) as unknown as typeof globalThis.setTimeout);
  restoreTimers = () => spy.mockRestore();
});

afterEach(() => {
  restoreTimers();
  setExecPolicy([]);
});

describe('handshake', () => {
  test('the socket is dialled outbound over wss at this server id', () => {
    const { socket } = open();
    expect(socket().url).toBe(`wss://api.servor.test/agent/tunnel/${SERVER_ID}`);
  });

  test('the first message proves which agent is speaking, by HMAC over its own id', () => {
    const { socket } = open();
    socket().accept();
    const init = socket().sent[0] ?? {};
    expect(init.type).toBe('init');
    const expected = createHmac('sha256', SECRET)
      .update(
        canonicalAgentMessage({
          kind: 'tunnel',
          serverId: SERVER_ID,
          timestamp: String(init.ts),
          body: `tunnel:${SERVER_ID}`,
        }),
      )
      .digest('hex');
    expect(init.sig).toBe(expected);
  });

  test('nothing is sent before the socket is open', () => {
    const { socket } = open();
    expect(socket().sent).toEqual([]);
  });

  test('a rejected handshake is reported and leaves the agent offline', () => {
    const { socket } = open();
    socket().accept();
    socket().deliver({ type: 'init.error' });
    expect(socket().of('resume')).toEqual([]);
  });

  test('the refusal names its reason, and says it once', () => {
    // A tunnel that cannot authenticate retries for ever. Printing the same
    // sentence on every attempt fills the journal with nothing — and on a small
    // server the journal is disk someone is paying for.
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { socket } = open();
      socket().accept();
      socket().deliver({ type: 'init.error', reason: 'clock_skew' });
      socket().deliver({ type: 'init.error', reason: 'clock_skew' });
      socket().deliver({ type: 'init.error', reason: 'clock_skew' });

      const said = errors.mock.calls.map((c) => String(c[0]));
      expect(said.filter((line) => line.includes('clock_skew'))).toHaveLength(1);

      // A different reason is news, and is printed.
      socket().deliver({ type: 'init.error', reason: 'unknown_agent' });
      expect(
        errors.mock.calls.map((c) => String(c[0])).filter((l) => l.includes('unknown_agent')),
      ).toHaveLength(1);
    } finally {
      errors.mockRestore();
    }
  });
});

describe('exec authorization', () => {
  test('a command with no grant answers 126 and spawns nothing', () => {
    const { socket } = online();
    socket().deliver({ type: 'exec', id: 'req-1', command: 'whoami' });

    const result = socket().of('exec.result')[0] ?? {};
    expect(result.exitCode).toBe(126);
    expect(result.stderr).toBe('unauthorized: valid exec signature required');
    expect(spawns).toEqual([]);
  });

  test('a command signed by an unauthorized key answers 126 and spawns nothing', () => {
    const { socket } = online();
    socket().deliver(signed('exec', 'rm -rf /', {}, otherKey));

    expect(socket().of('exec.result')[0]?.exitCode).toBe(126);
    expect(spawns).toEqual([]);
  });

  test('a replayed grant answers 126 and spawns nothing the second time', async () => {
    const { socket } = online();
    const msg = signed('exec', 'uptime');
    socket().deliver(msg);
    procs[0]?.end(0);
    await tick();
    socket().deliver(msg);

    expect(
      socket()
        .of('exec.result')
        .map((r) => r.exitCode),
    ).toEqual([0, 126]);
    expect(spawns).toHaveLength(1);
  });

  test('an agent with no authorized key runs nothing at all', () => {
    const { socket } = online([]);
    socket().deliver(signed('exec', 'uptime'));

    expect(socket().of('exec.result')[0]?.exitCode).toBe(126);
    expect(spawns).toEqual([]);
  });
});

describe('exec execution', () => {
  test('an authorized command runs and reports stdout, stderr and exit code', async () => {
    const { socket } = online();
    socket().deliver(signed('exec', 'systemctl status nginx'));

    const proc = procs[0];
    proc?.out('active (running)\n');
    proc?.err('warning: deprecated flag\n');
    proc?.end(3);
    await tick();

    const result = socket().of('exec.result')[0] ?? {};
    expect(result.exitCode).toBe(3);
    expect(result.stdout).toBe('active (running)\n');
    expect(result.stderr).toBe('warning: deprecated flag\n');
    expect(typeof result.durationMs).toBe('number');
  });

  test('the command reaches the shell exactly as it was signed', () => {
    const command = 'echo "$HOME" && systemctl restart nginx';
    const { socket } = online();
    socket().deliver(signed('exec', command));

    expect(spawns[0]).toContain(command);
  });

  test('a one-shot command runs under a shell with an explicit forced PATH (posix)', () => {
    if (process.platform === 'win32') return; // powershell path does not force PATH
    const { socket } = online();
    socket().deliver(signed('exec', 'node -v'));

    const argv = spawns[0] ?? [];
    expect(argv).toContain('bash');
    expect(argv).toContain('-c');
    // PATH is forced via a leading `env PATH=…`, and it must include the sbin dirs
    // a stripped login shell drops.
    const pathArg = argv.find((a) => a.startsWith('PATH='));
    expect(pathArg).toBeDefined();
    expect(pathArg).toContain('/usr/sbin');
    // the signed command is still the final argument, untouched
    expect(argv[argv.length - 1]).toBe('node -v');
  });

  test('a spawn that throws is answered rather than left hanging', () => {
    spawnThrows = true;
    const { socket } = online();
    socket().deliver(signed('exec', 'uptime'));

    const result = socket().of('exec.result')[0] ?? {};
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe('spawn refused');
  });

  test('a request carries its own deadline, capped at ten minutes', () => {
    const { socket } = online();
    socket().deliver(signed('exec', 'sleep 3600', { timeoutMs: 3_600_000 }));

    // The 25s heartbeat and 60s stability timers are scheduled at handshake; this
    // asserts the exec's own deadline, not those.
    expect(scheduled.map((s) => s.ms).filter((ms) => ms !== 25_000 && ms !== 60_000)).toEqual([
      600_000,
    ]);
  });

  test('a request with no deadline gets the five minute default', () => {
    const { socket } = online();
    socket().deliver(signed('exec', 'uptime'));

    expect(scheduled.map((s) => s.ms).filter((ms) => ms !== 25_000 && ms !== 60_000)).toEqual([
      300_000,
    ]);
  });

  test('a command that outlives its deadline is killed', () => {
    const { socket } = online();
    socket().deliver(signed('exec', 'sleep 3600'));
    fire(300_000);

    expect(procs[0]?.kills()).toBe(1);
  });
});

describe('interactive sessions', () => {
  test('opening a session with no grant answers a 126 exit and spawns nothing', () => {
    const { socket } = online();
    socket().deliver({ type: 'shell.open', id: 'sh-1', command: 'bash -l' });

    expect(socket().of('shell.exit')[0]).toEqual({ type: 'shell.exit', id: 'sh-1', code: 126 });
    expect(spawns).toEqual([]);
  });

  test('a refused session explains itself in the terminal before it exits', () => {
    // The whole point: a silent 126 shows the user only "session ended" and
    // hides a signing/key problem behind what looks like a dead tunnel.
    const { socket } = online();
    socket().deliver({ type: 'shell.open', id: 'sh-1', command: 'bash -l' });

    const data = socket().of('shell.data')[0];
    expect(String(data?.data)).toContain('Exec refused');
    expect(spawns).toEqual([]);
  });

  test('an exec grant cannot be reused to open a session', () => {
    const { socket } = online();
    socket().deliver({ ...signed('exec', 'bash -l'), type: 'shell.open', id: 'sh-1' });

    expect(socket().of('shell.exit')[0]?.code).toBe(126);
    expect(spawns).toEqual([]);
  });

  test('a PTY session forces the same PATH as a one-shot command (posix)', () => {
    if (process.platform === 'win32') return; // powershell path does not force PATH
    if (process.platform === 'darwin') return; // its branch runs a login bash instead
    // `script -c` hands its argument to /bin/sh, which sources no profile. Without
    // a forced PATH a per-user tool died on `sh: 1: pm2: not found` while the very
    // same command succeeded as a one-shot exec.
    const { socket } = online();
    socket().deliver(signed('shell', 'pm2 logs web --lines 20 --raw', { id: 'sh-1' }));

    const argv = spawns[0] ?? [];
    const pathArg = argv.find((a) => a.startsWith('PATH='));
    expect(pathArg).toBeDefined();
    expect(argv).toContain('script');
    // The signed string still reaches the shell untouched.
    expect(argv).toContain('pm2 logs web --lines 20 --raw');
  });

  test('an authorized session starts and streams its output', async () => {
    const { socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    expect(spawns[0]).toContain('bash -l');

    procs[0]?.out('root@host:~# ');
    await tick();
    expect(socket().of('shell.data')[0]).toEqual({
      type: 'shell.data',
      id: 'sh-1',
      data: 'root@host:~# ',
    });
  });

  test('keystrokes are written to the session that was authorized', () => {
    const { socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    socket().deliver({ type: 'shell.input', id: 'sh-1', data: 'ls -la\n' });

    expect(procs[0]?.writes).toEqual(['ls -la\n']);
  });

  test('an interrupt is delivered as the control character', () => {
    const { socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    socket().deliver({ type: 'shell.signal', id: 'sh-1' });

    expect(procs[0]?.writes).toEqual(['\x03']);
  });

  test('input for an unknown session is dropped', () => {
    const { socket } = online();
    socket().deliver({ type: 'shell.input', id: 'never-opened', data: 'ls\n' });
    socket().deliver({ type: 'shell.signal', id: 'never-opened' });
    socket().deliver({ type: 'shell.close', id: 'never-opened' });

    expect(procs).toEqual([]);
  });

  test('closing a session kills the process and forgets it', () => {
    const { tunnel, socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    expect(tunnel.isBusy()).toBe(true);

    socket().deliver({ type: 'shell.close', id: 'sh-1' });
    expect(procs[0]?.kills()).toBe(1);
    expect(tunnel.isBusy()).toBe(false);
  });

  test('a session that ends on its own reports its exit code', async () => {
    const { tunnel, socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    procs[0]?.end(130);
    await tick();

    expect(socket().of('shell.exit')[0]).toEqual({ type: 'shell.exit', id: 'sh-1', code: 130 });
    expect(tunnel.isBusy()).toBe(false);
  });

  test('a session that cannot be spawned answers an exit rather than hanging', () => {
    spawnThrows = true;
    const { socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));

    expect(socket().of('shell.exit')[0]?.code).toBe(1);
  });
});

describe('message dispatch', () => {
  test('an unknown message type is ignored', () => {
    const { socket } = online();
    const before = socket().sent.length;
    socket().deliver({ type: 'shutdown-everything', id: 'x' });

    expect(socket().sent).toHaveLength(before);
    expect(spawns).toEqual([]);
  });

  test('a frame that is not JSON is ignored', () => {
    const { socket } = online();
    const before = socket().sent.length;
    socket().raw('<html>proxy error</html>');

    expect(socket().sent).toHaveLength(before);
    expect(spawns).toEqual([]);
  });

  test('a frame that parses to null is ignored', () => {
    const { socket } = online();
    const before = socket().sent.length;
    socket().raw('null');

    expect(socket().sent).toHaveLength(before);
  });
});

describe('busy state', () => {
  test('a fresh tunnel is idle', () => {
    const { tunnel } = online();
    expect(tunnel.isBusy()).toBe(false);
  });

  test('a running command makes the agent busy until it finishes', async () => {
    const { tunnel, socket } = online();
    socket().deliver(signed('exec', 'apt upgrade -y'));
    expect(tunnel.isBusy()).toBe(true);

    procs[0]?.end(0);
    await tick();
    expect(tunnel.isBusy()).toBe(false);
  });

  test('an open session makes the agent busy', () => {
    const { tunnel, socket } = online();
    socket().deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    expect(tunnel.isBusy()).toBe(true);
  });
});

describe('outage buffering', () => {
  test('output produced while offline is flushed once the tunnel is back', async () => {
    const { socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    live.close();

    procs[0]?.out('still working\n');
    await tick();
    expect(live.of('shell.data')).toEqual([]);

    fire();
    const next = socket();
    next.accept();
    next.deliver({ type: 'init.ok' });

    expect(next.of('shell.data')).toEqual([
      { type: 'shell.data', id: 'sh-1', data: 'still working\n' },
    ]);
  });

  test('the offline buffer is bounded and sacrifices the oldest output first', async () => {
    const { socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    live.close();

    const chunk = (n: number) => `chunk-${n}`.padEnd(OFFLINE_BUF_MAX / 2, '.');
    for (const n of [1, 2, 3, 4]) {
      procs[0]?.out(chunk(n));
      await tick();
    }

    fire();
    const next = socket();
    next.accept();
    next.deliver({ type: 'init.ok' });

    const flushed = next.of('shell.data').map((m) => String(m.data));
    expect(flushed).toEqual([chunk(3), chunk(4)]);
  });

  test('output buffered for a session that is closed goes away with it', async () => {
    const { socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    live.close();

    procs[0]?.out('lost\n');
    await tick();
    live.deliver({ type: 'shell.close', id: 'sh-1' });

    fire();
    const next = socket();
    next.accept();
    next.deliver({ type: 'init.ok' });

    expect(next.of('resume')).toEqual([]);
    expect(next.of('shell.data')).toEqual([]);
  });

  test('still-running sessions are re-advertised on the new connection', () => {
    const { socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    live.deliver(signed('shell', 'apt upgrade -y', { id: 'sh-2', persistent: true }));
    live.close();

    fire();
    const next = socket();
    next.accept();
    next.deliver({ type: 'init.ok' });

    expect(next.of('resume')[0]?.shells).toEqual([
      { id: 'sh-1', persistent: false },
      { id: 'sh-2', persistent: true },
    ]);
  });
});

describe('reconnection', () => {
  test('the delay doubles on every failed attempt, up to ten seconds', () => {
    // Ten, not sixty. This is the channel every command travels down, and a
    // minute-long gap left a freshly installed agent unreachable long after
    // whatever refused it had cleared — usually a clock that had since synced.
    const { socket } = open();
    const delays: number[] = [];
    for (let i = 0; i < 8; i++) {
      socket().close();
      delays.push(scheduled[scheduled.length - 1]?.ms ?? 0);
      fire();
    }
    expect(delays).toEqual([1000, 2000, 4000, 8000, 10000, 10000, 10000, 10000]);
  });

  test('a successful handshake resets the delay', () => {
    const { socket } = open();
    socket().close();
    fire();
    socket().close();
    fire();
    expect(scheduled[scheduled.length - 1]?.ms).toBe(2000);

    socket().accept();
    socket().deliver({ type: 'init.ok' });
    socket().close();
    expect(scheduled[scheduled.length - 1]?.ms).toBe(1000);
  });

  test('a socket error closes the socket, which is what triggers the retry', () => {
    const { socket } = open();
    const live = socket();
    live.onerror?.();
    expect(live.readyState).toBe(3);
    expect(scheduled[scheduled.length - 1]?.ms).toBe(1000);
  });
});

describe('flap breaker', () => {
  // A connection that authenticates then dies young is a flap — the signature of
  // two agents sharing one server id, evicting each other on the control plane.
  const flapOnce = (socket: () => FakeSocket) => {
    socket().accept();
    socket().deliver({ type: 'init.ok' });
    socket().close();
  };

  test('a run of flaps stretches the reconnect to a long cooldown', () => {
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { socket } = open();
      let last = 0;
      for (let i = 0; i < 5; i++) {
        flapOnce(socket);
        last = scheduled[scheduled.length - 1]?.ms ?? 0;
        fire();
      }
      // Under the soft limit the fast backoff still applies; at it, the cooldown.
      expect(last).toBe(5 * 60_000);
    } finally {
      errors.mockRestore();
    }
  });

  test('past the hard limit it pauses for half an hour instead of for ever', () => {
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { socket } = open();
      let last = 0;
      for (let i = 0; i < 20; i++) {
        flapOnce(socket);
        last = scheduled[scheduled.length - 1]?.ms ?? 0;
        fire();
      }
      // Giving up for ever turned a duplicate-agent guard into a permanent
      // outage with no way back but a human: the 20th close now arms one long
      // retry rather than nothing at all.
      expect(last).toBe(30 * 60_000);
      expect(errors.mock.calls.some((c) => String(c[0]).includes('pausing reconnects'))).toBe(true);
    } finally {
      errors.mockRestore();
    }
  });

  test('the pause starts from a clean counter, so one more flap does not re-trip it', () => {
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { socket } = open();
      for (let i = 0; i < 20; i++) {
        flapOnce(socket);
        fire();
      }
      flapOnce(socket);
      // Back to the fast backoff: the half-hour pause bought a fresh start, it
      // did not leave the breaker latched.
      expect(scheduled[scheduled.length - 1]?.ms).toBe(1000);
    } finally {
      errors.mockRestore();
    }
  });

  test('a connection that proves stable clears the flap counter', () => {
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { socket } = open();
      for (let i = 0; i < 4; i++) {
        flapOnce(socket);
        fire();
      }
      // Reconnect, authenticate, and stay up long enough to be judged healthy.
      socket().accept();
      socket().deliver({ type: 'init.ok' });
      fire(60_000); // the stable timer resets the counter
      socket().close();
      // Back to the ordinary fast backoff, not the cooldown.
      expect(scheduled[scheduled.length - 1]?.ms).toBe(1000);
    } finally {
      errors.mockRestore();
    }
  });
});

describe('outage grace window', () => {
  test('an interactive session is reaped once the outage outlives the window', () => {
    const { tunnel, socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    live.close();

    expect(tunnel.isBusy()).toBe(true);
    fire(GRACE_MS);

    expect(procs[0]?.kills()).toBe(1);
    expect(tunnel.isBusy()).toBe(false);
  });

  test('a form-launched command keeps running through the whole outage', () => {
    const { tunnel, socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'apt upgrade -y', { id: 'sh-1', persistent: true }));
    live.close();

    fire(GRACE_MS);

    expect(procs[0]?.kills()).toBe(0);
    expect(tunnel.isBusy()).toBe(true);
  });

  test('no reaping is scheduled when there is no session to lose', () => {
    const { socket } = online();
    socket().close();

    expect(scheduled.filter((s) => s.ms === GRACE_MS)).toEqual([]);
  });

  test('reconnecting inside the window keeps the session alive', () => {
    const { tunnel, socket } = online();
    const live = socket();
    live.deliver(signed('shell', 'bash -l', { id: 'sh-1' }));
    live.close();

    fire(1000);
    const next = socket();
    next.accept();
    next.deliver({ type: 'init.ok' });

    expect(procs[0]?.kills()).toBe(0);
    expect(tunnel.isBusy()).toBe(true);
  });
});

describe('heartbeat keeps the tunnel from silently dying', () => {
  test('once up, it pings on each heartbeat tick', () => {
    const { socket } = online();
    fire(25_000);
    expect(socket().of('ping')).toHaveLength(1);
  });

  test('a pong resets the deadline — the tunnel stays open', () => {
    const { socket } = online();
    fire(25_000);
    socket().deliver({ type: 'pong' });
    fire(25_000);
    expect(socket().of('ping')).toHaveLength(2);
    expect(socket().readyState).not.toBe(3);
  });

  test('no pong past the deadline tears the socket down so onclose reconnects', () => {
    const now = spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000_000);
      const { socket } = online(); // lastPong stamped at 1_000_000
      now.mockReturnValue(1_000_000 + 61_000); // past the 60s deadline
      fire(25_000);
      expect(socket().readyState).toBe(3); // closed → onclose schedules reconnect
    } finally {
      now.mockRestore();
    }
  });

  test('a close that never completes still reconnects', () => {
    // The incident this guards: on a half-open socket — peer gone, no FIN
    // coming — `close()` has nothing to complete against and `onclose` may never
    // fire. The heartbeat used to log, stop its own chain and return, leaving
    // the tunnel with `online` true, no timer pending and no reconnect armed:
    // dead, convinced it was alive, until someone restarted the service.
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    const now = spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000_000);
      const { socket } = online();
      const live = socket();
      live.close = () => {
        live.readyState = 2; // CLOSING, and it stays there: no close event
      };
      const before = sockets.length;

      now.mockReturnValue(1_000_000 + 61_000);
      fire(25_000);
      fire(); // the reconnect the teardown armed

      expect(sockets.length).toBe(before + 1);
    } finally {
      now.mockRestore();
      errors.mockRestore();
    }
  });

  test('a close from the socket we gave up on does not tear down its replacement', () => {
    // The close event can land long after the heartbeat declared the socket
    // dead and a fresh one came up. Unstamped, that teardown would fire against
    // the healthy connection — turning one outage into a loop of them.
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    const now = spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000_000);
      const { socket } = online();
      const stale = socket();
      let staleClose: (() => void) | null = null;
      stale.close = () => {
        stale.readyState = 3;
        staleClose = stale.onclose;
      };

      now.mockReturnValue(1_000_000 + 61_000);
      fire(25_000); // heartbeat gives up on `stale`
      fire(); // reconnect: a new socket is dialled
      const fresh = socket();
      fresh.accept();
      fresh.deliver({ type: 'init.ok' });
      const armed = scheduled.length;

      (staleClose as unknown as () => void)?.(); // the old close finally lands

      expect(fresh.readyState).toBe(1); // still open
      expect(scheduled.length).toBe(armed); // and nothing new armed
    } finally {
      now.mockRestore();
      errors.mockRestore();
    }
  });

  test('a late close event does not arm a second reconnect', () => {
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    const now = spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000_000);
      const { socket } = online();
      const live = socket();
      let closeEvent: (() => void) | null = null;
      live.close = () => {
        live.readyState = 3;
        closeEvent = live.onclose; // held back, delivered by hand below
      };

      now.mockReturnValue(1_000_000 + 61_000);
      fire(25_000);
      const armed = scheduled.length;
      (closeEvent as unknown as () => void)?.(); // the close finally lands

      expect(scheduled.length).toBe(armed);
    } finally {
      now.mockRestore();
      errors.mockRestore();
    }
  });
});

describe('an outage nobody can see is the one nobody can fix', () => {
  test('a connection that never authenticates is reported, not swallowed', () => {
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { socket } = open();
      socket().close(); // refused before the handshake: the silent case
      expect(errors.mock.calls.some((c) => String(c[0]).includes('tunnel down for'))).toBe(true);
    } finally {
      errors.mockRestore();
    }
  });

  test('the control plane reporting no tunnel dials one even when none is open', () => {
    // The HTTP config poll is the only channel still working in this state, and
    // returning early here is what left a dead tunnel dead.
    const errors = spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const { tunnel, socket } = open();
      socket().close();
      fire(); // consume the armed retry: a socket is dialling, nothing is queued
      const before = sockets.length;

      tunnel.reconnectNow();

      expect(sockets.length).toBe(before + 1);
      expect(errors.mock.calls.some((c) => String(c[0]).includes('dialling now'))).toBe(true);
    } finally {
      errors.mockRestore();
    }
  });
});
