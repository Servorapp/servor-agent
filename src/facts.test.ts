import { describe, expect, test } from 'bun:test';
import {
  countEmptyPasswords,
  countNopasswd,
  findExtraRootAccounts,
  heavyFactsAreStale,
  invalidateHeavyFacts,
  parseCrontab,
  parseSshdConfig,
} from './facts';

describe('parseCrontab', () => {
  test('reads a per-user spool, where there is no user column', () => {
    const entries = parseCrontab('30 4 * * * /usr/local/bin/backup.sh', false, 'crontab:deploy');
    expect(entries).toEqual([
      {
        schedule: '30 4 * * *',
        command: '/usr/local/bin/backup.sh',
        user: undefined,
        source: 'crontab:deploy',
      },
    ]);
  });

  test('reads /etc/crontab, where the sixth field is the user', () => {
    // Getting this backwards would silently turn `root` into the command.
    const entries = parseCrontab(
      '17 * * * * root cd / && run-parts /etc/cron.hourly',
      true,
      '/etc/crontab',
    );
    expect(entries[0]?.user).toBe('root');
    expect(entries[0]?.command).toBe('cd / && run-parts /etc/cron.hourly');
  });

  test('keeps the @-shorthands cron actually accepts', () => {
    const entries = parseCrontab('@daily /opt/rotate.sh\n@reboot root /opt/boot.sh', false, 'x');
    expect(entries[0]?.schedule).toBe('@daily');
    expect(entries[1]?.schedule).toBe('@reboot');
  });

  test('skips comments, blanks and settings', () => {
    const content = [
      '# nightly backup',
      '',
      'MAILTO="ops@example.com"',
      'PATH=/usr/bin:/bin',
      'SHELL=/bin/sh',
    ].join('\n');
    expect(parseCrontab(content, false, 'x')).toEqual([]);
  });

  test('skips a line too short to be a schedule', () => {
    expect(parseCrontab('* * * *', false, 'x')).toEqual([]);
    expect(parseCrontab('30 4 * * * root', true, 'x')).toEqual([]);
  });

  test('redacts a secret sitting in a cron line', () => {
    // A cron line is one of the likelier places on a box to find a token.
    const entries = parseCrontab(
      '0 * * * * curl -H "Authorization: Bearer sk_live_abcdef1234567890" https://api.example.com',
      false,
      'x',
    );
    expect(entries[0]?.command).not.toContain('sk_live_abcdef1234567890');
    expect(entries[0]?.command).toContain('redacted');
  });

  test('records where each entry came from', () => {
    const entries = parseCrontab('@daily /opt/x.sh', false, '/etc/cron.d/backup');
    expect(entries[0]?.source).toBe('/etc/cron.d/backup');
  });
});

describe('when the heavy pass runs again', () => {
  const TTL = 15 * 60 * 1000;
  const NOW = 1_800_000_000_000;

  // The heavy pass shells out to docker, systemd, pm2 and a TLS probe. Driving
  // it through `getFacts` — which the first version of this test did — costs
  // tens of seconds on a real Linux box and does nothing at all elsewhere, so it
  // was both slow and blind. The rule is checked directly instead.
  test('a fresh cache is reused', () => {
    expect(heavyFactsAreStale(NOW - 1_000, NOW)).toBe(false);
  });

  test('a cache older than the TTL is re-collected', () => {
    expect(heavyFactsAreStale(NOW - TTL - 1, NOW)).toBe(true);
  });

  test('a cache exactly at the TTL is still good', () => {
    expect(heavyFactsAreStale(NOW - TTL, NOW)).toBe(false);
  });

  // This is what makes "Update everything" show an empty list afterwards: the
  // agent used to serve a quarter-hour-old inventory, so a machine that had just
  // been fully updated still displayed its old queue of packages.
  test('an invalidated cache is stale whatever the clock says', () => {
    expect(heavyFactsAreStale(0, NOW)).toBe(true);
    expect(heavyFactsAreStale(0, 0)).toBe(true);
  });

  test('invalidating is safe before anything was ever collected', () => {
    expect(() => invalidateHeavyFacts()).not.toThrow();
  });

  test('invalidating twice is safe', () => {
    invalidateHeavyFacts();
    expect(() => invalidateHeavyFacts()).not.toThrow();
  });
});

describe('security audit inputs', () => {
  test('reads the effective sshd settings', () => {
    const ssh = parseSshdConfig(
      [
        'port 22',
        'permitrootlogin without-password',
        'passwordauthentication no',
        'permitemptypasswords no',
        'maxauthtries 6',
        'x11forwarding yes',
      ].join('\n'),
    );
    // Older OpenSSH spelling, normalised so the audit has one value to read.
    expect(ssh).toEqual({
      permitRootLogin: 'prohibit-password',
      passwordAuthentication: false,
      permitEmptyPasswords: false,
      maxAuthTries: 6,
      x11Forwarding: true,
    });
  });

  test('no sshd output means no ssh facts, not defaults', () => {
    expect(parseSshdConfig('')).toBeUndefined();
  });

  test('counts NOPASSWD rules, not comments or Defaults', () => {
    const sudoers = [
      '# ubuntu ALL=(ALL) NOPASSWD:ALL',
      'Defaults env_reset',
      '%sudo ALL=(ALL:ALL) ALL',
      'ubuntu ALL=(ALL) NOPASSWD:ALL',
      'deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app',
    ].join('\n');
    expect(countNopasswd(sudoers)).toBe(2);
  });

  test('an empty hash is a passwordless account, a locked one is not', () => {
    const shadow = [
      'root:$6$abc:19000::::::',
      'daemon:*:19000::::::',
      'svc:!:19000::::::',
      'guest::19000::::::',
    ].join('\n');
    expect(countEmptyPasswords(shadow)).toBe(1);
  });

  test('finds uid 0 under another name', () => {
    const passwd = [
      'root:x:0:0:root:/root:/bin/bash',
      'toor:x:0:0::/root:/bin/sh',
      'deploy:x:1000:1000::/home/deploy:/bin/bash',
    ].join('\n');
    expect(findExtraRootAccounts(passwd)).toEqual(['toor']);
  });
});
