#!/usr/bin/env python3
"""Private, endpoint-only journals. Never render or reload a tunnel."""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

CONFIG = Path('/usr/local/etc/gonf-endpoint.json')


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.endpoint-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            if path.exists():
                require(not path.is_symlink(), 'symlink replacement refused')
                original = path.stat()
                os.fchown(stream.fileno(), original.st_uid, original.st_gid)
                # Preserve SELinux labels and other existing extended attributes.
                if hasattr(os, 'listxattr'):
                    for name in os.listxattr(path):
                        os.setxattr(temporary, name, os.getxattr(path, name))
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        with directory_fd(path.parent) as parent:
            os.fsync(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def directory_fd(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        yield fd
    finally:
        os.close(fd)


def write_json(path, value):
    atomic(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def private(path, directory=False):
    info = Path(path).lstat()
    require(not Path(path).is_symlink(), 'symlink state refused')
    require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
            'state must be private and owned by current user')
    require(Path(path).is_dir() if directory else Path(path).is_file(),
            'unexpected state file type')


def load_json(path):
    private(path)
    return json.loads(Path(path).read_bytes())


def scope_digest(scope):
    return digest(json.dumps({k: scope[k] for k in
        ('id', 'old', 'new', 'peer', 'source_sha256')}, sort_keys=True).encode())


def endpoint(value):
    address, port = value.rsplit(':', 1)
    require(ipaddress.ip_address(address).version == 4 and port == '56709',
            'only IPv4 UDP56709 endpoints supported')
    return address


def validate_scope(scope):
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', scope['id']), 'invalid transaction ID')
    old, new = endpoint(scope['old']), endpoint(scope['new'])
    require(old.startswith('192.168.1.') and new == '10.20.0.' + old.rsplit('.', 1)[1],
            'endpoint substitution outside approved migration')
    require(int(old.rsplit('.', 1)[1]) in (120, 121, 122, 123, 125, 126, 130, 131, 132, 133),
            'destination outside approved migration')
    require(re.fullmatch(r'[A-Za-z0-9+/]{43}=', scope['peer']), 'invalid public identity')
    require(re.fullmatch(r'[a-f0-9]{64}', scope['source_sha256']), 'missing source receipt')


def parse(data):
    """Fail closed on unknown structure, duplicates, and opaque script directives."""
    sections = []
    current = None
    for line in data.decode().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        if line in ('[Interface]', '[Peer]'):
            current = {'section': line, 'values': {}}
            sections.append(current)
            continue
        require(current is not None and '=' in line, 'unrecognized configuration syntax')
        name, value = map(str.strip, line.split('=', 1))
        allowed = ('PrivateKey', 'ListenPort', 'FwMark', 'Address', 'DNS') if current['section'] == '[Interface]' else (
            'PublicKey', 'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive')
        require(name in allowed, 'unsupported configuration directive')
        if name in current['values']:
            require(name in ('Address', 'DNS', 'AllowedIPs'), 'duplicate configuration directive')
            current['values'][name] += ',' + value
        else:
            current['values'][name] = value
    require(sections and sections[0]['section'] == '[Interface]' and
            all(s['section'] == '[Peer]' for s in sections[1:]), 'invalid section structure')
    peers = {}
    for section in sections[1:]:
        values = section['values']
        key = values.get('PublicKey')
        require(key and key not in peers, 'missing or duplicate peer identity')
        peers[key] = values
    return sections[0]['values'], peers


def normalized(values):
    result = dict(values)
    if 'AllowedIPs' in result:
        result['AllowedIPs'] = ','.join(sorted(str(ipaddress.ip_network(x.strip(), strict=False))
                                               for x in result['AllowedIPs'].split(',')))
    if result.get('PersistentKeepalive', '0') in ('0', 'off'):
        result.pop('PersistentKeepalive', None)
    return result


def compare(before, after, peer, old, new):
    interface, peers = parse(before)
    next_interface, next_peers = parse(after)
    require(interface == next_interface and peers.keys() == next_peers.keys(),
            'interface or peer-set drift refused')
    require(peer in peers and peers[peer].get('Endpoint') == old, 'selected old endpoint absent')
    expected = copy.deepcopy(peers)
    expected[peer]['Endpoint'] = new
    require({k: normalized(v) for k, v in expected.items()} ==
            {k: normalized(v) for k, v in next_peers.items()}, 'unrelated peer drift refused')


def replace_endpoint(data, peer, old, new):
    _, peers = parse(data)
    require(peer in peers and peers[peer].get('Endpoint') == old, 'selected endpoint changed')
    lines = data.decode().splitlines(keepends=True)
    start = None
    blocks = []
    for index, line in enumerate(lines):
        if line.split('#', 1)[0].strip() == '[Peer]':
            if start is not None:
                blocks.append((start, index))
            start = index
    if start is not None:
        blocks.append((start, len(lines)))
    found = 0
    for start, stop in blocks:
        _, block_peers = parse(('[Interface]\n' + ''.join(lines[start:stop])).encode())
        if peer not in block_peers:
            continue
        for index in range(start, stop):
            if re.match(r'^\s*Endpoint\s*=', lines[index]):
                ending = '\r\n' if lines[index].endswith('\r\n') else '\n'
                lines[index] = 'Endpoint = ' + new + ending
                found += 1
    require(found == 1, 'ambiguous endpoint line')
    candidate = ''.join(lines).encode()
    compare(data, candidate, peer, old, new)
    return candidate


def run(arguments):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0, 'external command failed (output suppressed)')
    return result.stdout


class Agent:
    def __init__(self, config, journal):
        self.config = config
        validate_scope(config)
        require(config['role'] == 'peer' and config['interface'] == 'wg0', 'unsupported agent scope')
        self.journal = Path(journal)
        self.saved = Path(config['saved'])
        require(str(self.saved) in ('/etc/wireguard/wg0.conf', '/usr/local/etc/wireguard/wg0.conf'),
                'unapproved saved configuration path')
        require(config['wg'] in ('/usr/bin/wg', '/usr/local/bin/wg'), 'unapproved wg executable')

    def runtime(self):
        return run([self.config['wg'], 'showconf', 'wg0'])

    def set_endpoint(self, value):
        run([self.config['wg'], 'set', 'wg0', 'peer', self.config['peer'], 'endpoint', value])

    def read(self):
        private(self.journal, True)
        record = load_json(self.journal / 'record.json')
        require(record['scope'] == self.config, 'journal belongs to another scope')
        return record

    def recovery_check(self):
        if self.saved == Path('/etc/wireguard/wg0.conf'):
            require(run(['/usr/bin/systemctl', 'is-active', 'gonf-endpoint-rollback.timer']).strip() == b'active',
                    'independent endpoint timer inactive')
            for unit in ('gonf-endpoint-rollback-boot.service', 'gonf-endpoint-rollback-runtime.service'):
                require(run(['/usr/bin/systemctl', 'is-enabled', unit]).strip() == b'enabled',
                        'endpoint boot recovery disabled')
        else:
            run(['/usr/sbin/service', 'cron', 'onestatus'])
            cron = Path('/etc/crontab').read_text()
            expected = '* * * * * root /usr/local/sbin/gonf-endpoint-rollback watchdog /var/db/gonf-endpoint/pending'
            require(expected in cron.splitlines(), 'independent endpoint cron missing')
            scripts = sorted(Path('/etc/rc.d').glob('*')) + sorted(Path('/usr/local/etc/rc.d').glob('*'))
            order = run(['/sbin/rcorder'] + [str(p) for p in scripts if p.is_file()]).decode().splitlines()
            require(order.index('/etc/rc.d/gonf_endpoint_rollback') < order.index('/etc/rc.d/netif') and
                    order.index('/usr/local/etc/rc.d/wireguard') < order.index('/etc/rc.d/gonf_endpoint_runtime'),
                    'endpoint boot hook ordering invalid')

    def snapshot(self):
        require(not (self.journal / 'record.json').exists(), 'snapshot already exists')
        self.recovery_check()
        self.journal.mkdir(mode=0o700, parents=False, exist_ok=True)
        private(self.journal, True)
        private(self.saved)
        saved, runtime = self.saved.read_bytes(), self.runtime()
        _, peers = parse(saved)
        _, live = parse(runtime)
        require(peers.keys() == live.keys(), 'saved/runtime peer-set drift')
        require(self.config['peer'] in live, 'selected runtime peer absent')
        # Compare every crypto/route/keepalive field; endpoints are captured separately
        # because authenticated roaming can differ from persisted endpoints.
        for key in peers:
            a, b = normalized(peers[key]), normalized(live[key])
            a.pop('Endpoint', None)
            b.pop('Endpoint', None)
            require(a == b, 'saved/runtime peer drift')
        saved_interface, _ = parse(saved)
        runtime_interface, _ = parse(runtime)
        protocol = {k: v for k, v in saved_interface.items() if k in ('PrivateKey', 'ListenPort', 'FwMark')}
        require(normalized(protocol) == normalized(runtime_interface), 'saved/runtime interface drift')
        require(live[self.config['peer']].get('Endpoint'), 'running endpoint missing')
        private(self.journal / 'recovery-approved')
        require((self.journal / 'recovery-approved').read_text().strip() == self.config['id'],
                'native timer/boot recovery proof not bound to this transaction')
        candidate = replace_endpoint(saved, self.config['peer'], self.config['old'], self.config['new'])
        atomic(self.journal / 'saved.before', saved)
        atomic(self.journal / 'runtime.before', runtime)
        atomic(self.journal / 'saved.after', candidate)
        record = {'scope': self.config, 'phase': 'armed', 'deadline': int(time.time()) + 900}
        write_json(self.journal / 'record.json', record)

    def apply(self):
        record = self.read()
        require(record['phase'] == 'armed' and time.time() < record['deadline'], 'journal expired or applied')
        require((self.journal / 'apply-approved').is_file(), 'fresh referring-host reachability approval absent')
        private(self.journal / 'apply-approved')
        require((self.journal / 'apply-approved').read_text().strip() == self.config['id'],
                'reachability approval belongs to another transaction')
        require(self.saved.read_bytes() == (self.journal / 'saved.before').read_bytes(), 'saved configuration drift')
        require(parse(self.runtime()) == parse((self.journal / 'runtime.before').read_bytes()), 'runtime drift')
        candidate = (self.journal / 'saved.after').read_bytes()
        compare(self.saved.read_bytes(), candidate, self.config['peer'], self.config['old'], self.config['new'])
        # Journal remains armed through either failure. Independent watchdog reconciles it.
        atomic(self.saved, candidate)
        self.set_endpoint(self.config['new'])
        record['phase'] = 'applied'
        write_json(self.journal / 'record.json', record)
        (self.journal / 'apply-approved').unlink()

    def restore(self, runtime):
        record = self.read()
        # Explicit controller rollback may undo a partially released transaction.
        # Independent expiry/boot never rolls back a committed transaction.
        current = self.saved.read_bytes()
        _, peers = parse(current)
        require(self.config['peer'] in peers, 'rollback peer disappeared')
        existing = peers[self.config['peer']].get('Endpoint')
        require(existing in (self.config['old'], self.config['new']), 'rollback endpoint drift')
        # Patch only this endpoint into CURRENT config, preserving unrelated concurrent edits.
        if existing != self.config['old']:
            atomic(self.saved, replace_endpoint(current, self.config['peer'], existing, self.config['old']))
        if runtime:
            _, before = parse((self.journal / 'runtime.before').read_bytes())
            old_live = before[self.config['peer']].get('Endpoint')
            require(old_live, 'snapshot lacked running endpoint')
            _, live = parse(self.runtime())
            require(self.config['peer'] in live, 'runtime rollback peer disappeared')
            self.set_endpoint(old_live)
        record['phase'] = 'restored' if runtime else 'boot-restored'
        write_json(self.journal / 'record.json', record)

    def confirm(self):
        record = self.read()
        require(record['phase'] == 'applied' and time.time() < record['deadline'], 'unapplied or expired journal')
        require((self.journal / 'accept-approved').is_file(), 'external traffic/cold-start approval absent')
        private(self.journal / 'accept-approved')
        require((self.journal / 'accept-approved').read_text().strip() == self.config['id'],
                'acceptance approval belongs to another transaction')
        compare((self.journal / 'saved.before').read_bytes(), self.saved.read_bytes(),
                self.config['peer'], self.config['old'], self.config['new'])
        expected = replace_endpoint((self.journal / 'runtime.before').read_bytes(), self.config['peer'],
                                    parse((self.journal / 'runtime.before').read_bytes())[1][self.config['peer']]['Endpoint'],
                                    self.config['new'])
        require(parse(expected) == parse(self.runtime()), 'runtime acceptance drift')
        # Confirmation validates without disarming. Controller releases only after
        # destination address acceptance and coherent source promotion.
        record['accepted'] = True
        write_json(self.journal / 'record.json', record)

    def release(self):
        record = self.read()
        if record['phase'] == 'confirmed':
            return
        require(record.get('accepted') and record['phase'] == 'applied' and
                time.time() < record['deadline'], 'release requires unexpired acceptance')
        self.confirm()
        record['phase'] = 'confirmed'
        write_json(self.journal / 'record.json', record)

    def status(self):
        record = self.read() if (self.journal / 'record.json').exists() else {'phase': 'absent'}
        # Sanitized receipt only: no config, key, or runtime output.
        return {k: record.get(k) for k in ('phase', 'accepted', 'deadline')} | {
            'id': self.config['id'], 'source_sha256': self.config['source_sha256'],
            'scope_sha256': scope_digest(self.config)}

    def dispatch(self, action):
        if action == 'scope':
            print(json.dumps({'scope_sha256': scope_digest(self.config)}))
        elif action == 'snapshot':
            self.snapshot()
        elif action == 'apply':
            self.apply()
        elif action == 'confirm':
            self.confirm()
        elif action == 'release':
            self.release()
        elif action == 'status':
            print(json.dumps(self.status()))
        elif action == 'restore-boot':
            if self.read()['phase'] != 'confirmed':
                self.restore(False)
        elif action == 'restore-after-boot':
            if self.read()['phase'] == 'boot-restored':
                self.restore(True)
        elif action == 'restore-runtime':
            self.restore(True)
        elif action == 'watchdog':
            if not (self.journal / 'record.json').exists():
                return
            record = self.read()
            if record['phase'] not in ('confirmed', 'restored') and time.time() >= record['deadline']:
                self.restore(True)
        else:
            raise Refused('unsupported peer action')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['scope', 'snapshot', 'apply', 'restore-runtime', 'restore-boot', 'restore-after-boot', 'confirm', 'release', 'status', 'watchdog'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'host endpoint agent requires root')
    os.umask(0o077)
    config = load_json(CONFIG)
    # Advisory lock survives crashes as a file; flock owns exclusion.
    require(args.directory == Path('/var/lib/gonf-endpoint/pending') or
            args.directory == Path('/var/db/gonf-endpoint/pending'), 'unsupported referring-host journal')
    private(args.directory.parent, True)
    lock_path = args.directory.parent / 'lock'
    with open(lock_path, 'a') as lock:
        os.chmod(lock_path, 0o600)
        private(lock_path)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        Agent(config, args.directory).dispatch(args.action)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError):
        # Never include parser/command exceptions which may contain private data.
        print('Endpoint operation refused; private state retained.', file=sys.stderr)
        sys.exit(1)
