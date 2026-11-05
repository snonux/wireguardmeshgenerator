#!/usr/bin/env python3
"""Coordinate one destination through explicit SSH referring-peer actions.

No address mutation, config generation, key creation, or whole-tunnel reload.
The destination must already have accepted dual addresses with old IP retained.
"""
import argparse
import contextlib
import copy
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from endpoint import Refused, require, private, load_json, write_json, atomic, digest, validate_scope, scope_digest


@contextlib.contextmanager
def generator_lock(repo):
    with (repo / '.endpoint-generator.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def source_delta(before, after, destination, old, new):
    # Ruby's YAML parser is already the generator's native input parser. Never
    # serialize the YAML: validate a separately prepared byte-preserving candidate.
    program = '''require 'yaml'
a = YAML.safe_load(File.read(ARGV[0])); b = YAML.safe_load(File.read(ARGV[1]))
h = a.fetch('hosts').fetch(ARGV[2]).fetch('lan')
raise 'old mismatch' unless h.fetch('ip') == ARGV[3]
h['ip'] = ARGV[4]
raise 'unrelated source drift' unless a == b
'''
    result = subprocess.run(['ruby', '-e', program, str(before), str(after), destination,
                             old.split(':')[0], new.split(':')[0]],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(result.returncode == 0, 'candidate source contains unrelated drift')


class Controller:
    def __init__(self, repo, state):
        self.repo = Path(repo).resolve()
        self.source = self.repo / 'wireguardmeshgenerator.yaml'
        self.pending = self.repo / '.endpoint-pending'
        self.state = Path(state).resolve()
        private(self.state, True)

    def read(self):
        record = load_json(self.state / 'record.json')
        require(load_json(self.pending)['state'] == str(self.state), 'another migration owns generator lock')
        return record

    def peer(self, record, name, action):
        peer = record['peers'][name]
        # SSH argv and root prefix are trusted private operator input. The remote
        # shell receives only quoted fixed helper/action/path arguments.
        if action != 'scope':
            self.peer(record, name, 'scope')
        command = peer['prefix'] + ['/usr/local/sbin/gonf-endpoint-rollback', action, peer['journal']]
        result = subprocess.run(peer['ssh'] + [shlex.join(command)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(result.returncode == 0, 'referring-host action failed; lock retained')
        if action in ('scope', 'status'):
            receipt = json.loads(result.stdout)
            require(receipt['scope_sha256'] == scope_digest(record['scope']), 'foreign peer receipt')
            return receipt

    def begin(self, manifest, candidate):
        require(not self.pending.exists(), 'endpoint migration already pending')
        require(not (self.state / 'record.json').exists(), 'controller journal already exists')
        validate_scope(manifest['scope'])
        require(manifest['peers'] and isinstance(manifest['peers'], dict), 'explicit referring hosts required')
        # The complete referring-host list must be independently checked against
        # current saved configs. No broad host discovery or key rendering here.
        for name, peer in manifest['peers'].items():
            require(name and peer['ssh'] and peer['ssh'][0] == 'ssh', 'explicit SSH transport required')
            require(peer['journal'] in ('/var/lib/gonf-endpoint/pending', '/var/db/gonf-endpoint/pending'),
                    'invalid referring-host journal')
            require(peer['prefix'] in (['sudo', '-n'], ['doas', '-n']), 'noninteractive privilege required')
        gate = load_json(self.state / 'destination-approved.json')
        require(gate == {'id': manifest['scope']['id'], 'destination': manifest['destination'],
                         'dual_address_accepted': True, 'old_address_retained': True,
                         'referring_hosts': sorted(manifest['peers'])},
                'destination/referencing inventory acceptance required')
        before = self.source.read_bytes()
        require(digest(before) == manifest['scope']['source_sha256'], 'source digest mismatch')
        private(candidate)
        source_delta(self.source, candidate, manifest['destination'], manifest['scope']['old'], manifest['scope']['new'])
        atomic(self.state / 'source.before', before)
        atomic(self.state / 'source.after', Path(candidate).read_bytes())
        record = copy.deepcopy(manifest)
        record['decision'] = 'pending'
        write_json(self.state / 'record.json', record)
        # Persistent marker is deliberately not an expiring PID lock. It survives
        # controller exit/reboot, and normal generate/install/clean refuse it.
        write_json(self.pending, {'state': str(self.state)})

    def finish(self, record, decision):
        expected = (self.state / ('source.after' if decision == 'commit' else 'source.before')).read_bytes()
        require(self.source.read_bytes() == expected, 'source does not match final decision')
        record['decision'] = decision + '-complete'
        write_json(self.state / 'record.json', record)
        self.pending.unlink()
        # Persist unlink before allowing a subsequent generator invocation.
        fd = os.open(self.repo, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def reconcile(self, rollback=False):
        record = self.read()
        record['decision'] = record['decision'].removesuffix('-complete')
        receipts = {name: self.peer(record, name, 'status') for name in record['peers']}
        if rollback or record['decision'] == 'rollback' or any(
                r['phase'] in ('restored', 'boot-restored') for r in receipts.values()):
            record['decision'] = 'rollback'
            write_json(self.state / 'record.json', record)
            # Source stays locked until every peer has acknowledged runtime and
            # persistent restoration, including peers already partially released.
            self.promote('source.before')
            for name in record['peers']:
                if receipts[name]['phase'] != 'absent':
                    self.peer(record, name, 'restore-runtime')
            require(all(self.peer(record, n, 'status')['phase'] in ('restored', 'absent') for n in record['peers']),
                    'rollback acknowledgments incomplete')
            self.finish(record, 'rollback')
            return
        require(record['decision'] == 'commit', 'explicit commit or rollback decision required')
        require(all(r['phase'] == 'confirmed' or (r['phase'] == 'applied' and r['accepted'] and time.time() < r['deadline'])
                    for r in receipts.values()), 'all referring hosts must accept before release')
        self.promote('source.after')
        for name in record['peers']:
            self.peer(record, name, 'release')
        require(all(self.peer(record, n, 'status')['phase'] == 'confirmed' for n in record['peers']),
                'release acknowledgments incomplete')
        self.finish(record, 'commit')

    def promote(self, filename):
        before = (self.state / 'source.before').read_bytes()
        after = (self.state / 'source.after').read_bytes()
        require(self.source.read_bytes() in (before, after), 'authoritative source drift; reconcile manually')
        # This is the only source-writing path; all generator operations remain
        # blocked across promotion, partial release, and failed rollback.
        atomic(self.source, (self.state / filename).read_bytes(), self.source.stat().st_mode & 0o777)

    def dispatch(self, action):
        record = self.read()
        if action == 'commit':
            require(record['decision'] == 'pending', 'decision already recorded')
            receipts = [self.peer(record, n, 'status') for n in record['peers']]
            require(all(r['phase'] == 'applied' and r.get('accepted') and time.time() < r['deadline']
                        for r in receipts), 'missing or expired referring-host acceptance')
            record['decision'] = 'commit'
            write_json(self.state / 'record.json', record)
            self.reconcile()
        elif action in ('rollback', 'reconcile'):
            self.reconcile(action == 'rollback')
        elif action in ('snapshot', 'apply', 'confirm', 'status'):
            raise Refused('select one referring host with --peer')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['begin', 'snapshot', 'apply', 'confirm', 'status', 'commit', 'rollback', 'reconcile'])
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--peer')
    args = parser.parse_args()
    os.umask(0o077)
    controller = Controller(args.repo, args.state)
    with generator_lock(controller.repo):
        if args.action == 'begin':
            require(args.manifest and args.candidate, 'manifest and candidate required')
            controller.begin(load_json(args.manifest), args.candidate)
        elif args.peer:
            require(args.action in ('snapshot', 'apply', 'confirm', 'status'), 'invalid scoped action')
            record = controller.read()
            require(record['decision'] == 'pending', 'scoped apply refused after decision')
            require(args.peer in record['peers'], 'unknown referring host')
            receipt = controller.peer(record, args.peer, args.action)
            if receipt:
                print(json.dumps(receipt))
        else:
            controller.dispatch(args.action)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError):
        print('Endpoint coordination refused; private state and generator lock retained.', file=sys.stderr)
        sys.exit(1)
