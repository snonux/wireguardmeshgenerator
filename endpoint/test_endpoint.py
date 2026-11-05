"""Generic private fixtures; never read real YAML, keys, dist, or interfaces."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

from endpoint import Agent, Refused, atomic, compare, digest, normalized, parse, replace_endpoint, write_json
from controller import Controller

KEY = base64.b64encode(bytes(range(32))).decode()
OTHER = base64.b64encode(bytes(range(1, 33))).decode()
OLD = '192.168.1.120:56709'
NEW = '10.20.0.120:56709'
SAVED = f'''[Interface]
Address = 192.0.2.1/32
Address = fd00::1/64
PrivateKey = {KEY}
ListenPort = 56709

[Peer] # destination a.example
PublicKey = {KEY}
PresharedKey = {OTHER}
AllowedIPs = 192.0.2.2/32, fd00::2/128
Endpoint = {OLD}

[Peer]
PublicKey = {OTHER}
AllowedIPs = 198.51.100.0/24
Endpoint = 203.0.113.1:56709
PersistentKeepalive = 25
'''.encode()
RUNTIME = SAVED.replace(b'Address = 192.0.2.1/32\nAddress = fd00::1/64\n', b'')
SCOPE = {'id': 'test-stage-1', 'peer': KEY, 'old': OLD, 'new': NEW, 'source_sha256': 'a' * 64}


class FixtureAgent(Agent):
    def __init__(self, root, scope=None):
        scope = scope or SCOPE
        config = dict(scope, role='peer', interface='wg0', saved='/etc/wireguard/wg0.conf', wg='/usr/bin/wg')
        super().__init__(config, root / 'pending')
        self.saved = root / 'wg0.conf'
        self.journal.mkdir(mode=0o700)
        atomic(self.saved, SAVED)
        self.live = RUNTIME
        self.calls = []
        self.fail_set = False
        atomic(self.journal / 'recovery-approved', (scope['id'] + '\n').encode())

    def recovery_check(self):
        pass  # OS-owned recovery readiness is a later native canary prerequisite.

    def runtime(self):
        return self.live

    def set_endpoint(self, value):
        self.calls.append(value)
        if self.fail_set:
            raise Refused('fixture set failure')
        _, peers = parse(self.live)
        self.live = replace_endpoint(self.live, self.config['peer'], peers[self.config['peer']]['Endpoint'], value)

    def approve(self, name):
        atomic(self.journal / name, self.config['id'].encode())

    def prepared(self):
        self.snapshot()
        self.approve('apply-approved')
        self.apply()
        self.approve('accept-approved')
        self.confirm()


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.agent = FixtureAgent(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_dormant_watchdog_is_quiet_without_a_snapshot(self):
        self.agent.dispatch('watchdog')
        self.assertEqual(self.agent.calls, [])

    def test_scoped_patch_preserves_other_peer_and_dual_address(self):
        after = replace_endpoint(SAVED, KEY, OLD, NEW)
        self.assertEqual(after, SAVED.replace(OLD.encode(), NEW.encode()))
        compare(SAVED, after, KEY, OLD, NEW)
        self.assertEqual(parse(SAVED)[0]['Address'], '192.0.2.1/32,fd00::1/64')

    def test_rejects_crypto_routes_interface_peer_and_public_endpoint_drift(self):
        good = replace_endpoint(SAVED, KEY, OLD, NEW)
        variants = [good.replace(b'PresharedKey = ', b'PresharedKey = x'),
                    good.replace(b'PrivateKey = ', b'PrivateKey = x'),
                    good.replace(b'192.0.2.1/32', b'192.0.2.9/32'),
                    good.replace(b'192.0.2.2/32', b'192.0.2.3/32'),
                    good.replace(b'PersistentKeepalive = 25', b'PersistentKeepalive = 30'),
                    good.replace(b'203.0.113.1', b'203.0.113.2'),
                    good + f'\n[Peer]\nPublicKey = {KEY}\n'.encode(),
                    good.replace(f'PublicKey = {OTHER}'.encode(), b'PublicKey = foreign')]
        for candidate in variants:
            with self.subTest(candidate=digest(candidate)), self.assertRaises(Refused):
                compare(SAVED, candidate, KEY, OLD, NEW)

    def test_semantic_allowed_ip_order_and_disabled_keepalive(self):
        after = replace_endpoint(SAVED, KEY, OLD, NEW).replace(
            b'192.0.2.2/32, fd00::2/128', b'fd00:0::2/128,192.0.2.2/32')
        after = after.replace(f'PublicKey = {KEY}'.encode(), f'PublicKey = {KEY}\nPersistentKeepalive = off'.encode())
        compare(SAVED, after, KEY, OLD, NEW)

    def test_opaque_or_duplicate_structure_refused(self):
        for data in (b'garbage', SAVED + b'ListenPort = 10\nListenPort = 11\n',
                     SAVED + b'[Interface]\nListenPort = 56709\n'):
            with self.assertRaises(Refused):
                parse(data)

    def test_snapshot_rejects_saved_runtime_drift_and_missing_recovery_proof(self):
        self.agent.live = RUNTIME.replace(b'198.51.100.0/24', b'198.51.101.0/24')
        with self.assertRaises(Refused):
            self.agent.snapshot()
        self.agent.live = RUNTIME
        (self.agent.journal / 'recovery-approved').unlink()
        with self.assertRaises(FileNotFoundError):
            self.agent.snapshot()
        self.assertFalse((self.agent.journal / 'record.json').exists())

    def test_expired_and_foreign_gates_refused(self):
        self.agent.snapshot()
        atomic(self.agent.journal / 'apply-approved', b'another-transaction')
        with self.assertRaises(Refused):
            self.agent.apply()
        self.agent.approve('apply-approved')
        with patch('endpoint.time.time', return_value=time.time() + 1000), self.assertRaises(Refused):
            self.agent.apply()
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)

    def test_public_gate_permissions_refused(self):
        self.agent.snapshot()
        self.agent.approve('apply-approved')
        (self.agent.journal / 'apply-approved').chmod(0o644)
        with self.assertRaises(Refused):
            self.agent.apply()
        self.assertEqual(self.agent.calls, [])

    def test_apply_requires_bound_gate_and_unchanged_runtime(self):
        self.agent.snapshot()
        self.agent.approve('apply-approved')
        self.agent.live = RUNTIME.replace(b'203.0.113.1', b'203.0.113.2')
        with self.assertRaises(Refused):
            self.agent.apply()
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertEqual(self.agent.calls, [])

    def test_runtime_failure_keeps_journal_armed_and_restores_both(self):
        self.agent.snapshot()
        self.agent.approve('apply-approved')
        self.agent.fail_set = True
        with self.assertRaises(Refused):
            self.agent.apply()
        self.assertEqual(self.agent.read()['phase'], 'armed')
        self.assertIn(NEW.encode(), self.agent.saved.read_bytes())
        self.agent.fail_set = False
        self.agent.restore(True)
        self.agent.restore(True)
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertEqual(self.agent.live, RUNTIME)

    def test_learned_runtime_endpoint_restored_exactly(self):
        self.agent.live = RUNTIME.replace(OLD.encode(), b'198.51.100.7:62000')
        learned = self.agent.live
        self.agent.snapshot()
        self.agent.approve('apply-approved')
        self.agent.apply()
        self.agent.restore(True)
        self.assertEqual(self.agent.live, learned)
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)

    def test_confirm_does_not_disarm_deadline(self):
        self.agent.prepared()
        self.assertEqual(self.agent.read()['phase'], 'applied')
        with patch('endpoint.time.time', return_value=time.time() + 1000):
            self.agent.dispatch('watchdog')
        self.assertEqual(self.agent.read()['phase'], 'restored')
        with self.assertRaises(Refused):
            self.agent.release()

    def test_boot_ignores_deadline_and_restores_runtime_later(self):
        self.agent.prepared()
        self.agent.dispatch('restore-boot')
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertIn(NEW.encode(), self.agent.live)
        self.agent.dispatch('restore-after-boot')
        self.assertEqual(self.agent.live, RUNTIME)
        self.assertEqual(self.agent.read()['phase'], 'restored')

    def test_released_peer_keeps_endpoint_at_boot_but_explicit_rollback_works(self):
        self.agent.prepared()
        self.agent.release()
        self.agent.release()
        self.agent.dispatch('restore-boot')
        with patch('endpoint.time.time', return_value=time.time() + 1000):
            self.agent.dispatch('watchdog')
        self.assertIn(NEW.encode(), self.agent.saved.read_bytes())
        self.agent.restore(True)
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)

    def test_rollback_preserves_concurrent_unrelated_edit(self):
        self.agent.prepared()
        atomic(self.agent.saved, self.agent.saved.read_bytes().replace(b'203.0.113.1', b'203.0.113.9'))
        self.agent.restore(True)
        self.assertIn(b'203.0.113.9', self.agent.saved.read_bytes())
        self.assertIn(OLD.encode(), self.agent.saved.read_bytes())

    @unittest.skipUnless(shutil.which('wg-quick'), 'wg-quick unavailable')
    def test_native_wg_quick_strip_accepts_candidate(self):
        path = self.root / 'candidate.conf'
        atomic(path, replace_endpoint(SAVED, KEY, OLD, NEW))
        result = subprocess.run(['wg-quick', 'strip', str(path)], capture_output=True, check=True)
        self.assertNotIn('Address', parse(result.stdout)[0])
        compare(RUNTIME, result.stdout, KEY, OLD, NEW)


class FixtureController(Controller):
    def __init__(self, root):
        repo = root / 'repo'; repo.mkdir()
        state = root / 'state'; state.mkdir(mode=0o700)
        super().__init__(repo, state)
        self.agents = {}
        self.fail_release = None

    def peer(self, record, name, action):
        agent = self.agents[name]
        if action == 'status':
            return agent.status()
        if action == 'release' and name == self.fail_release:
            raise Refused('fixture controller interruption')
        agent.dispatch(action)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.c = FixtureController(self.root)
        self.before = b'hosts:\n  a.example:\n    lan:\n      ip: 192.168.1.120\n    os: Linux\n'
        atomic(self.c.source, self.before)
        self.candidate = self.root / 'candidate.yaml'
        atomic(self.candidate, self.before.replace(b'192.168.1.120', b'10.20.0.120'))
        self.scope = dict(SCOPE, source_sha256=digest(self.before))
        self.manifest = {'scope': self.scope, 'destination': 'a.example', 'peers': {
            n: {'ssh': ['ssh', n], 'prefix': ['sudo', '-n'], 'journal': '/var/lib/gonf-endpoint/pending'}
            for n in ('b.example', 'c.example')}}
        write_json(self.c.state / 'destination-approved.json', {
            'id': self.scope['id'], 'destination': 'a.example', 'dual_address_accepted': True,
            'old_address_retained': True, 'referring_hosts': sorted(self.manifest['peers'])})
        for n in self.manifest['peers']:
            directory = self.root / n; directory.mkdir(mode=0o700)
            self.c.agents[n] = FixtureAgent(directory, self.scope)

    def tearDown(self):
        self.temp.cleanup()

    def begin(self):
        self.c.begin(self.manifest, self.candidate)
        for a in self.c.agents.values():
            a.prepared()

    def test_begin_never_promotes_source_and_missing_destination_gate_refuses(self):
        (self.c.state / 'destination-approved.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.c.begin(self.manifest, self.candidate)
        self.assertFalse(self.c.pending.exists())
        self.assertEqual(self.c.source.read_bytes(), self.before)

    def test_foreign_peer_scope_refused_before_any_mutating_command(self):
        self.c.begin(self.manifest, self.candidate)
        controller = Controller(self.c.repo, self.c.state)
        result = Mock(returncode=0, stdout=b'{"scope_sha256": "foreign"}')
        with patch('controller.subprocess.run', return_value=result) as command:
            with self.assertRaises(Refused):
                controller.peer(self.c.read(), 'b.example', 'apply')
        self.assertEqual(command.call_count, 1)
        self.assertIn(' scope ', command.call_args.args[0][-1])

    def test_generator_refuses_marker_before_help_or_yaml_read(self):
        script = Path(__file__).resolve().parent.parent / 'wireguardmeshgenerator.rb'
        write_json(self.c.pending, {'state': str(self.c.state)})
        result = subprocess.run(['ruby', str(script), '--help'], cwd=self.c.repo, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'Unresolved endpoint migration', result.stdout)
        self.assertFalse((self.c.repo / 'dist').exists())

    def test_native_yaml_parser_rejects_unrelated_drift(self):
        atomic(self.candidate, self.candidate.read_bytes().replace(b'Linux', b'FreeBSD'))
        with self.assertRaises(Refused):
            self.c.begin(self.manifest, self.candidate)
        self.assertFalse(self.c.pending.exists())

    def test_abort_before_any_host_snapshot_releases_source_lock(self):
        self.c.begin(self.manifest, self.candidate)
        self.c.dispatch('rollback')
        self.assertEqual(self.c.source.read_bytes(), self.before)
        self.assertFalse(self.c.pending.exists())

    def test_commit_promotes_only_after_all_accepted_and_releases(self):
        self.begin()
        self.assertEqual(self.c.source.read_bytes(), self.before)
        self.c.dispatch('commit')
        self.assertEqual(self.c.source.read_bytes(), self.candidate.read_bytes())
        self.assertFalse(self.c.pending.exists())
        self.assertTrue(all(a.read()['phase'] == 'confirmed' for a in self.c.agents.values()))

    def test_partial_release_crash_expiry_then_reconcile_restores_all_and_source(self):
        self.begin()
        self.c.fail_release = 'c.example'
        with self.assertRaises(Refused):
            self.c.dispatch('commit')
        self.assertTrue(self.c.pending.exists())
        self.assertEqual(self.c.agents['b.example'].read()['phase'], 'confirmed')
        self.c.agents['c.example'].restore(True)
        self.c.fail_release = None
        # New controller instance recovers solely from durable journal.
        recovered = Controller(self.c.repo, self.c.state)
        recovered.peer = self.c.peer
        recovered.reconcile()
        self.assertEqual(self.c.source.read_bytes(), self.before)
        self.assertFalse(self.c.pending.exists())
        self.assertTrue(all(a.read()['phase'] == 'restored' for a in self.c.agents.values()))

    def test_source_drift_keeps_lock_and_refuses_promotion(self):
        self.begin()
        atomic(self.c.source, self.before + b'# concurrent change\n')
        with self.assertRaises(Refused):
            self.c.dispatch('commit')
        self.assertTrue(self.c.pending.exists())
        self.assertTrue(all(a.read()['phase'] == 'applied' for a in self.c.agents.values()))

    def test_expired_peer_cannot_commit_and_explicit_rollback_is_coherent(self):
        self.begin()
        self.c.agents['c.example'].restore(True)
        with self.assertRaises(Refused):
            self.c.dispatch('commit')
        self.assertTrue(self.c.pending.exists())
        self.c.dispatch('rollback')
        self.assertEqual(self.c.source.read_bytes(), self.before)
        self.assertFalse(self.c.pending.exists())


if __name__ == '__main__':
    unittest.main()
