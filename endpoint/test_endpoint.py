"""Generic private fixtures; never read real YAML, keys, dist, or interfaces."""
import base64
import copy
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

from endpoint import Agent, Refused, atomic, compare, digest, journal_lock, normalized, parse, replace_endpoint, scope_digest, write_json
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


class FileFixtureAgent(FixtureAgent):
    """Persist the synthetic runtime too, so separate processes observe each other."""
    def runtime(self):
        return (self.journal / 'fixture-live').read_bytes()

    def set_endpoint(self, value):
        current = self.runtime()
        old = parse(current)[1][self.config['peer']]['Endpoint']
        atomic(self.journal / 'fixture-live', replace_endpoint(current, self.config['peer'], old, value))


def race_action(agent, action, now, ready, results):
    ready.set()
    try:
        with journal_lock(agent.journal), patch('endpoint.time.time', return_value=now):
            agent.dispatch(action)
        results.put('ok')
    except Refused:
        results.put('refused')


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


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.agent = FixtureAgent(self.root, dict(SCOPE, protocol='canary'))
        (self.agent.journal / 'recovery-approved').unlink()
        self.deadline = int(time.time()) + 120
        self.outer = self.deadline + 120
        self.authorize()

    def tearDown(self):
        self.temp.cleanup()

    def authorize(self, **changes):
        gate = {'config_sha256': digest(json.dumps(self.agent.config, sort_keys=True).encode()),
                'expires': self.outer, 'confirm_before': self.deadline}
        gate.update(changes)
        write_json(self.agent.journal / 'canary-approved.json', gate)

    def apply(self):
        self.agent.snapshot()
        self.agent.approve('apply-approved')
        self.agent.apply()

    def test_canary_requires_no_false_production_proof_and_restores_on_expiry(self):
        self.agent.live = RUNTIME.replace(OLD.encode(), b'198.51.100.7:62000')
        captured = self.agent.live
        self.apply()
        self.assertEqual(self.agent.read()['deadline'], self.deadline)
        self.assertIn(NEW.encode(), self.agent.saved.read_bytes())
        with patch('endpoint.time.time', return_value=self.deadline):
            self.agent.dispatch('watchdog')
            self.agent.dispatch('watchdog')
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertEqual(self.agent.live, captured)
        self.assertEqual(self.agent.read()['phase'], 'restored')
        self.assertFalse((self.agent.journal / 'recovery-approved').exists())

    def test_missing_foreign_stale_unbounded_and_public_authorizations_refused(self):
        for changes in ({'config_sha256': 'b' * 64}, {'expires': 0},
                        {'expires': int(time.time()) + 1000}, {'expires': True},
                        {'extra': True}):
            self.authorize(**changes)
            with self.assertRaises(Refused):
                self.agent.snapshot()
            self.assertFalse((self.agent.journal / 'record.json').exists())
        self.authorize()
        path = self.agent.journal / 'canary-approved.json'
        path.chmod(0o644)
        with self.assertRaises(Refused):
            self.agent.snapshot()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.agent.snapshot()

    def test_canary_readiness_and_fresh_apply_gates_still_required(self):
        with patch.object(self.agent, 'recovery_check', side_effect=Refused('inactive')):
            with self.assertRaises(Refused):
                self.agent.snapshot()
        self.agent.snapshot()
        with self.assertRaises(Refused):
            self.agent.apply()
        self.agent.approve('apply-approved')
        self.authorize(expires=self.deadline + 1)
        with self.assertRaises(Refused):
            self.agent.apply()
        self.authorize()
        with patch.object(self.agent, 'recovery_check', side_effect=Refused('inactive')):
            with self.assertRaises(Refused):
                self.agent.apply()
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)

    def test_confirmation_retains_past_inner_deadline_but_outer_lease_restores(self):
        self.apply()
        self.agent.approve('accept-approved')
        with self.assertRaises(Refused):
            self.agent.confirm()
        self.agent.approve('canary-confirm-approved')
        self.agent.confirm()
        self.assertEqual(self.agent.read()['phase'], 'confirmed')
        with patch('endpoint.time.time', return_value=self.deadline + 1):
            self.agent.dispatch('watchdog')
        self.assertIn(NEW.encode(), self.agent.saved.read_bytes())
        self.assertIn(NEW.encode(), self.agent.live)
        with self.assertRaises(Refused):
            self.agent.release()
        with patch('endpoint.time.time', return_value=self.outer):
            self.agent.dispatch('watchdog')
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertEqual(self.agent.live, RUNTIME)
        with self.assertRaises(Refused):
            self.agent.confirm()

    def test_confirmed_canary_still_restores_at_boot(self):
        self.apply()
        self.agent.approve('canary-confirm-approved')
        self.agent.confirm()
        self.agent.dispatch('restore-boot')
        self.agent.dispatch('restore-after-boot')
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertEqual(self.agent.live, RUNTIME)

    def test_canary_boot_before_deadline_and_runtime_retry(self):
        self.apply()
        self.agent.dispatch('restore-boot')
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)
        self.assertIn(NEW.encode(), self.agent.live)
        self.agent.fail_set = True
        with self.assertRaises(Refused):
            self.agent.dispatch('restore-after-boot')
        self.assertEqual(self.agent.read()['phase'], 'boot-restored')
        self.agent.fail_set = False
        self.agent.dispatch('restore-after-boot')
        self.assertEqual(self.agent.live, RUNTIME)

    def test_expiry_wins_confirmation_and_failed_confirmation_remains_armed(self):
        self.apply()
        self.agent.approve('canary-confirm-approved')
        self.agent.live = self.agent.live.replace(b'198.51.100.0/24', b'198.51.101.0/24')
        with self.assertRaises(Refused):
            self.agent.confirm()
        self.assertEqual(self.agent.read()['phase'], 'applied')
        with patch('endpoint.time.time', return_value=self.deadline):
            with self.assertRaises(Refused):
                self.agent.confirm()
            self.agent.dispatch('watchdog')
            with self.assertRaises(Refused):
                self.agent.confirm()
        self.assertEqual(self.agent.saved.read_bytes(), SAVED)

    def test_canary_cannot_relabel_a_journal_as_production_or_reuse_trial(self):
        self.apply()
        with self.assertRaises(Refused):
            self.agent.snapshot()
        self.assertNotEqual(scope_digest(self.agent.config), scope_digest(SCOPE))
        self.agent.config.pop('protocol')
        self.agent.canary = False
        self.agent.approve('recovery-approved')
        with self.assertRaises(Refused):
            self.agent.read()

    def test_actual_flock_serializes_confirm_against_outer_expiry(self):
        # Whichever worker obtains the real CLI lock first, outer expiry wins.
        self.apply()
        self.agent.approve('canary-confirm-approved')
        shared = FileFixtureAgent.__new__(FileFixtureAgent)
        shared.__dict__.update(self.agent.__dict__)
        atomic(shared.journal / 'fixture-live', self.agent.live)
        context = multiprocessing.get_context('spawn')
        results = context.Queue()
        ready = [context.Event(), context.Event()]
        workers = [context.Process(target=race_action, args=(shared, action, now, event, results))
                   for action, now, event in [('confirm', time.time(), ready[0]),
                                               ('watchdog', self.outer, ready[1])]]
        try:
            with journal_lock(shared.journal):
                for worker in workers:
                    worker.start()
                for event in ready:
                    self.assertTrue(event.wait(5))
                self.assertTrue(all(worker.is_alive() for worker in workers))
                self.assertEqual(shared.read()['phase'], 'applied')
            for worker in workers:
                worker.join(5)
                self.assertEqual(worker.exitcode, 0)
            outcomes = [results.get(timeout=5), results.get(timeout=5)]
            self.assertIn('ok', outcomes)
            self.assertEqual(shared.read()['phase'], 'restored')
            self.assertEqual(shared.saved.read_bytes(), SAVED)
            self.assertEqual(shared.runtime(), RUNTIME)
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.terminate()
                    worker.join(5)
            results.close()


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

    def test_canary_manifest_and_receipt_cannot_promote_source(self):
        self.manifest['scope']['protocol'] = 'canary'
        with self.assertRaises(Refused):
            self.c.begin(self.manifest, self.candidate)
        self.assertFalse(self.c.pending.exists())
        self.manifest['scope'].pop('protocol')
        self.c.begin(self.manifest, self.candidate)
        controller = Controller(self.c.repo, self.c.state)
        receipt = {'scope_sha256': scope_digest(dict(self.scope, protocol='canary'))}
        result = Mock(returncode=0, stdout=json.dumps(receipt).encode())
        with patch('controller.subprocess.run', return_value=result) as command:
            with self.assertRaises(Refused):
                controller.dispatch('commit')
        self.assertEqual(command.call_count, 1)
        self.assertEqual(self.c.source.read_bytes(), self.before)
        self.assertTrue(self.c.pending.exists())

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
