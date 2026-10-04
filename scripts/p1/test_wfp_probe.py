"""恢复探针的拒绝边界测试；不调用防火墙，不替代 Windows 真实故障试验。"""
import copy
import ctypes
import datetime as dt
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import wfp_native as native
from wfp_probe import validate_scope, validate_command, write_new, owner, supervise


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat()


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.now = 1800000000
        self.scope = dict(runId='p1-0123456789abcdef', local='10.88.0.2', peer='10.88.0.3',
                          port=55161, controlPort=55162, expiresUtc=iso(self.now+120),
                          platform='Windows', direction='inbound', transport='tcp')
        self.ready = dict(bootId='boot-new', executorId='executor-new')
        self.command = {k: self.scope[k] for k in ('runId', 'local', 'peer', 'port')}
        self.command.update(self.ready, actionId='one', issuedUtc=iso(self.now),
                            applyBy=iso(self.now+10), blockUntil=iso(self.now+30))

    def test_valid_fixed_deadline(self):
        validate_scope(self.scope, self.now)
        self.assertEqual(30, validate_command(self.command, self.scope, self.ready, self.now))
        self.assertEqual(23, validate_command(self.command, self.scope, self.ready, self.now+7))

    def test_old_boot(self):
        self.command['bootId'] = 'boot-old'
        with self.assertRaisesRegex(ValueError, 'STALE_BOOT'):
            validate_command(self.command, self.scope, self.ready, self.now)

    def test_old_executor(self):
        self.command['executorId'] = 'executor-old'
        with self.assertRaisesRegex(ValueError, 'STALE_EXECUTOR'):
            validate_command(self.command, self.scope, self.ready, self.now)

    def test_expired_late_and_future(self):
        for when in (self.now-1, self.now+10, self.now+30, self.now+60):
            with self.subTest(when=when), self.assertRaises(ValueError):
                validate_command(self.command, self.scope, self.ready, when)

    def test_no_extended_or_shortened_lease(self):
        for length in (5, 29, 31, 60):
            self.command['blockUntil'] = iso(self.now+length)
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, 'LEASE'):
                validate_command(self.command, self.scope, self.ready, self.now)

    def test_scope_mismatch(self):
        for key, value in (('local','10.88.0.4'), ('peer','10.88.0.5'), ('port',55162), ('runId','other')):
            c = copy.deepcopy(self.command); c[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SCOPE_MISMATCH'):
                validate_command(c, self.scope, self.ready, self.now)

    def test_authorization_ends_before_lease(self):
        self.scope['expiresUtc'] = iso(self.now+20)
        with self.assertRaises(ValueError):
            validate_command(self.command, self.scope, self.ready, self.now)

    def test_management_ports_rejected(self):
        for port in (22, 443, 3389, 41641, 49151, 65534):
            self.scope.update(port=port, controlPort=port+1)
            with self.subTest(port=port), self.assertRaises(ValueError):
                validate_scope(self.scope, self.now)

    def test_nonisolated_addresses_rejected(self):
        for peer in ('127.0.0.1','8.8.8.8','::1','10.88.0.2'):
            self.scope['peer'] = peer
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                validate_scope(self.scope, self.now)

    def test_expired_or_long_authorization(self):
        for seconds in (-1, 0, 1201):
            self.scope['expiresUtc'] = iso(self.now+seconds)
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                validate_scope(self.scope, self.now)

    def test_immutable_command_rejects_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'command.json'
            write_new(path, self.command)
            first = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_new(path, {'changed': True})
            self.assertEqual(first, path.read_bytes())

    def test_sdk_x64_abi(self):
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            self.skipTest('64 bit ABI only')
        self.assertEqual([72,72,40,200], [ctypes.sizeof(t) for t in
                         (native.Session,native.Sublayer,native.Condition,native.Filter)])

    def test_residual_objects_keep_command_gate_closed(self):
        import json
        for inventory in ({'filters':[{'id':42}],'sublayerPresent':True},
                          {'filters':[],'sublayerPresent':True}):
            with self.subTest(inventory=inventory), tempfile.TemporaryDirectory() as directory:
                base=Path(directory); manifest=base/'manifest.json'
                manifest.write_text(json.dumps(self.scope))
                engine=MagicMock(); engine.return_value.__enter__.return_value.inventory.return_value=inventory
                with patch('wfp_probe.Engine',engine), patch('wfp_probe.time.time',return_value=self.now), \
                     patch('wfp_probe.assert_isolation',return_value={}), patch('wfp_probe.boot_id',return_value='boot'):
                    owner(base,manifest,MagicMock(),'none')
                self.assertFalse((base/'ready.json').exists())
                self.assertFalse((base/'applied.json').exists())
                self.assertIn('RECOVERY_INCOMPLETE',(base/'owner.jsonl').read_text())
                engine.return_value.install.assert_not_called()

    def test_rejected_owner_pipe_closure_still_records_final_inventory(self):
        # Windows PeekNamedPipe 在子进程早退后可直接抛错；拒绝命令仍须形成外部清零账本。
        import json
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)/'case';context=MagicMock();parent=MagicMock();child=MagicMock()
            context.Pipe.return_value=(parent,child);parent.poll.side_effect=BrokenPipeError()
            proc=context.Process.return_value;proc.is_alive.side_effect=[True,False,False,False];proc.exitcode=0;proc.pid=42
            engine=MagicMock();inventory={'filters':[],'sublayerPresent':False}
            engine.return_value.__enter__.return_value.inventory.return_value=inventory
            with patch('wfp_probe.mp.get_context',return_value=context),patch('wfp_probe.Engine',engine):
                supervise(Path(directory)/'manifest.json',base,'none')
            self.assertEqual(json.loads((base/'final.json').read_text())['inventory'],inventory)


if __name__ == '__main__':
    unittest.main()
