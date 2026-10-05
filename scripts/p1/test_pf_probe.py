"""复现 PF 安装到回执间失败的恢复边界；替换系统调用，不需要特权或改变规则。"""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import pf_probe


class PFRecoveryTests(unittest.TestCase):
    def test_observer_recovers_without_apply_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);case=base/'ttl';case.mkdir()
            now=time.monotonic()
            manifest=dict(base=directory,anchor='hostguard/fixture',authorizationUntil=time.time()+60)
            lease=dict(case='ttl',id='fixture',deadline=now-1,clockAnchor=time.time()-now)
            (base/'lease.json').write_text(json.dumps(lease))
            (base/'owner-heartbeat.json').write_text(json.dumps({'monotonic':now}))
            state={'blocked':True}
            def recover(m,blocked,lease=None):
                self.assertFalse(blocked)
                self.assertTrue((case/'clear-requested.json').exists())
                state['blocked']=False
            def stop_loop(_):manifest['authorizationUntil']=0
            with patch.object(pf_probe,'load',side_effect=recover), \
                 patch.object(pf_probe,'inventory',side_effect=lambda _:dict(blockRules=int(state['blocked']),rules='')), \
                 patch.object(pf_probe,'run',return_value=('','')), \
                 patch.object(pf_probe.time,'sleep',side_effect=stop_loop):
                pf_probe.worker(manifest,'observer')
            self.assertFalse((case/'applied.json').exists())
            self.assertEqual(json.loads((case/'cleared.json').read_text())['reason'],'ttl_expired')
            self.assertFalse(state['blocked'])

    def test_cancelled_lease_cannot_reinstall_after_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);case=base/'executor-crash';case.mkdir()
            (case/'clear-requested.json').write_text('{}')
            now=time.monotonic()
            manifest=dict(base=directory,anchor='hostguard/fixture',authorizationUntil=time.time()+60)
            lease=dict(case='executor-crash',deadline=now+30,clockAnchor=time.time()-now)
            with patch.object(pf_probe,'run') as command,patch.object(pf_probe,'inventory') as inventory:
                self.assertFalse(pf_probe.load(manifest,True,lease))
                command.assert_not_called();inventory.assert_not_called()


if __name__=='__main__':unittest.main()
