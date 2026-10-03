"""探针判定须保留控制连接误伤与缺证，不得用重试覆盖失败。"""
import copy
import unittest
from connection_probe import evaluate


class ProbeVerdictTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            'before':{k:{'ok':True} for k in ('targetExisting','targetNew','controlExisting','controlNew')},
            'during':{k:{'ok':not k.startswith('target')} for k in ('targetExisting','targetNew','controlExisting','controlNew')},
            'after':{k:{'ok':True} for k in ('targetNew','controlExisting','controlNew')},
            'remainingBlockRules':0, 'recoveryTask':[{'lastResult':0}],
        }

    def test_control_timeout_is_failure_even_when_rule_removed(self):
        failed=copy.deepcopy(self.report)
        failed['after']['controlExisting']={'ok':False,'error':'TimeoutError'}
        self.assertEqual(evaluate(failed)['failedChecks'],['after.controlExisting'])
        self.assertTrue(evaluate(self.report)['passed'])
        self.assertFalse(evaluate(failed)['passed'])

    def test_missing_blocking_evidence_is_not_success(self):
        del self.report['during']['targetExisting']
        self.assertFalse(evaluate(self.report)['passed'])

    def test_remaining_rule_or_failed_recovery_is_failure(self):
        self.report['remainingBlockRules']=1
        self.report['recoveryTask'][0]['lastResult']=1
        self.assertEqual(evaluate(self.report)['failedChecks'],['remainingBlockRules','independentRecovery'])
