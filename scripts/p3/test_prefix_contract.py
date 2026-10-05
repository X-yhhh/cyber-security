"""旁路角色链、公共角色和共同早期轨迹防泄漏回归，无采集或拟合。"""
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from prefix_contract import collection_gate, metadata, planned_role, sole_role, early_edges


class PrefixContractTest(unittest.TestCase):
    def _gate_files(self, blockers, *, status='blocked', mutate=None):
        plan = {
            'version': 'test-plan',
            'versions': {
                'decision': 'decision/test',
                'evaluation': 'evaluation/test',
            },
            'candidateOnly': True,
            'finalTestRead': False,
            'preFitDiagnostics': {'parameters': {'threshold': 0.5}},
        }
        subject = {k: v for k, v in plan.items()
                   if k not in ('planSha256', '_health', 'preFitDiagnostics')}
        subject['preFitParameters'] = plan['preFitDiagnostics']['parameters']
        subject_sha = hashlib.sha256(json.dumps(
            subject, sort_keys=True, separators=(',', ':'), ensure_ascii=False
        ).encode()).hexdigest()
        directory = tempfile.mkdtemp(prefix='p3-prefix-contract-')
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        root = Path(directory)
        plan_path = root / 'plan.json'
        report_path = root / 'report.json'
        plan_path.write_text(json.dumps(plan), encoding='utf-8')
        report = {
            'status': status,
            'blockers': blockers,
            'modelFits': 0,
            'finalTestRead': False,
            'runtimeSubjectSha256': subject_sha,
            'runtimePlanSha256': hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            'decisionVersion': 'decision/test',
            'evaluationVersion': 'evaluation/test',
            'diagnosticOnly': True,
            'candidateOnly': True,
            'automaticExecutionAuthorized': False,
            'blockerClasses': {'structuralOrImplementation': [], 'collectionRepairable': list(blockers)},
        }
        if mutate:
            mutate(report, plan)
        report_path.write_text(json.dumps(report), encoding='utf-8')
        return plan_path, report_path

    def test_missing_role_cannot_fall_back_to_split(self):
        for row in ({}, {'split':'independent_development'}, {'plannedRole':'final_test'}):
            with self.assertRaises(ValueError): planned_role(row)

    def test_merge_conflict_must_not_reassign_to_training(self):
        with self.assertRaises(ValueError): sole_role([{'plannedRole':'train'},{'plannedRole':'validation_calibration'}])

    def test_public_role_and_behavior_are_separate_from_source(self):
        row=metadata(dict(plannedRole='train',scenario='cic2017_slowhttptest',sourceId='cic2017_corrected'))
        self.assertEqual(row['behaviorScenario'],'slowhttptest')
        self.assertEqual(row['originalScenario'],'cic2017_slowhttptest')
        with self.assertRaises(ValueError): metadata(dict(row,plannedRole='independent_development',split='independent_development'))

    def test_changed_tail_does_not_create_independent_early_evidence(self):
        vectors={'short':[(1,[1,2]),(5,[5,4])],
                 'long':[(1,[1,2]),(5,[5,4]),(15,[15,100])],
                 'distinct':[(1,[1,9]),(5,[5,10])]}
        edges=early_edges(vectors,dict(short='a',long='b',distinct='c'))
        self.assertTrue(any(left=='a' and right=='b' for left,right,_ in edges))
        self.assertFalse(any('c' in (left,right) for left,right,_ in edges))

    def test_repeated_same_second_snapshots_are_not_an_early_trajectory(self):
        vectors={'repeated':[(1,[1,2]),(1,[1,2])],
                 'progressed':[(1,[1,2]),(1,[1,2]),(10,[10,4])],
                 'other':[(1,[1,2]),(10,[10,4])]}
        edges=early_edges(vectors,dict(repeated='a',progressed='b',other='c'))
        self.assertFalse(any('a' in (left,right) for left,right,_ in edges))
        self.assertTrue(any(left=='b' and right=='c' for left,right,_ in edges))

    def test_short_common_trajectory_merges_all_previously_seen_branches(self):
        sequences={'a':[(1,[1,2]),(5,[5,4]),(10,[10,10])],
                   'b':[(1,[1,2]),(5,[5,4]),(10,[10,20])],
                   'z':[(1,[1,2]),(5,[5,4])]}
        edges=early_edges(sequences,dict(a='a',b='b',z='z'))
        self.assertIn(('a','z',10),edges)
        self.assertIn(('b','z',10),edges)

    def test_collection_gate_allows_data_completion_blockers_only(self):
        plan_path, report_path = self._gate_files([
            'ROLE_MISSING_CLASS:validation_calibration:1',
            'AUTHENTICATED_CONTINUOUS_HEALTH_UNAVAILABLE',
        ])
        collection_gate(plan_path, report_path)

    def test_collection_gate_rejects_structural_policy_blocker(self):
        plan_path, report_path = self._gate_files([
            'REGISTERED_POLICY_GRID_STRUCTURALLY_UNREACHABLE:cic2018_corrected',
        ])
        with self.assertRaisesRegex(ValueError, '不可由补采修复'):
            collection_gate(plan_path, report_path)

    def test_collection_gate_rejects_action_horizon_and_handoff_failures(self):
        for blocker in ('ACTION_HORIZON_SOURCE_REACHABILITY_BELOW_80_PERCENT:taara_publisher',
                        'HANDOFF_SOURCE_CONTINUITY_BELOW_80_PERCENT:cic2018_corrected',
                        'HIGH_SCORE_SOURCE_REACHABILITY_BELOW_80_PERCENT:cic2018_corrected'):
            plan_path, report_path = self._gate_files([blocker])
            with self.assertRaisesRegex(ValueError, '不可由补采修复'):
                collection_gate(plan_path, report_path)

    def test_collection_gate_rejects_structural_class_even_if_listed_repairable(self):
        def hide(report, _plan):
            report['blockerClasses']['structuralOrImplementation'] = ['REGISTERED_POLICY_GRID_STRUCTURALLY_UNREACHABLE:x']
        plan_path, report_path = self._gate_files(['ROLE_MISSING_CLASS:validation_calibration:1'], mutate=hide)
        with self.assertRaisesRegex(ValueError, '根因分类'):
            collection_gate(plan_path, report_path)

    def test_collection_gate_requires_bound_plan_and_versions(self):
        def break_binding(report, _plan):
            report['runtimePlanSha256'] = 'wrong'
        plan_path, report_path = self._gate_files([], status='passed', mutate=break_binding)
        with self.assertRaisesRegex(ValueError, '哈希/零拟合'):
            collection_gate(plan_path, report_path)


if __name__=='__main__': unittest.main()
