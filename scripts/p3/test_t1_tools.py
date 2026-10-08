"""T1 新冻结链与单对端工具回归；只使用合成开发数据及 ONNX。"""
import argparse
import contextlib
import io
import json
import shutil
from pathlib import Path
import tempfile
import unittest
import uuid

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

import freeze_multiclass_candidate as freeze
from single_peer_check import check
from evaluate import checked_candidate, numeric_indices, model_decisions
from metrics import report, source_eligibility
from runtime import read, sha, write
from multiclass_common import PLAN


def graph(path, index=0, divisor=1, categorical_type=TensorProto.INT64):
    """按指定数值列输出 attack_score，四家族等分；保留真实 43+3 输入接口。"""
    inputs = [helper.make_tensor_value_info(name, kind, ['N', width]) for name, kind, width in
              [('numeric_values', TensorProto.FLOAT, 43), ('numeric_missing', TensorProto.FLOAT, 43),
               ('categorical_codes', categorical_type, 3)]]
    nodes = [helper.make_node('Gather', ['numeric_values', 'index'], ['value'], axis=1),
             helper.make_node('Div', ['value', 'divisor'], ['attack_score']),
             helper.make_node('Div', ['attack_score', 'four'], ['family']),
             helper.make_node('Concat', ['family'] * 4, ['family_scores'], axis=1)]
    constants = [numpy_helper.from_array(np.array([index], np.int64), 'index'),
                 numpy_helper.from_array(np.array([divisor], np.float32), 'divisor'),
                 numpy_helper.from_array(np.array([4], np.float32), 'four')]
    outputs = [helper.make_tensor_value_info('attack_score', TensorProto.FLOAT, ['N', 1]),
               helper.make_tensor_value_info('family_scores', TensorProto.FLOAT, ['N', 4])]
    model = helper.make_model(helper.make_graph(nodes, 'synthetic', inputs, outputs, constants),
                              opset_imports=[helper.make_opsetid('', 17)])
    model.ir_version = 10
    onnx.save(model, path)


class T1ToolsTest(unittest.TestCase):
    def fixture(self, root):
        feature = read(freeze.ROOT / 'docs/contracts/feature-profile.json')
        source, frozen, audit = [root / name for name in ('source', 'frozen', 'audit')]
        for path in (source, frozen, audit):
            path.mkdir()
        rows = []
        for label in freeze.CLASSES:
            features = {name.split('.')[1]: 1 for name in feature['numericFeatures'] if name.startswith('features.')}
            contexts = [{'windowSeconds': w, **{name.split('.')[2]: 10 if name.endswith('hostDistinctPeers') else 1
                         for name in feature['numericFeatures'] if name.startswith(f'contexts.{w}.')}} for w in (1, 5, 30)]
            rows.append({'label': label, 'parentConnectionId': str(uuid.uuid4()), 'input': {
                'features': features, 'contexts': contexts, 'transport': 'tcp', 'direction': 'inbound', 'serviceClass': 'web'}})
        hashes, artifacts = {}, {}
        for role in ('train', 'validation'):
            (frozen / role).mkdir()
            (frozen / role / 'dataset.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            hashes[role] = sha(frozen / role / 'dataset.jsonl')
            np.save(source / f'framework-{role}.npy', np.tile([0, .25, .25, .25, .25], (5, 1)))
            artifacts[f'framework-{role}.npy'] = sha(source / f'framework-{role}.npy')
        # test 只有元数据哈希，故任何实际读取都会失败。
        hashes['test'] = 'a' * 64
        (frozen / 'split-ledger.jsonl').write_text('{}\n')
        write(frozen / 'manifest.json', {'finalTestRead': False, 'classOrder': list(freeze.CLASSES),
            'datasetSha256': hashes, 'splitLedgerSha256': sha(frozen / 'split-ledger.jsonl'),
            'classMappingVersion': 'synthetic/1', 'labelRuleVersion': 'synthetic/1'})
        graph(source / 'model.onnx')
        pre = {'fitRole': 'train', 'featureSet': 'no_host_context', 'includeServiceClass': True,
            'numericIndices': numeric_indices('no_host_context', feature), 'vocabularies': [['tcp'], ['inbound'], ['web']],
            'meanLog': [0] * 43, 'scaleLog': [1] * 43}
        write(source / 'preprocessing.json', pre)
        (source / 'native-model.txt').write_text('synthetic only')
        write(source / 'code-manifest.json', {'packages': {'lightgbm': 'synthetic'}})
        for name in ('model.onnx', 'preprocessing.json', 'native-model.txt'):
            artifacts[name] = sha(source / name)
        summary = {'finalTestRead': False, 'candidateOnly': True, 'fitCountAfter': 1, 'budget': 2, 'roundId': 'round-2',
            'frameworkParityPassed': True, 'validationExitPassed': True, 'datasetSha256': hashes,
            'artifacts': artifacts, 'featureSet': 'no_host_context', 'alertThreshold': .9,
            'codeManifestSha256': sha(source / 'code-manifest.json')}
        write(source / 'reproduction-summary.json', summary)
        write(audit / 'validation-report.json', {'modelSha256': artifacts['model.onnx'], 'newFits': 0,
            'finalTestRead': False, 'alertThreshold': .9})
        write(audit / 'verification.json', {'modelSha256': artifacts['model.onnx'], 'newFits': 0,
            'finalTestRead': False, 'candidateOnly': True, 'alertThreshold': .9, 'platformParityPassed': True,
            'validationExitPassed': True, 'alertMatchesWindows': True})
        for name in ('policy-preview.json', 'rules-comparison.json'):
            write(audit / name, {'researchOnly': True})
        plan = {'plan': PLAN, 'stage': 'P6', 'evaluationVersion': 'host-guard-evaluation/synthetic-2',
            'metricDefinitionSha256': sha(freeze.ROOT / 'docs/验证与验收.md'), 'statisticalUnit': 'parentConnection',
            'connectionDecision': 'first_snapshot_at_alert_threshold_then_argmax_family',
            'attackDetectionAggregation': 'equal_weight_four_attack_classes',
            'falsePositiveAggregation': 'equal_weight_internal_and_website_normal',
            'automaticEligibility': {'recallMin': .8, 'precisionMin': .9, 'requiresG3': True, 'sourceMode': 'model_and_each_rule'},
            'evaluationIds': ['synthetic-1', 'synthetic-2', 'synthetic-3'], 'maxTestEvaluations': 3,
            'repeatPolicy': 'pre-register changes', 'otherDatasets': {}, 'noTestReadBeforeP6': True,
            'gates': {'G1': {'attackDetectionMin': .9, 'falsePositiveRateMax': .02}, 'G2': {'macroF1Min': .8}}}
        write(root / 'plan.json', plan)
        scope = [{'addressFamily': 'ipv4', 'transport': 'tcp', 'direction': 'inbound', 'family': family,
                  'minimumCoverageMs': 1000, 'coverageWindowSeconds': 5} for family in freeze.CLASSES[1:]]
        write(root / 'scope.json', scope)
        (root / 'extractor').write_bytes(b'synthetic')
        args = argparse.Namespace(source=source, frozen=frozen, audit=audit, extractor=root / 'extractor',
            plan=root / 'plan.json', scope=root / 'scope.json', output=root / 'prepared',
            source_sha256=artifacts['model.onnx'], model_version='synthetic-only', training_run_id=str(uuid.uuid4()))
        return args, feature

    def test_prepare_seal_current_schemas_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp) / '.cache'
            root.mkdir()
            args, _ = self.fixture(root)
            proof = check(args.source, args.frozen / 'validation/dataset.jsonl', root / 'single-peer')
            self.assertTrue(proof['passed'])
            freeze.prepare(args)
            self.assertFalse((args.output / 'decision-policy.json').exists())
            with self.assertRaises((ValueError, FileNotFoundError)):
                checked_candidate(args.output)
            manifest = read(args.output / 'model-manifest.json')
            self.assertEqual(manifest['contractVersion'], 'host-guard/5.0.0-rc.3')
            listing = read(args.output / 'checksums.json')
            self.assertNotIn('model-manifest.json', listing['files'])
            record = read(args.output / 'freeze-record.json')
            self.assertEqual(record['featureSet'], 'no_host_context')
            self.assertEqual(record['hostContextFields'], [])
            self.assertEqual(len(record['excludedHostContextFields']), 6)
            self.assertEqual(record['fitCount'], 1)
            self.assertEqual(record['modelManifestSha256'], sha(args.output / 'model-manifest.json'))
            policy = read(freeze.ROOT / 'docs/contracts/examples/decision-policy.json')
            policy.update(modelId=manifest['modelId'], evaluationPlanSha256=sha(args.output / 'evaluation-plan.json'), alertThreshold=.9)
            for item in policy['familyPolicies']:
                item['alertThreshold'] = .9
            write(root / 'policy.json', policy)
            sealing = argparse.Namespace(prepared=args.output, policy=root / 'policy.json',
                single_peer_report=root / 'single-peer/report.json', output=root / 'sealed')
            freeze.seal(sealing)
            checked_candidate(sealing.output)
            manifest_copy = root / 'manifest-tamper'
            shutil.copytree(sealing.output, manifest_copy)
            value = read(manifest_copy / 'model-manifest.json')
            value['modelVersion'] = 'tampered'
            (manifest_copy / 'model-manifest.json').write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, '绑定不符'):
                checked_candidate(manifest_copy)
            # P6 入口独立复核单对端证据：删除或篡改后即使重算清单也拒绝。
            for name, edit in (("missing", None), ("failedDrop", lambda v: v["dropByClass"].update(dos_flood=.21)),
                               ("otherModel", lambda v: v.update(candidateSha256="c" * 64))):
                with self.subTest(singlePeer=name):
                    copied = root / ("single-peer-" + name)
                    shutil.copytree(sealing.output, copied)
                    if edit is None:
                        (copied / 'single-peer-report.json').unlink()
                    else:
                        proof = read(copied / 'single-peer-report.json')
                        edit(proof)
                        (copied / 'single-peer-report.json').unlink()
                        write(copied / 'single-peer-report.json', proof)
                    (copied / 'checksums.json').write_text(json.dumps(freeze.checksums(copied)))
                    with self.assertRaisesRegex(ValueError, "缺少必需文件|单对端"):
                        checked_candidate(copied)
            # 改策略并重算清单也不能绕过计划绑定及 Schema 校验。
            policy['evaluationPlanSha256'] = 'b' * 64
            (sealing.output / 'decision-policy.json').write_text(json.dumps(policy))
            (sealing.output / 'checksums.json').write_text(json.dumps(freeze.checksums(sealing.output)))
            with self.assertRaises(ValueError):
                checked_candidate(sealing.output)
            with self.assertRaises(ValueError):
                checked_candidate(sealing.output, legacy=True)

    def test_actual_single_peer_drop_and_float_categorical_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / '.cache'
            root.mkdir()
            args, feature = self.fixture(root)
            index = feature['numericFeatures'].index('contexts.5.hostDistinctPeers')
            for kind in (TensorProto.INT64, TensorProto.FLOAT):
                graph(args.source / 'model.onnx', index=index, divisor=10, categorical_type=kind)
                summary = read(args.source / 'reproduction-summary.json')
                summary['artifacts']['model.onnx'] = sha(args.source / 'model.onnx')
                (args.source / 'reproduction-summary.json').write_text(json.dumps(summary))
                if kind == TensorProto.FLOAT:
                    with self.assertRaises(ValueError):
                        check(args.source, args.frozen / 'validation/dataset.jsonl', root / 'float-rejected')
                else:
                    proof = check(args.source, args.frozen / 'validation/dataset.jsonl', root / 'drop')
                    self.assertFalse(proof['passed'])
                    self.assertEqual(set(proof['dropByClass'].values()), {1.0})

    def test_plan_requires_current_source_semantics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            args, _ = self.fixture(root)
            plan = read(args.plan)
            freeze.check_plan(plan)
            for changed in (plan | {'decisionPolicySha256': 'a' * 64}, plan | {'evaluationIds': ['x'] * 3},
                            plan | {'evaluationVersion': 'host-guard-evaluation/2026-10-07.1'},
                            plan | {'plan': 'p3-multiclass-renamed'}):
                with self.assertRaises(ValueError):
                    freeze.check_plan(changed)

    def test_duplicate_identical_opsets_normalized_conflicts_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source.onnx'
            graph(source)
            model = onnx.load(source)
            model.opset_import.add(domain='', version=17)
            onnx.save(model, source)
            freeze.converted_model(source, root / 'normalized.onnx')
            actual = onnx.load(root / 'normalized.onnx')
            self.assertEqual([(x.domain, x.version) for x in actual.opset_import], [('', 17)])
            model.opset_import.add(domain='', version=15)
            onnx.save(model, source)
            with self.assertRaisesRegex(ValueError, '冲突 opset'):
                freeze.converted_model(source, root / 'rejected.onnx')

    def test_each_rule_and_model_use_independent_metrics(self):
        labels = [0, 0, 1, 2, 3, 4]
        sources = ['internal', 'website'] + ['internal'] * 4
        good = report(labels, labels, sources, ['s'] * 6, l1=True)
        bad = report(labels, [0] * 6, sources, ['s'] * 6, l1=True)
        policy = {'rulePolicies': [{'ruleId': name, 'family': 'port_scan'} for name in ('good', 'bad')]}
        plan = {'gates': {'G1': {'attackDetectionMin': .9, 'falsePositiveRateMax': .02}, 'G2': {'macroF1Min': .8}},
                'automaticEligibility': {'recallMin': .8, 'precisionMin': .9}}
        values = source_eligibility(bad, {'good': good, 'bad': bad}, policy, plan)['port_scan']
        self.assertFalse(values['modelOnly']['offlineEligible'])
        self.assertTrue(values['ruleOnly']['good']['offlineEligible'])
        self.assertFalse(values['ruleOnly']['bad']['offlineEligible'])
        scores = np.array([[.85, 0, .85, 0, 0]])
        self.assertEqual(model_decisions(scores, {'alertThreshold': .1,
            'familyPolicies': [{'family': 'brute_force', 'alertThreshold': .9}]}).tolist(), [0])


if __name__ == '__main__':
    unittest.main()
