"""收口的来源资格与跨端证据绑定；只读取合成文件。"""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from closeout import closeout
from metrics import CLASSES, report, source_eligibility, gates_and_eligibility
from runtime import compare, read, sha, write


class CloseoutTest(unittest.TestCase):
    def test_synthetic_closeout_and_tampered_source_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, remote, l3, candidate = [root / name for name in ('run', 'remote', 'l3', 'candidate')]
            bundle = run / 'runtime-bundle'
            for path in (bundle, remote, l3, candidate):
                path.mkdir(parents=True)
            for name in ('checksums.json', 'model-manifest.json', 'evaluation-plan.json', 'decision-policy.json'):
                write(candidate / name, {'synthetic': name})
            (bundle / 'model.onnx').write_bytes(b'synthetic')
            output = np.array([[.99, .99, 0, 0, 0]], np.float32)
            np.save(bundle / 'mac-output.npy', output)
            np.save(remote / 'output.npy', output)
            thresholds = {family: .9 for family in CLASSES[1:]}
            policy = {'familyPolicies': [{'family': f, 'alertThreshold': .9} for f in CLASSES[1:]], 'rulePolicies': []}
            plan = {'evaluationVersion': 'host-guard-evaluation/synthetic-2', 'candidateSha256': sha(bundle / 'model.onnx'),
                'testDatasetSha256': 'a' * 64, 'evaluationIds': ['synthetic-1', 'synthetic-2', 'synthetic-3'],
                'gates': {'G1': {'attackDetectionMin': .9, 'falsePositiveRateMax': .02}, 'G2': {'macroF1Min': .8}},
                'automaticEligibility': {'recallMin': .8, 'precisionMin': .9}}
            registration = {'layer': 'L1', 'evaluationVersion': plan['evaluationVersion'], 'evaluationId': 'synthetic-1',
                'candidate': str(candidate), 'candidateChecksumsSha256': sha(candidate / 'checksums.json'),
                'evaluationPlanSha256': sha(candidate / 'evaluation-plan.json'),
                'modelManifestSha256': sha(candidate / 'model-manifest.json'),
                'decisionPolicySha256': sha(candidate / 'decision-policy.json'), 'datasetSha256': 'a' * 64,
                'codeSha256': {'scripts/p6/runtime.py': 'b' * 64}}
            write(run / 'registration.json', registration)
            write(run / 'registration-receipt.json', {'sha256': sha(run / 'registration.json')})
            metrics = report([0, 0, 1, 2, 3, 4], [0, 0, 1, 2, 3, 4],
                             ['internal', 'website'] + ['internal'] * 4, ['s'] * 6, l1=True)
            gates, _ = gates_and_eligibility(metrics, plan)
            eligibility = source_eligibility(metrics, {}, policy, plan)
            result = {'layer': 'L1', 'version': plan['evaluationVersion'], 'evaluationId': 'synthetic-1',
                'registrationSha256': sha(run / 'registration.json'), 'modelSha256': plan['candidateSha256'],
                'datasetSha256': 'a' * 64, 'evaluationPlanSha256': registration['evaluationPlanSha256'],
                'modelManifestSha256': registration['modelManifestSha256'],
                'decisionPolicySha256': registration['decisionPolicySha256'], 'platform': 'Darwin',
                'modelOnly': metrics, 'ruleOnlyById': {}, 'gates': gates, 'classEligibility': eligibility,
                'sourceEligibility': {f: {'model': v['modelOnly'], 'rules': v['ruleOnly']} for f, v in eligibility.items()},
                'frameworkParity': {'passed': True}, 'testEvaluationsUsed': 2}
            write(run / 'report.json', result)
            write(bundle / 'runtime-bundle.json', {'evaluationId': 'synthetic-1', 'alertThreshold': thresholds,
                'files': {name: sha(bundle / name) for name in ('model.onnx', 'mac-output.npy')}})
            write(remote / 'runtime-report.json', compare(output, output, thresholds) | {
                'bundleSha256': sha(bundle / 'runtime-bundle.json'), 'runtimeCodeSha256': 'b' * 64,
                'modelSha256': result['modelSha256'], 'outputSha256': sha(remote / 'output.npy'), 'platform': 'Windows'})
            l3_registration = registration | {'layer': 'L3', 'evaluationId': 'synthetic-l3', 'datasetSha256': 'c' * 64}
            write(l3 / 'registration.json', l3_registration)
            write(l3 / 'registration-receipt.json', {'sha256': sha(l3 / 'registration.json')})
            write(l3 / 'report.json', result | {'layer': 'L3', 'evaluationId': 'synthetic-l3',
                'datasetSha256': 'c' * 64, 'registrationSha256': sha(l3 / 'registration.json')})
            with patch('closeout.checked_candidate', return_value=({}, plan, {}, policy, {})):
                final = closeout(run, remote, l3, root / 'final.json')
                self.assertTrue(final['completed'])
                self.assertFalse(final['automaticExecutionEnabled'])
                result['classEligibility']['port_scan']['modelOnly']['offlineEligible'] = False
                (run / 'report.json').write_text(json.dumps(result))
                with self.assertRaises(ValueError):
                    closeout(run, remote, l3, root / 'tampered.json')


if __name__ == '__main__':
    unittest.main()
