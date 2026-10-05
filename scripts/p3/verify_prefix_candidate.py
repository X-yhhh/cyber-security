#!/usr/bin/env python3
"""Mac/Windows相同的prefix候选推理验收；校验完整绑定后实际运行ONNX全量对拍。

仅接受candidateOnly/alert_only的本轮prefix制品；错误显式失败，不切换旧模型。
该工具验证推理与组合完整性，不能授予防火墙权限或证明OS动作时效。
"""
import argparse
import json
from pathlib import Path
import platform

import numpy as np

from package_candidate import verify
from verify_prefix_corpus import read, sha


def verify_candidate(root, expected_model_sha=None):
    """拒绝final模型、外部张量/缺失mask错配、模型策略profile不一致及阈值翻转。"""
    root = Path(root).resolve()
    result = verify(root); candidate = root / 'candidate'
    manifest = read(candidate / 'model-manifest.json'); policy = read(candidate / 'decision-policy.json')
    if manifest['profiles'] != ['flow-prefix-v1'] or policy['profile'] != 'flow-prefix-v1':
        raise ValueError('本入口只接受新prefix候选，旧final验收不可代替')
    if expected_model_sha is not None and sha(candidate / 'model.onnx') != expected_model_sha:
        raise ValueError('传输的模型身份不符')
    for key, file in [('artifactSha256', 'model.onnx'), ('featureProfileSha256', 'feature-profile.json'),
                      ('preprocessingSha256', 'preprocessing.json'), ('calibrationSha256', 'calibration.json')]:
        if manifest[key] != sha(candidate / file): raise ValueError('manifest文件绑定不符: ' + key)
    if manifest['validationReportSha256'] != sha(root / 'validation-report.json'):
        raise ValueError('模型评价报告绑定不符')
    plan = read(root / 'experiment-plan.json')
    if plan['finalTestRead'] is not False or plan['scope']['profile'] != 'flow-prefix-v1': raise ValueError('计划边界不符')
    for document in (manifest, policy):
        if document['evaluationPlanSha256'] != sha(root / 'experiment-plan.json'): raise ValueError('计划哈希不符')
    lock = read(root / 'pipeline-lock.json')
    if lock['pipelineFrozen'] is not True or lock['independentUsedForSelection'] is not False or lock['planSha256'] != sha(root / 'experiment-plan.json'):
        raise ValueError('pipeline锁无效')
    for name, digest in lock['files'].items():
        if name not in {'model.onnx', 'preprocessing.json', 'calibration.json', 'decision-parameters.json'} or sha(candidate / name) != digest:
            raise ValueError('pipeline已改变')
    if set(lock['files']) != {'model.onnx', 'preprocessing.json', 'calibration.json', 'decision-parameters.json'}: raise ValueError('pipeline锁不完整')
    params = read(candidate / 'decision-parameters.json')
    for key, param in [('autoThreshold','threshold'), ('minDistinctFlows','min_flows'), ('minEvidenceSpanMs','span_ms'), ('minPeerFlowStarts','min_starts'), ('maxTtlSeconds','ttl')]:
        if policy[key] != params[param]: raise ValueError('公开策略与实际冻结参数不符')
    import onnxruntime as ort
    options = ort.SessionOptions(); options.intra_op_num_threads = 2; options.inter_op_num_threads = 1
    options.enable_mem_pattern = False
    runtime = ort.InferenceSession(str(candidate / 'model.onnx'), sess_options=options, providers=['CPUExecutionProvider'])
    kinds = {'numeric_values':'tensor(float)', 'numeric_missing':'tensor(float)', 'categorical_codes':'tensor(int64)'}
    if {v.name:v.type for v in runtime.get_inputs()} != kinds or [v.name for v in runtime.get_outputs()] != ['attack_score']:
        raise ValueError('ONNX实际输入输出契约不符')
    with np.load(candidate / 'parity-fixture.npz', allow_pickle=False) as fixture:
        if set(fixture.files) != set(kinds) | {'expected'}: raise ValueError('对拍夹具键不符')
        feeds = {name: fixture[name] for name in kinds}; expected = fixture['expected'].reshape(-1)
        n = len(expected); k = len(manifest['numericFeatures']); c = len(manifest['categoricalFeatures'])
        if n == 0 or feeds['numeric_values'].shape != (n,k) or feeds['numeric_missing'].shape != (n,k) or feeds['categorical_codes'].shape != (n,c): raise ValueError('张量形状不符')
        if feeds['numeric_values'].dtype != np.float32 or feeds['numeric_missing'].dtype != np.float32 or feeds['categorical_codes'].dtype != np.int64: raise ValueError('张量类型不符')
        if not np.isfinite(feeds['numeric_values']).all() or np.any(feeds['numeric_values'] < 0) or not np.isin(feeds['numeric_missing'],[0,1]).all(): raise ValueError('数值或缺失mask不符')
        if np.any(feeds['numeric_values'][feeds['numeric_missing']==1] != 0): raise ValueError('缺失占位必须为零')
        pre = read(candidate / 'preprocessing.json')
        if pre['fitRole'] != 'train' or len(pre['vocabularies']) != c: raise ValueError('预处理拟合角色不符')
        for i,vocab in enumerate(pre['vocabularies']):
            if np.any(feeds['categorical_codes'][:,i] < 0) or np.any(feeds['categorical_codes'][:,i] > len(vocab)): raise ValueError('类别编码越界')
        actual = np.concatenate([runtime.run(['attack_score'], {name:value[i:i+4096] for name,value in feeds.items()})[0].reshape(-1) for i in range(0,n,4096)])
    if not np.isfinite(actual).all() or not np.isfinite(expected).all() or np.any((actual<0)|(actual>1)):
        raise ValueError('ONNX输出无效')
    maximum = float(np.max(np.abs(actual - expected)))
    flips = {key: int(np.count_nonzero((actual >= policy[key]) != (expected >= policy[key]))) for key in ('alertThreshold','autoThreshold')}
    if maximum > 1e-4 or any(flips.values()): raise ValueError('ONNX分数/阈值对拍失败')
    return dict(result, status='passed', platform=platform.system(), machine=platform.machine(),
                onnxruntime=ort.__version__, profile='flow-prefix-v1', rows=n, maxAbsError=maximum,
                decisionFlips=flips, actualInference=True, candidateOnly=True, automaticExecutionAuthorized=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expected-model-sha256')
    args = p.parse_args(); result = verify_candidate(args.run,args.expected_model_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream: json.dump(result,stream,indent=2); stream.write('\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
