"""用冻结组合收尾：复算全部开发角色、统一裁决，不重新拟合或搜索阈值/策略。"""
from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
import shutil
import uuid

from .data import Dataset, contract_validator, read, sha, write
from .regression import regression, stage_decision, frozen_inputs, verify_source
from .runner import environment, source_hash


def finalize(source, out, data_root, contracts, public):
    """创建独占的新候选包。旧报告、候选与失败目录不变，更新的元数据另存历史。"""
    source, out = verify_source(source), Path(out)
    original = read(source / 'validation-report.json')
    manifest = read(source / 'candidate/model-manifest.json')
    policy = read(source / 'candidate/decision-policy.json')
    for field, name in [('artifactSha256', 'candidate/model.onnx'),
                        ('preprocessingSha256', 'candidate/preprocessing.json'),
                        ('calibrationSha256', 'candidate/calibration.json'),
                        ('validationReportSha256', 'validation-report.json')]:
        if manifest[field] != sha(source / name):
            raise ValueError('既有制品绑定已变化')
    if original['export']['status'] != 'passed' or original['finalTestRead'] or not manifest['candidateOnly'] or policy['mode'] != 'alert_only':
        raise ValueError('源交付未通过导出或越过候选边界')
    shutil.copytree(source, out)
    history = out / 'audit-history' / sha(source / 'checksums.json')
    data = Dataset(data_root, contracts, public, read(source / 'experiment-plan.json'),
                   history / 'access-audit.jsonl')
    batches, raw, scores = frozen_inputs(source, data)
    winner_id = read(source / 'selection-lock.json')['experimentId']
    threshold = read(source / 'experiments' / winner_id / 'report.json')['workingPoint']['threshold']
    repaired = deepcopy(original)
    repaired['developmentRegression'] = regression(batches, raw, scores, threshold,
                                                   original['policySelection']['parameters'], history / 'private')
    repaired['policyBySource'] = repaired['developmentRegression']['workingPoints']['frozen_policy']['bySource']
    audit_sha, audit_files = source_hash(Path(__file__).parent)
    repaired['finalization'] = dict(method='fixed parameters; global replay then role/source/activity/scenario projection',
        trainingRepeated=False, calibrationRefit=False, selectionChanged=False, thresholdSearches=0,
        sourceValidationReportSha256=sha(source / 'validation-report.json'), evaluationCodeSha256=audit_sha,
        historicalModelMatrixPreserved=True, historicalE5SelectionExposure='validation_calibration')

    def replace(name, value):
        # 仅替换本次新复制目录中的报告；旧字节同时存在source和本次history，绝不删除源文件。
        target = out / name
        if target.exists():
            saved = history / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, saved)
            target.unlink()
        write(target, value)

    replace('validation-report.json', repaired)
    manifest['modelId'] = str(uuid.uuid4()); manifest['modelVersion'] = out.name
    manifest['validationReportSha256'] = sha(out / 'validation-report.json')
    policy['modelId'] = manifest['modelId']; policy['policyId'] = str(uuid.uuid4()); policy['policyVersion'] = out.name
    for name, value in [('model-manifest', manifest), ('decision-policy', policy)]:
        contract_validator(contracts, name).validate(value)
        replace('candidate/' + name + '.json', value)
    replace('finalization-code-manifest.json', {'sha256': audit_sha, 'files': audit_files})
    replace('finalization-environment.json', environment())
    decision = stage_decision(repaired, export_passed=repaired['export']['status'] == 'passed')
    decision.update(experimentCount=original['fullModelFits'], newModelFits=0, calibrationFits=0, thresholdSearches=0,
        candidateModelSha256=sha(out / 'candidate/model.onnx'), validationReportSha256=sha(out / 'validation-report.json'),
        trainingCodeSha256=original['trainingCodeSha256'], evaluationCodeSha256=audit_sha)
    replace('stage-exit.json', decision)
    # checksums本身不自引用；先归档旧清单，再计算包含历史材料的新清单。
    old_checksums = out / 'checksums.json'
    (history / 'checksums.json').parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(old_checksums, history / 'checksums.json'); old_checksums.unlink()
    write(old_checksums, {p.relative_to(out).as_posix(): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
    return dict(status='completed', stageGate=decision['status'], feasibilityStatus=decision['feasibilityStatus'],
                trainingRepeated=False, calibrationRefit=False, thresholdSearches=0,
                weightHashUnchanged=sha(source / 'candidate/model.onnx') == sha(out / 'candidate/model.onnx'))


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-run', 'output', 'dataset', 'contracts', 'public']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(finalize(args.source_run, args.output, args.dataset, args.contracts, args.public)))
