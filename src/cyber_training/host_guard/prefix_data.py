"""新prefix冻结入口；独立评价只能在完整pipeline锁落盘后读取，不改变旧final入口。"""
from collections import Counter
from pathlib import Path
import json

import numpy as np

from .data import Batch, contract_validator, read, sha, vector
from .prefix_corpus import ROLES, verify


class PrefixDataset:
    """数据哈希和准入从实际原件重算；缺组/未知真值/篡改导致拟合前拒绝。"""
    def __init__(self, root, contracts, plan, audit_path):
        self.root, self.contracts, self.audit_path = map(Path, (root, contracts, audit_path))
        self.plan = plan
        if plan.get('candidateOnly') is not True or plan.get('finalTestRead') is not False or plan['scope']['profile'] != 'flow-prefix-v1':
            raise ValueError('新prefix计划的候选/测试/profile边界不符')
        for path, digest in [(self.root / 'readiness.json', plan['datasetFreezeSha256']),
                             (self.contracts / 'docs/p2/freeze-manifest.json', plan['softwareFreezeSha256']),
                             (self.contracts / 'docs/contracts/feature-profile.json', plan['featureProfileSha256'])]:
            if sha(path) != digest: raise ValueError('冻结入口哈希不符: ' + path.name)
        frozen = read(self.contracts / 'docs/p2/freeze-manifest.json')
        for name, digest in frozen['files'].items():
            if sha(self.contracts / name) != digest: raise ValueError('冻结软件被修改')
        self.verification = verify(self.root, plan['scenarios'])
        self._audit('integrity_only', 'all_development_roles')
        if not self.verification['trainingAllowed']:
            raise ValueError('PREFIX_ADMISSION_BLOCKED:' + ','.join(self.verification['blockers']))
        self.profile = read(self.contracts / 'docs/contracts/feature-profile.json')
        schema = read(self.contracts / 'docs/contracts/model-manifest.schema.json')
        for name in ('numericFeatures', 'categoricalFeatures'):
            if self.profile[name] != schema['properties'][name]['const']: raise ValueError('profile输入顺序不符')
        self.validator = contract_validator(self.contracts, 'observation')
        self.loaded_roles = set()

    def _audit(self, operation, role):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(dict(operation=operation, role=role, finalTestRead=False)) + '\n')

    def load(self, role, lock=None):
        """校准锁绑定选型ONNX；独立评价锁绑定模型/预处理/校准/完整策略四项。"""
        if role not in ROLES: raise ValueError('禁止访问最终测试或未知角色')
        if role in ('validation_calibration', 'independent_development'):
            if lock is None: raise ValueError('该角色要求先冻结选择锁')
            frozen = read(lock)
            if frozen.get('planSha256') != self.plan['planSha256']: raise ValueError('选择锁计划哈希不符')
            if role == 'validation_calibration':
                if frozen.get('selectionFrozen') is not True or frozen.get('calibrationUsedForSelection') is not False:
                    raise ValueError('无效选型锁')
                artifact = Path(lock).parent / 'experiments' / frozen['experimentId'] / 'model.onnx'
                if sha(artifact) != frozen['artifactSha256']: raise ValueError('选型模型被修改')
            else:
                if frozen.get('pipelineFrozen') is not True or frozen.get('independentUsedForSelection') is not False:
                    raise ValueError('无效完整pipeline锁')
                if set(frozen['files']) != {'model.onnx', 'preprocessing.json', 'calibration.json', 'decision-parameters.json'}:
                    raise ValueError('完整pipeline锁缺少绑定项')
                for name, digest in frozen['files'].items():
                    if sha(Path(lock).parent / 'candidate' / name) != digest: raise ValueError('完整pipeline被修改')
        rows, observations, vals, masks, cats = [], [], [], [], []
        with (self.root / 'index.jsonl').open(encoding='utf-8') as a, (self.root / 'observations.jsonl').open(encoding='utf-8') as b:
            for left, right in zip(a, b, strict=True):
                row = json.loads(left)
                if row['split'] != role: continue
                observation = json.loads(right); self.validator.validate(observation)
                values, missing, categories = vector(observation, self.profile)
                rows.append(row); observations.append(observation); vals.append(values); masks.append(missing); cats.append(categories)
        if not rows or {r['label'] for r in rows} != {0, 1}: raise ValueError('角色缺少正负例')
        count = Counter(r['parentConnectionId'] for r in rows)
        rows = [dict(r, sampleWeight=1 / count[r['parentConnectionId']]) for r in rows]
        self._audit('load_features', role)
        self.loaded_roles.add(role)
        return Batch(rows, observations, np.asarray(vals), np.asarray(masks), np.asarray(cats), role)

    def timeline(self, roles):
        """正式分母由冻结标签时间线提供，不能用被保留/高分观察数替代。"""
        if not set(roles) <= set(ROLES): raise ValueError('禁止最终测试时间线')
        if not set(roles) <= self.loaded_roles: raise ValueError('该角色时间线须在选择锁验证后读取')
        with (self.root / 'label-timeline.jsonl').open(encoding='utf-8') as stream:
            return [r for line in stream if (r := json.loads(line))['split'] in roles]
