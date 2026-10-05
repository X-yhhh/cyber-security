"""P3 旁路元数据与共同早期轨迹规则；不改变 rc.2 特征，不提供默认角色。"""
import hashlib
import json
from pathlib import Path

ROLES = ('train', 'validation_selection', 'validation_calibration', 'independent_development')
MAPPING_VERSION = 'host-guard-behavior-map/1'
BEHAVIORS = {
    'cic2017_slowhttptest': 'slowhttptest', 'cic2018_slowloris': 'slowloris',
    'taara_slowloris': 'slowloris', 'controlled_slowloris': 'slowloris',
    'controlled_slowhttptest': 'slowhttptest', 'controlled_benign': 'benign',
}
PUBLIC_ROLES = {'cic2017_slowhttptest': 'train', 'cic2018_slowloris': 'validation_selection',
                'taara_slowloris': 'independent_development'}
EARLY_WINDOWS = (10, 30, 45, 60, 75, 90)

# P3-A 诊断可以在数据仍不完整时阻止拟合，但不能把代码、版本、策略
# 或完整性错误伪装成“再采集即可修复”。这些前缀只表示缺少本轮新采集
# 或持续健康旁证，真正的执行范围仍由采集脚本的授权校验决定。处置期
# 可达性、移交连续性和网格上界属于结构/实现阻断，不在此列。
COLLECTION_REPAIRABLE_BLOCKERS = (
    'AUTHENTICATED_CONTINUOUS_HEALTH_UNAVAILABLE',
    'ACTION_PHASE_PENDING_CAPTURE_HEALTH:',
    'CAPTURE_HEALTH_EMPTY',
    'CONTINUOUS_CAPTURE_HEALTH_NOT_BOUND',
    'INDEPENDENT_DEVELOPMENT_FEWER_THAN_FIVE_ATTACK_GROUPS',
    'INSUFFICIENT_INDEPENDENT_ATTACK_GROUPS',
    'LATENCY_REGISTRATION_MISSING',
    'P3_A_ROLE_BEHAVIOR_EARLY_TRAJECTORY_NOT_FROZEN',
    'ROLE_MISSING_CLASS:',
    'SCENARIO_NOT_PRESENT_IN_ALL_DEVELOPMENT_ROLES:',
    'CALIBRATION_ATTACK_MISSING',
    'BEHAVIOR_ROLE_COVERAGE_INCOMPLETE',
)


def planned_role(record):
    """角色必须由登记提供；split/role 不能隐式充当缺失 plannedRole 的替身。"""
    role = record.get('plannedRole')
    if role not in ROLES:
        raise ValueError('plannedRole 缺失或非法')
    if record.get('split', role) not in (role, 'development_unassigned'):
        raise ValueError('plannedRole 与 split 冲突')
    return role


def metadata(record):
    """保留原来源/场景；行为用于评价分层，所有字段都禁止进入特征张量。"""
    role = planned_role(record)
    original = record.get('originalScenario', record.get('scenario'))
    if original not in BEHAVIORS:
        raise ValueError('未登记的行为映射: ' + str(original))
    behavior = BEHAVIORS[original]
    if record.get('behaviorScenario', behavior) != behavior:
        raise ValueError('behaviorScenario 与原场景不符')
    if original in PUBLIC_ROLES and PUBLIC_ROLES[original] != role:
        raise ValueError('公共来源不得重新分派登记角色')
    source = record.get('sourceId')
    if not isinstance(source, str) or not source:
        raise ValueError('缺少来源身份')
    return dict(record, plannedRole=role, split=role, originalScenario=original,
                behaviorScenario=behavior, scenarioMappingVersion=MAPPING_VERSION,
                sourceDomainId=record.get('sourceDomainId', source),
                contextSourceId=record.get('contextSourceId', source))


def early_edges(parent_rows, parent_cohorts):
    """在共有的早期前缀上建立保守相关边；短序列与长序列的相同开头也归并。

    输入为已去身份的量化向量，第一项是 elapsedMs 的秒分箱。前缀树避免
    全部 parent 两两比较。每个窗口至少两条观察，尾部延长不会消除既有边。
    返回 cohort 边而非独立组数；调用方还须合并活动、完整 parent 和上下文。
    """
    edges = set()
    for window in EARLY_WINDOWS:
        tree = {}
        for parent, sequence in sorted(parent_rows.items()):
            vectors = [tuple(v) for _, v in sorted(sequence, key=lambda item: item[0])
                       if v[0] is not None and v[0] <= window]
            if len(vectors) < 2:
                continue
            cohort = parent_cohorts[parent]
            node = tree
            for vector in vectors:
                for prior in node.get('terminal', ()):
                    if prior != cohort: edges.add((*sorted((cohort, prior)), window))
                node.setdefault('descendant', set()).add(cohort)
                node = node.setdefault(vector, {})
            for prior in node.get('descendant', set()) | node.get('terminal', set()):
                if prior != cohort: edges.add((*sorted((cohort, prior)), window))
            node.setdefault('terminal', set()).add(cohort)
            node.setdefault('descendant', set()).add(cohort)
    return sorted(edges)


def sole_role(records):
    """相关组只能有一个预登记角色；冲突要求先重新登记，绝不自动改归 train。"""
    roles = {planned_role(r) for r in records}
    if len(roles) != 1:
        raise ValueError('归并后 plannedRole 冲突，须在拟合前重新登记完整组')
    return next(iter(roles))


def _subject_sha256(plan):
    """计算排除自引用字段后的运行计划主题哈希。"""
    subject = {k: v for k, v in plan.items()
               if k not in ('planSha256', '_health', 'preFitDiagnostics')}
    prefit = plan.get('preFitDiagnostics')
    if not isinstance(prefit, dict) or not isinstance(prefit.get('parameters'), dict):
        raise ValueError('采集计划缺少 preFitDiagnostics.parameters')
    subject['preFitParameters'] = prefit['parameters']
    return hashlib.sha256(json.dumps(
        subject, sort_keys=True, separators=(',', ':'), ensure_ascii=False
    ).encode()).hexdigest()


def _collection_repairable(reason):
    return any(reason == prefix or reason.startswith(prefix)
               for prefix in COLLECTION_REPAIRABLE_BLOCKERS)


def collection_gate(plan_path, report_path):
    """采集前核对 P3-A 出口，并允许受控补齐数据类阻断。

    ``blocked`` 仅在每个原因都能由新增登记活动或健康旁证修复时放行
    到采集脚本；策略网格不可达、哈希/版本不符和实现错误仍 fail-closed。
    授权由调用方的本轮范围登记验证；本门只负责阶段依赖，不制造授权。
    """
    plan = json.loads(Path(plan_path).read_text(encoding='utf-8'))
    report = json.loads(Path(report_path).read_text(encoding='utf-8'))
    digest = _subject_sha256(plan)
    reasons = report.get('blockers')
    if not isinstance(reasons, list) or any(not isinstance(r, str) or not r for r in reasons):
        raise ValueError('P3-A 诊断阻断原因缺失或格式非法')
    status = report.get('status')
    if status not in ('passed', 'blocked'):
        raise ValueError('P3-A 诊断状态不允许采集: ' + str(status))
    if status == 'passed' and reasons:
        raise ValueError('P3-A 诊断状态与阻断原因不一致')
    classes = report.get('blockerClasses')
    if (not isinstance(classes, dict) or set(classes) != {'structuralOrImplementation', 'collectionRepairable'}
            or classes['structuralOrImplementation']
            or sorted(set(classes['collectionRepairable'])) != sorted(set(reasons))):
        raise ValueError('P3-A 诊断未按根因分类或仍含结构/实现阻断')
    if status == 'blocked':
        rejected = [reason for reason in reasons if not _collection_repairable(reason)]
        if not reasons or rejected:
            detail = ','.join(rejected or reasons)
            raise ValueError('P3-A 仍有不可由补采修复的阻断: ' + detail)
    if (report.get('modelFits') != 0 or report.get('finalTestRead') is not False
            or report.get('runtimeSubjectSha256') != digest
            or report.get('runtimePlanSha256') != hashlib.sha256(Path(plan_path).read_bytes()).hexdigest()):
        raise ValueError('P3-A 诊断与运行计划哈希/零拟合边界不一致')
    versions = plan.get('versions', {})
    if (report.get('decisionVersion') != versions.get('decision')
            or report.get('evaluationVersion') != versions.get('evaluation')):
        raise ValueError('P3-A 决策/评价版本未绑定当前运行计划')
    if (report.get('diagnosticOnly') is not True
            or report.get('candidateOnly') is not True
            or report.get('automaticExecutionAuthorized') is not False):
        raise ValueError('P3-A 诊断越过候选或自动执行边界')
    if plan.get('candidateOnly') is not True or plan.get('finalTestRead') is not False:
        raise ValueError('采集计划候选边界不符')
