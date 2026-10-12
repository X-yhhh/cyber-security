"""P5 运行前冻结的发布 subject；只验证执行配置，不授予模型或类别资格。"""
from pathlib import Path
import os
from .common import digest, parse, require

SUBJECT_FIELDS=set('contractVersion protocolVersions modelId manifestSha256 policyId policySha256 featureProfileSha256 extractorSha256 evaluationPlanSha256 capabilityIds environment'.split())


def validate(value):
    """完整 JCS 与显式 bundle ID 一并绑定；拒绝事后只提供一个摘要。"""
    require(isinstance(value,dict) and set(value)=={'bundleId','subject','subjectSha256'},'REPORT_SUBJECT_BINDING_INVALID')
    subject=value['subject']
    require(isinstance(subject,dict) and set(subject)==SUBJECT_FIELDS and subject['environment']=='lab'
            and isinstance(subject['capabilityIds'],list) and subject['capabilityIds']
            and subject['capabilityIds']==sorted(set(subject['capabilityIds'])),'REPORT_SUBJECT_INVALID')
    require(digest(subject)==value['subjectSha256'],'REPORT_SUBJECT_MISMATCH')
    from uuid import UUID
    try: require(str(UUID(value['bundleId']))==value['bundleId'],'REPORT_SUBJECT_BINDING_INVALID')
    except (ValueError,TypeError,AttributeError):require(False,'REPORT_SUBJECT_BINDING_INVALID')
    return value


def configured():
    """root 启动器只设置已纳入逐文件清单的副本路径；旧 P5 无绑定仍可运行但不能出 K6 报告。"""
    path=os.environ.get('HOSTGUARD_SUBJECT_BINDING')
    return validate(parse(Path(path).read_bytes())) if path else None


def verify_config(binding, config):
    """证明这次执行器实际限制到指定组合、策略和能力，不把标签粘到无关运行上。"""
    if binding is None:return None
    validate(binding);subject=binding['subject']
    require(config['environment']=='lab' and config['bundleIds']==[binding['bundleId']]
            and config['policyHashes']==[subject['policySha256']]
            and config['capabilityIds'] and set(config['capabilityIds'])<=set(subject['capabilityIds']),
            'REPORT_RUNTIME_SUBJECT_MISMATCH')
    return dict(subjectSha256=binding['subjectSha256'],bundleId=binding['bundleId'],
                policySha256=subject['policySha256'],capabilityIds=sorted(config['capabilityIds']),
                verifiedBeforeExecution=True)
