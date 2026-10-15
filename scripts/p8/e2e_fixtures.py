"""T1 专用合成夹具：沿用 GuardIntegrationTest 契约，仅连接 runner 拥有的随机库。

常量 ONNX 与自签评价只供界面回归，不代表模型成绩或平台资格。不启动执行器，
不领取命令；所有 SQL 初始化只允许 E2E_SCHEMA 的随机测试命名空间。
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from e2e_env import ROOT, Database, Human, owned_schema, private_json, require, uid

OBS = 'host-guard/5.0.0-rc.2'
HEALTH = 'host-guard-capture-health/1.0.0'
VERSIONS = dict(observation=OBS, decision='host-guard-decision/2026-10-08.1',
                evaluation='host-guard-evaluation/2026-10-08.1', health=HEALTH)
PROTECTION = dict(protectedBudgetTargetIds=[], protectedServicePorts=[22, 53, 3389])
KEY = 't1-fixture-runner'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def digest(value):
    return sha(rfc8785.dumps(value))


def now():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def write(root, name, value):
    path = root / name
    path.write_bytes(rfc8785.dumps(value))
    path.chmod(0o600)
    return dict(reportRef=name, sha256=sha(path.read_bytes()), runnerIdentity=KEY)


def signing_files(root):
    key = Ed25519PrivateKey.generate()
    (root / 'report-key.der').write_bytes(key.private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / 'report-key.der').chmod(0o600)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    write(root, 'trust.json', {KEY: base64.b64encode(public).decode()})
    write(root, 'protection.json', PROTECTION)


def signed(root, name, payload):
    key = serialization.load_der_private_key((root / 'report-key.der').read_bytes(), None)
    signature = base64.urlsafe_b64encode(key.sign(rfc8785.dumps(payload))).decode().rstrip('=')
    return write(root, name, dict(payload=payload, keyId=KEY, algorithm='Ed25519', signature=signature))


def constant_model():
    """纯 protobuf 构造与 Java GuardOnnxFixture 等价的 43+43+3 输入常量图。"""
    def varint(n):
        result = bytearray()
        while n > 127:
            result.append(n & 127 | 128)
            n >>= 7
        result.append(n)
        return bytes(result)
    def integer(k, n):
        return varint(k * 8) + varint(n)
    def field(k, data):
        return varint(k * 8 + 2) + varint(len(data)) + data
    def text(k, value):
        return field(k, value.encode())
    def value(name, typ, width):
        shape = field(1, integer(1, 1)) + field(1, integer(1, width))
        return text(1, name) + field(2, field(1, integer(1, typ) + field(2, shape)))
    def constant(name, numbers):
        tensor = integer(1, 1) + integer(1, len(numbers)) + integer(2, 1) + field(9, struct.pack('<' + 'f' * len(numbers), *numbers))
        return field(1, text(2, name) + text(4, 'Constant') + field(5, text(1, 'value') + integer(20, 4) + field(5, tensor)))
    graph = constant('attack_score', [.999]) + constant('family_scores', [0, 0, 0, .999]) + text(2, 't1-synthetic-only')
    for name, typ, width in [('numeric_values', 1, 43), ('numeric_missing', 1, 43), ('categorical_codes', 7, 3)]:
        graph += field(11, value(name, typ, width))
    graph += field(12, value('attack_score', 1, 1)) + field(12, value('family_scores', 1, 4))
    return integer(1, 8) + text(2, 't1-test-only') + field(7, graph) + field(8, integer(2, 17))


def catalog(base, accounts, root):
    """只登记 U4 的前置资源；发布申请、导入、封存、批准和激活交给浏览器。"""
    operator, reviewer = [Human(base).login(accounts[r]) for r in ('operator', 'reviewer')]
    ds = write(root, 'dataset.json', dict(datasetKey='t1-synthetic-' + uid(), version='fixture'))
    dataset = operator.v2('/datasets', dict(manifestRef=ds['reportRef'], manifestSha256=ds['sha256']))['id']
    plan = operator.v2('/evaluation-plans', dict(planKey='t1-plan-' + uid(), version='fixture', protocolVersions=VERSIONS,
        datasetRefs=[dataset], splitHashes=dict(train='1'*64, selection='2'*64, calibration='3'*64, development='4'*64),
        behaviorSourceScope=[dict(source='synthetic-fixture', behaviors=['slowloris', 'slowhttptest'])],
        scenarioMappingSha256='a'*64, labelTimelineSha256='a'*64, captureHealthSha256='a'*64,
        latencyRegistration=dict(maxMs=10000), metrics=dict(unit='episode'), budget=dict(maxSeconds=120), scenarioRefs=['synthetic']))
    profile = sha((ROOT / 'docs/contracts/feature-profile.json').read_bytes())
    (root / 'model.onnx').write_bytes(constant_model())
    write(root, 'preprocessing.json', dict(fitRole='train', vocabularies=[['tcp'], ['outbound'], ['web']]))
    write(root, 'calibration.json', dict(fitRole='calibration', kind='fixed-test-only'))
    manifest = json.loads((ROOT / 'docs/contracts/examples/model-manifest.json').read_text())
    model = uid()
    manifest.update(modelId=model, modelVersion='t1-synthetic', featureProfileSha256=profile, evaluationPlanSha256=plan['planSha256'])
    for scope in manifest['supportedScope']:
        scope['direction'] = 'outbound'
    for key, name in [('artifactSha256','model.onnx'), ('preprocessingSha256','preprocessing.json'), ('calibrationSha256','calibration.json')]:
        manifest[key] = sha((root / name).read_bytes())
    manifest['runtime']['runtimeVersion'] = '1.23.2'
    mf = write(root, 'manifest.json', manifest)
    operator.v2('/models', dict(manifestRef='manifest.json', manifestSha256=mf['sha256']))
    require(operator.v2('/models/' + model + '/validations', dict(validationProfileId='host-guard-onnx-v1'))['status'] == 'validated', 'FIXTURE_MODEL_INVALID')
    cap = dict(capabilityKey=uid(), version='t1-research', platform='macos', adapterVersion='fixture-1',
        addressFamily='ipv4', transport='tcp', direction='outbound', family='dos_slow', profile='flow-prefix-v1',
        behaviorScope=['slowloris','slowhttptest'], latencyLimits=dict(maxMs=10000), level='alert_only')
    proof = signed(root, 'research-capability.json', dict(passed=True, protocolVersions=VERSIONS, capability=copy.deepcopy(cap)))
    cap.update(evidenceRef=proof['reportRef'], evidenceSha256=proof['sha256'], runnerIdentity=KEY)
    capability = operator.v2('/capabilities', cap)['id']
    policy = json.loads((ROOT / 'docs/contracts/examples/decision-policy.json').read_text())
    policy.update(policyId=uid(), modelId=model, policyVersion='t1-research', mode='alert_only', minDistinctFlows=1,
        minEvidenceSpanMs=0, protectionSetSha256=digest(PROTECTION), evaluationPlanSha256=plan['planSha256'],
        family='dos_slow', rulePolicies=[], supportedCapabilityIds=[capability])
    for family in policy['familyPolicies']:
        family.update(autoEligible=False, modelAutoEligible=False)
    operator.v2('/decision-policies', policy)
    reviewer.v2('/decision-policies/' + policy['policyId'] + '/reviews', dict(decision='approve', reason='T1 合成只告警夹具'), 1)
    return dict(profile=profile, model=model, plan=plan['id'], planHash=plan['planSha256'], extractor=manifest['extractorSha256'],
        policy=policy['policyId'], policyDefinition=policy, versions=VERSIONS)


def report(root, data, request):
    return signed(root, 'report-' + uid() + '.json', dict(protocolVersions=VERSIONS,
        subjectSha256=request['subjectSha256'], evaluationPlanSha256=data['fixtures']['planHash'],
        runKind=request.get('kind', 'final'), passed=True))


def machine(base, path, credential, body):
    return Human(base).call('POST', '/api/v2/machine' + path, body, credential=credential)


def observe(base, f, fixture):
    at = now()
    config = fixture['configDefinition']
    boot = fixture.setdefault('boot', uid())
    machine(base, '/sensors/' + fixture['sensor'] + '/heartbeats', fixture['credential'],
        dict(bootId=boot, version='t1-synthetic', configHash=digest(config), lastSequence=0, clockSkewMs=0))
    health = dict(healthVersion=HEALTH, healthWindowId=uid(), assetId=fixture['asset'], sensorId=fixture['sensor'],
        captureScopeId=fixture['scope'], observerSessionId=uid(), sequence=1, intervalStart=stamp(at-timedelta(seconds=5)),
        intervalEnd=stamp(at), previousSha256=None, counterStart=dict(packetsSeen=0,kernelDrops=0,capacityDrops=0),
        counterEnd=dict(packetsSeen=0,kernelDrops=0,capacityDrops=0), captureGap=False, clockSkewMs=0,
        configSha256=digest(config), buildSha256='b'*64)
    machine(base, '/sensors/' + fixture['sensor'] + '/health-windows', fixture['credential'], health)
    observation = json.loads((ROOT / 'docs/contracts/examples/observation.json').read_text())
    parent = uid()
    observation.update(observationId=uid(), assetId=fixture['asset'], sensorId=fixture['sensor'], bootId=boot,
        captureScopeId=fixture['scope'], flowId=parent, parentConnectionId=parent, peerKey='d'*64,
        firstSeenAt=stamp(at-timedelta(seconds=5)), asOf=stamp(at), emittedAt=stamp(at),
        lastPacketAt=stamp(at-timedelta(milliseconds=1)), environment=fixture.get('environment','research'),
        targetRef=fixture.get('target'), targetExpiresAt=stamp(at+timedelta(seconds=13)) if fixture.get('target') else None)
    observation['features']['elapsedMs'] = 5000
    for context in observation['contexts']:
        context.update(coverageMs=min(5000, context['windowSeconds']*1000), peerFlowStarts=3)
    batch = dict(batchId=uid(), bootId=boot, sequence=1, configId=fixture['config'], contractVersion=OBS,
        profileSha256=f['profile'], observations=[observation])
    require(machine(base, '/sensors/' + fixture['sensor'] + '/observation-batches', fixture['credential'], batch)['acceptedCount'] == 1, 'OBSERVATION_NOT_ACCEPTED')
    return dict(observation=observation['observationId'], health=health['healthWindowId'])


def lab_action(base, data, root, db, schema):
    """构造经真实 gate 的合成 lab 动作，SQL 只把自动动作改为待人工审批以测试 UI。

    无执行器进程、无命令签名配置、无 claims。不得把此夹具视作网络隔离或 PF 证据。
    """
    admin, operator, reviewer = [Human(base).login(data['accounts'][r]) for r in ('admin','operator','reviewer')]
    f = data['fixtures']
    asset = admin.v2('/assets', dict(assetKey='t1-ui-lab-'+uid(), displayName='T1 合成处置资产', platform='macos', environment='lab', owner='synthetic-only'))['id']
    cap = dict(capabilityKey=uid(), version='t1-synthetic', platform='macos', adapterVersion='fixture-1', addressFamily='ipv4',
        transport='tcp', direction='outbound', family='dos_slow', profile='flow-prefix-v1',
        behaviorScope=['slowloris','slowhttptest'], latencyLimits=dict(maxMs=10000), level='lab_auto')
    signed_cap = signed(root, 'capability.json', dict(passed=True, protocolVersions=VERSIONS, capability=copy.deepcopy(cap)))
    cap.update(evidenceRef=signed_cap['reportRef'], evidenceSha256=signed_cap['sha256'], runnerIdentity=KEY)
    capability = operator.v2('/capabilities', cap)['id']
    at = now()
    auth = admin.v2('/assets/'+asset+'/authorizations', dict(interfaces=['lo0'], observationAllowed=True,
        executionScopes=[dict(scope='peer_service', direction='outbound', transport='tcp', servicePort=443, addressFamily='ipv4', capabilityId=capability)],
        validFrom=stamp(at-timedelta(seconds=60)), validUntil=stamp(at+timedelta(hours=1)), evidenceRef='synthetic:T1'))['id']
    reviewer.v2('/authorizations/'+auth+'/decisions', dict(decision='approve',reason='T1 合成数据'),1)
    scope = uid()
    sensor = admin.v2('/sensors',dict(assetId=asset, platform='macos',captureScopeId=scope))
    executor = admin.v2('/executors',dict(assetId=asset,platform='macos',capabilityProbeRef='synthetic:no-process'))
    config = dict(contractVersion=OBS,profileSha256=f['profile'],captureHealthVersion=HEALTH,interfaceIds=['lo0'],
        limits=dict(maxBatchSize=100),captureScopeId=scope,addressFamily='ipv4',buildSha256='b'*64)
    cid = admin.v2('/sensors/'+sensor['id']+'/configs',config)['id']
    reviewer.v2('/sensor-configs/'+cid+'/decisions',dict(decision='approve',reason='T1 合成配置'),1)
    policy = copy.deepcopy(f['policyDefinition'])
    policy.update(policyId=uid(),policyVersion='t1-lab',mode='auto',supportedCapabilityIds=[capability])
    for family in policy['familyPolicies']:
        if family['family']=='dos_slow':
            family.update(autoEligible=True,modelAutoEligible=True,minDistinctFlows=1)
    operator.v2('/decision-policies',policy)
    reviewer.v2('/decision-policies/'+policy['policyId']+'/reviews',dict(decision='approve',reason='T1 合成策略'),1)
    bundle = operator.v2('/release-bundles',dict(modelId=f['model'],policyId=policy['policyId'],featureProfileSha256=f['profile'],
        extractorSha256=f['extractor'],protocolVersions=VERSIONS,evaluationPlanId=f['plan'],capabilityIds=[capability],environment='lab'))
    reports=[]
    for kind in ('final','platform','canary'):
        reports.append(operator.v2('/release-bundles/'+bundle['id']+'/imports',report(root,data,dict(subjectSha256=bundle['subjectSha256'],kind=kind)))['id'])
    operator.v2('/release-bundles/'+bundle['id']+'/sealings',dict(evaluationIds=reports),1)
    reviewer.v2('/release-bundles/'+bundle['id']+'/decisions',dict(decision='approve',reason='T1 合成组合'),2)
    reviewer.v2('/release-bundles/'+bundle['id']+'/activations',dict(assetIds=[asset],authorizationIds=[auth]),3)
    eboot, boot, target = uid(), uid(), uid()
    cap_hash = digest([dict(capabilityId=capability,scope='peer_service',protectionSetSha256=None,protectedPortsSha256=None)])
    machine(base,'/sensors/'+sensor['id']+'/heartbeats',sensor['credential'],dict(bootId=boot,version='t1-synthetic',configHash=digest(config),lastSequence=0,clockSkewMs=0))
    machine(base,'/executors/'+executor['id']+'/heartbeats',executor['credential'],dict(bootId=eboot,adapterVersion='fixture-1',capabilityHash=cap_hash,pendingRecovery=False,activeRuleCount=0,clockSkewMs=0))
    normalized=dict(digestVersion='guard-state/1',assetId=asset,executorId=executor['id'],executorBootId=eboot,rules=[],pendingRevocations=[])
    machine(base,'/executors/'+executor['id']+'/reconciliations',executor['credential'],dict(executorBootId=eboot,observedAt=stamp(now()),digestVersion='guard-state/1',stateDigest=digest(normalized),ownedRules=[],pendingRevocations=[],recoveryErrors=[]))
    token=sha(uid().encode())
    machine(base,'/executors/'+executor['id']+'/target-bindings',executor['credential'],dict(bindingId=uid(),executorBootId=eboot,
        sensorId=sensor['id'],collectorBootId=boot,captureScopeId=scope,targetRef=target,peerKey='d'*64,keyEpoch=1,direction='outbound',
        transport='tcp',servicePort=443,addressFamily='ipv4',stableTargetToken=token,scopeDigest=sha(token.encode()),expiresAt=stamp(now()+timedelta(seconds=14))))
    observe(base,f,dict(asset=asset,sensor=sensor['id'],credential=sensor['credential'],scope=scope,config=cid,configDefinition=config,boot=boot,target=target,environment='lab'))
    deadline=time.monotonic()+8
    action=''
    while time.monotonic()<deadline:
        action=db.query("SELECT g.public_id FROM guard_action g JOIN asset a ON a.id=g.asset_id WHERE a.public_id='"+asset+"' LIMIT 1",schema)
        if action:
            break
        time.sleep(.1)
    require(action,'SYNTHETIC_ACTION_NOT_CREATED')
    db.query("UPDATE guard_action SET mode='manual',created_by=(SELECT id FROM sys_user WHERE username='demo-analyst') WHERE public_id='"+action+"'",schema)
    return dict(action=action,asset=asset,executor=executor['id'],eboot=eboot)


def receipt_fixture(db,schema,request):
    """只读展示种子：无有效命令签名，不经 claims，不可能被真实执行器领取。"""
    action=request['action']
    require(len(action)==36 and all(c in '0123456789abcdef-' for c in action),'INVALID_ACTION_ID')
    command,receipt=uid(),uid()
    payload=json.dumps(dict(synthetic=True,receiptId=receipt,status='revoked',ruleHandle='synthetic:no-firewall',errorCode=None))
    payload_hex=payload.encode().hex()
    db.query(f"INSERT INTO guard_command(public_id,action_id,executor_boot_id,payload_json,payload_sha256,key_id,signature,issued_at,apply_by,lease_expires_at) SELECT '{command}',id,UUID(),JSON_OBJECT('synthetic',true),REPEAT('0',64),'t1-ui-synthetic','not-a-valid-signature',NOW(6),DATE_ADD(NOW(6),INTERVAL 1 SECOND),DATE_ADD(NOW(6),INTERVAL 2 SECOND) FROM guard_action WHERE public_id='{action}';"
        f"INSERT INTO guard_action_receipt(public_id,command_id,executor_id,asset_id,status,observed_at,state_digest,content_sha256,payload_json,projected) SELECT '{receipt}',c.id,g.executor_id,g.asset_id,'revoked',NOW(6),REPEAT('0',64),REPEAT('0',64),CONVERT(0x{payload_hex} USING utf8mb4),false FROM guard_command c JOIN guard_action g ON g.id=c.action_id WHERE c.public_id='{command}';",schema)
    return dict(receipt=receipt)


def control():
    root=Path(os.environ['E2E_ARTIFACT_ROOT'])
    data=json.loads((root/'state.json').read_text())
    request=json.load(sys.stdin)
    op=request.pop('op')
    base=data['baseURL']
    if op=='report':
        result=report(root,data,request)
    elif op=='observe':
        result=observe(base,data['fixtures'],request)
    elif op in ('lab-action','receipt','assert-no-issued-command'):
        db=Database()
        schema=owned_schema(os.environ['E2E_SCHEMA'])
        if op=='lab-action':
            result=lab_action(base,data,root,db,schema)
        elif op=='receipt':
            result=receipt_fixture(db,schema,request)
        else:
            require(db.query("SELECT COUNT(*) FROM guard_command WHERE key_id<>'t1-ui-synthetic'",schema)=='0','REAL_COMMAND_ISSUED')
            result=dict(noIssuedCommands=True)
    else:
        raise RuntimeError('UNKNOWN_FIXTURE_OPERATION')
    print(json.dumps(result))


if __name__=='__main__':
    try:
        control()
    except Exception as error:
        print(str(error) if isinstance(error,RuntimeError) else 'E2E_FIXTURE_FAILED',file=sys.stderr)
        sys.exit(1)
