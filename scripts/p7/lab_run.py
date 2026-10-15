#!/usr/bin/env python3
"""冻结 lab v1.1 输入并运行真实后端/传感器的隔离 G3 演练。

rehearse 使用专用签名身份、随机 schema、真实模型与目标租约服务；
假想候选由后端 J1 判定器产生，全部真实执行门关闭。dry-run 以替身完成
生命周期和报告流程，不产生实测通过结论。每次尝试保留独立目录；恢复不重签或重置任何时钟。
"""
from __future__ import annotations
import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import re
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.request
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.p7 import j1_run, lab_report
from scripts.p7.j1_register import packet_records, tcp_tuple
from executor import pki
from executor.common import Rejected, canonical

UTC = timezone.utc
VERSION = "host-guard-lab/1.1"


def require(ok, code):
    if not ok:
        raise ValueError(code)


def load(path):
    return json.loads(Path(path).read_bytes())


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def uid():
    return str(uuid.uuid4())


def stamp():
    return datetime.now(UTC).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def at(micros):
    return (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=micros)).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(canonical(value) + b'\n')
    path.chmod(0o600)


def ensure_write(path, value):
    """恢复只接受原样重放，已有签名/报告不能被重签的新内容覆盖。"""
    path=Path(path)
    if path.exists():
        require(path.read_bytes()==canonical(value)+b'\n','LAB_RESUME_FILE_MISMATCH')
    else:write(path,value)


def freeze_scenarios(source, artifacts):
    """只接受已登记片段；逐一核验原件，保留采集/评分起点和原包间隔。"""
    require(source.get('schema') == 'g3-scenario/1', 'LAB_SOURCE_INVALID')
    seen, rows = set(), []
    for segment in source['segments']:
        name = segment['segmentId']
        require(name not in seen, 'LAB_SCENARIO_DUPLICATE')
        seen.add(name)
        pcap = (Path(artifacts) / segment['pcapRef']).resolve()
        require(pcap.is_relative_to(Path(artifacts).resolve()) and sha(pcap) == segment['pcapSha256'], 'LAB_PCAP_MISMATCH')
        capture, start, end = [segment[k] for k in ('captureStartUs', 'scoringFirstUs', 'scoringLastUs')]
        require(capture <= start < end, 'LAB_TIME_INVALID')
        rows.append(dict(scenarioId=name, family=segment['family'], source='model', ruleId=None,
                         trialAutoEligible=segment['family'] in source['plannedM2'],
                         autoIneligibleReason=None if segment['family'] in source['plannedM2'] else 'registered_alert_only',
                         pcapRef=segment['pcapRef'], pcapSha256=segment['pcapSha256'],
                         captureStart=at(capture), sourceStart=at(start), sourceEnd=at(end)))
    return rows


def clock_plan(rows, start, *, staggered=False):
    """冻结场景时钟；正式 G3 可显式错峰，既有 research/替身调用保持同时起算。

    port_scan、brute_force、dos_slow 各自占用独立的时间带；同一类别的三段
    也按 20 秒错开。normal 段每 60 秒启动一段，覆盖所有攻击带。这里只改变
    不可变的 scenarioOffsets，不改 PCAP、阈值或策略上限。
    """
    scoring_us = int(start.timestamp() * 1_000_000)
    family_base = {'port_scan': 0, 'brute_force': 120, 'dos_slow': 300, 'dos_flood': 480, 'normal': 0}
    family_index = {}
    offsets = {}
    for row in rows:
        family = row['family']
        index = family_index.get(family, 0)
        family_index[family] = index + 1
        delay = (family_base[family] + (60 if family == 'normal' else 20) * index) if staggered else 0
        desired = scoring_us + delay * 1_000_000
        offsets[row['scenarioId']] = desired - int(lab_report.timestamp(row['sourceStart']).timestamp() * 1_000_000)
    first = min(r['captureStart'] for r in rows)
    scoring_first = min(r['sourceStart'] for r in rows)
    last = max(r['sourceEnd'] for r in rows)
    base = scoring_us - int(lab_report.timestamp(scoring_first).timestamp()*1_000_000)
    return dict(sourceStart=first, labStart=lab_report.iso(lab_report.timestamp(first)+timedelta(microseconds=base)),
                offsetMicros=base, scenarioOffsets=offsets, warmupStart=first, scoringStart=scoring_first, scoringEnd=last)


def check_resume(state, directory, scenario_sha):
    """原身份、原文件和签名时钟都必须一致。只恢复收尾，不重新采集已丢失的引擎状态。"""
    require(state.get('schema') == 'guard-lab-run/1' and state.get('scenarioSha256') == scenario_sha, 'LAB_RESUME_BINDING_MISMATCH')
    for name, hashed in state.get('frozenFiles', {}).items():
        path = Path(name)
        require(path.is_absolute() and sha(path) == hashed, 'LAB_RESUME_FILE_MISMATCH')
    require(state.get('captureComplete') is True, 'LAB_CAPTURE_CONTINUITY_LOST')
    return state


def original_mapping(row, selection, artifacts):
    """从冻结 PCAP 的完整采集窗登记对端，包含预热；不增删或重写任何报文。

    selection 只列评分连接，不能拿它裁剪预热上下文。攻击段仍须单一已登记
    来源，正常段允许额外预热对端，各自分配独立 canary 和预算身份。
    """
    data=(Path(artifacts)/row['pcapRef']).read_bytes()
    require(hashlib.sha256(data).hexdigest()==row['pcapSha256'],'LAB_PCAP_MISMATCH')
    first=int(lab_report.timestamp(row['captureStart']).timestamp()*1_000_000)
    last=int(lab_report.timestamp(row['sourceEnd']).timestamp()*1_000_000)
    peers,ports=set(),set()
    for _,record in packet_records(data):
        if record is None:continue
        _,_,offset,size,when=record
        if not first<=when<=last:continue
        endpoints=tcp_tuple(data,offset,size)
        require(endpoints is not None,'LAB_ORIGINAL_MAPPING_MISMATCH')
        local=[endpoint for endpoint in endpoints if str(ipaddress.ip_address(endpoint[0]))==selection['host']]
        require(len(local)==1,'LAB_ORIGINAL_MAPPING_MISMATCH')
        peer=next(endpoint for endpoint in endpoints if endpoint!=local[0])
        peers.add(str(ipaddress.ip_address(peer[0])));ports.add(local[0][1])
    require(peers and ports and (row['family']=='normal' or peers=={selection['peer']}),'LAB_ORIGINAL_MAPPING_MISMATCH')
    return dict(host=selection['host'],peers=sorted(peers),ports=sorted(ports),port=min(ports))


R4_SUBJECT_SHA256 = 'f02022ba810357d9932e72474ca699253cecebbd3d9367e86694124f85ff9b43'


def subject_sha256(value):
    """期望 subject 必须显式匹配完整摘要，避免误用其他版本的组合。"""
    if not re.fullmatch(r'[0-9a-f]{64}', value):
        raise argparse.ArgumentTypeError('subject SHA-256 must contain 64 lowercase hex characters')
    return value


def formal_r4_preflight(db, bundle_id, expected_subject=R4_SUBJECT_SHA256):
    """只读核对业务库指定 subject 的激活状态与封存报告；默认仍为 r4。"""
    from scripts.p5.subject_report import REPORT_VERSION, check_execution_context
    try:
        require(str(uuid.UUID(bundle_id)) == bundle_id, 'LAB_PF_R4_NOT_ACTIVE')
    except (TypeError, ValueError) as error:
        raise ValueError('LAB_PF_R4_NOT_ACTIVE') from error
    rows = db.query("SELECT JSON_OBJECT('status',status,'environment',environment,"
                    "'subjectSha256',subject_sha256,'sealedSha256',sealed_manifest_sha256,"
                    "'sealed',sealed_manifest_json,'approvedBy',approved_by) "
                    "FROM guard_release_bundle WHERE public_id='" + bundle_id + "'", 'cyber_security').decode().splitlines()
    require(len(rows) == 1, 'LAB_PF_R4_NOT_ACTIVE')
    try:
        bundle = json.loads(rows[0])
        subject_sha = bundle['subjectSha256']
        sealed = bundle['sealed']
        require(bundle['status'] == 'active' and bundle['environment'] == 'lab'
                and bundle['approvedBy'] is not None and subject_sha == expected_subject
                and isinstance(sealed, dict) and bundle['sealedSha256'] == digest(sealed)
                and sealed['subjectSha256'] == subject_sha and isinstance(sealed['reports'], list)
                and sealed['reports'], 'LAB_PF_R4_NOT_ACTIVE')
        kinds = set()
        for ref in sealed['reports']:
            evaluation_id = ref['evaluationId']
            require(str(uuid.UUID(evaluation_id)) == evaluation_id, 'LAB_PF_R4_NOT_ACTIVE')
            report_rows = db.query("SELECT JSON_OBJECT('kind',run_kind,'status',status,"
                                   "'reportSha256',report_sha256,'payload',payload_json) "
                                   "FROM guard_evaluation_run WHERE public_id='" + evaluation_id + "' "
                                   "AND bundle_id=(SELECT id FROM guard_release_bundle WHERE public_id='" + bundle_id + "')",
                                   'cyber_security').decode().splitlines()
            require(len(report_rows) == 1, 'LAB_PF_R4_NOT_ACTIVE')
            report = json.loads(report_rows[0])
            kind = report['kind']
            require(report['status'] == 'passed' and report['reportSha256'] == ref['reportSha256'], 'LAB_PF_R4_NOT_ACTIVE')
            if kind in ('platform', 'canary'):
                payload = report['payload']
                require(payload.get('runKind') == kind and payload.get('reportVersion') == REPORT_VERSION
                        and payload.get('passed') is True
                        and payload.get('evidenceKind') == 'real_pf' and payload.get('subjectSha256') == subject_sha
                        and isinstance(payload.get('executionContext'), dict), 'LAB_PF_R4_NOT_ACTIVE')
                check_execution_context(payload['executionContext'], {'bundleId': bundle_id, 'subjectSha256': subject_sha})
                kinds.add(kind)
        require(kinds == {'platform', 'canary'}, 'LAB_PF_R4_NOT_ACTIVE')
    except (KeyError, TypeError, AttributeError, Rejected, json.JSONDecodeError, ValueError) as error:
        raise ValueError('LAB_PF_R4_NOT_ACTIVE') from error
    return {'bundleId': bundle_id, 'subjectSha256': subject_sha, 'formalKinds': sorted(kinds)}


def synthetic_provenance(source, policy, extractor_sha, executor_sha):
    """synthetic 会话与 K9 S1 共用的冻结 provenance；数据/切分/标签/代码摘要固定为 synthetic 占位。"""
    value = {k: digest({'synthetic': k}) for k in ('datasetSha256','splitSha256','labelRulesSha256','codeSha256')}
    value.update(modelSha256=source['bindings']['modelSha256'], policySha256=digest(policy),
                 extractorSha256=extractor_sha, executorSha256=executor_sha)
    return value


def synthetic_payload(kind, rows, subject_sha, plan_sha, versions, executor_sha, provenance):
    """隔离演练报告；evidenceKind=synthetic，正式库按 K9-1 开关拒绝。"""
    return dict(runKind=kind, evidenceKind='synthetic', passed=True, subjectSha256=subject_sha,
                evaluationPlanSha256=plan_sha, protocolVersions=versions, executorSha256=executor_sha, provenance=provenance,
                sourceEligibility=[f'{r["family"]}:model:' for r in rows if r['trialAutoEligible']]+['port_scan:rule:scan-ports'])


def executor_digest():
    return digest({'executor/'+p.name:sha(p) for p in sorted((ROOT/'executor').glob('*.py'))})


class Api:
    def __init__(self, session):
        self.session = session
    def request(self, method, path, body=None, revision=None):
        return self.session.v2(path, body, revision, method)


class Runner:
    def __init__(self, args):
        self.args = args
        self.work = args.directory.resolve()
        self.artifacts = args.artifacts.resolve()
        self.schema = 'cyber_g3_' + uuid.uuid4().hex
        self.processes = []
        self.db = None
        self.state = {'schema': 'guard-lab-run/1', 'mode': args.mode, 'sessionId': uid(), 'schemaName': self.schema,
                      'evidenceKind': 'synthetic', 'formalG3Eligible': False, 'scenarioSha256': sha(args.scenario),
                      'captureComplete': False, 'frozenFiles': {}}

    def save_state(self):
        # 原子更新仅限本次运行状态；每次检查点另存不可覆盖记录。
        write(self.work / ('checkpoint-' + uuid.uuid4().hex + '.json'), self.state)
        temporary = self.work / 'state.next'
        write(temporary, self.state)
        temporary.replace(self.work / 'state.json')

    def dry_run(self):
        """全部组件用替身，按虚拟时钟验证编排顺序与报告签名；不连接数据库或网络。"""
        from scripts.p5.platform_report import sign
        template=load(ROOT/'docs/contracts/examples/lab-report-input.json')['session']
        now=datetime.now(UTC)
        for field in ('assetId','bundleId','authorizationId','sensorId','bootId','executorId','executorBootId','mappingId'):
            template[field]=uid()
        template.update(contractVersion=VERSION,sessionId=self.state['sessionId'],runnerIdentity='dry-run-'+self.state['sessionId'],
                        evidenceKind='synthetic',speed=1,validFrom=lab_report.iso(now-timedelta(minutes=5)),
                        validUntil=lab_report.iso(now+timedelta(hours=2)),time=clock_plan(self.rows,now),
                        scenarioSha256=sha(self.work/'frozen-scenarios.json'),mappingSha256=digest({'simulated':True}))
        template['provenance']={name:digest({'simulated':name,'input':self.state['scenarioSha256']}) for name in template['provenance']}
        template['subjectSha256']=digest({'simulated':True,'source':self.state['scenarioSha256']})
        template['evaluationPlanSha256']=digest({'simulated':'evaluation-plan'})
        key=Ed25519PrivateKey.generate()
        trust={template['runnerIdentity']:base64.b64encode(key.public_key().public_bytes(
               serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()}
        write(self.work/'session.signed.json',sign(template,key,template['runnerIdentity']))
        write(self.work/'dry-run-trust.json',trust)
        events=[]
        for row in self.rows:
            offset=timedelta(microseconds=template['time']['scenarioOffsets'][row['scenarioId']])
            events.append(dict(kind='scenario_result',scenarioId=row['scenarioId'],completed=True,
                               occurredAt=lab_report.iso(lab_report.timestamp(row['sourceEnd'])+offset),simulated=True))
        quality=dict(snapshots=0,qualified=0,offloadSuspected=0,unknown=0,indeterminate=0,executionQualified=0)
        data=dict(contractVersion=VERSION,session=template,sessionSha256=digest(template),runStatus='completed',
                  scenarios=[dict(row,quality=quality.copy()) for row in self.rows],events=events,
                  unlinkedCommandIds=[],unlinkedDecisionIds=[],outsideScoringDecisionIds=[])
        write(self.work/'report-input.json',data)
        report=lab_report.generate(data);write(self.work/'report.json',report)
        envelope=sign(report,key,template['runnerIdentity']);write(self.work/'report.signed.json',envelope)
        write(self.work/'verification.json',lab_report.verify(envelope,trust,data))
        write(self.work/'runtime.json',dict(mode='dry-run',simulated=True,realBackend=False,realSensor=False,
                                           realPF=False,packetInjection=False,virtualClock=True))
        steps=['bundle.candidate','reports.synthetic','bundle.sealed','bundle.approved','bundle.active',
               'session.registered','session.approved','session.running','executor.empty-before']
        steps+=['scenario.completed:'+r['scenarioId'] for r in self.rows]
        steps+=['executor.empty-after','session.completed','report.generated','report.signed','report.verified',
                'report.simulated-import','components.stopped']
        write(self.work/'dry-run-trace.json',dict(simulated=True,steps=steps,rulesBefore=[],rulesAfter=[]))
        self.state.update(status='dry_run_completed',dryRunComplete=True,simulatedReportImport=True,
                          captureComplete=False,reportImported=False,manifest=template)
        self.state['frozenFiles']={str(self.work/n):sha(self.work/n) for n in
                                  ('frozen-source.json','frozen-scenarios.json','session.signed.json','report-input.json')}
        self.save_state()

    def start_process(self, command, log, env=None):
        stream = (self.work / log).open('xb')
        p = subprocess.Popen([str(c) for c in command], cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
        stream.close()
        self.processes.append(p)
        return p

    def snapshot(self):
        """只输出逐表摘要；原始账号、凭据和网络标识不进入日志。"""
        tables = self.db.query("SELECT table_name FROM information_schema.tables WHERE table_schema='cyber_security' AND table_type='BASE TABLE' ORDER BY table_name").decode().splitlines()
        return {t: {'rows': int(self.db.query('SELECT COUNT(*) FROM `' + t + '`', 'cyber_security')),
                    'sha256': hashlib.sha256(b'\n'.join(sorted(self.db.query('SELECT * FROM `' + t + '`', 'cyber_security').splitlines()))).hexdigest()} for t in tables}

    def signed(self, name, value, isolation=False):
        from scripts.p5.platform_report import sign
        path = self.artifact_dir / (name + '.json')
        ensure_write(path, sign(value, self.isolation_key if isolation else self.key,
                                self.isolation_name if isolation else self.runner_name))
        self.state['frozenFiles'][str(path)] = sha(path)
        return {'ref': str(path.relative_to(self.artifacts)), 'sha256': sha(path),
                'runnerIdentity': self.isolation_name if isolation else self.runner_name}

    def row(self, table, public_id):
        data = self.db.query('SELECT JSON_OBJECT(\'id\',id,\'revision\',revision) FROM `' + table + "` WHERE public_id='" + public_id + "'", self.schema)
        return json.loads(data)

    def start_backend(self):
        tls = self.work / 'private/tls'
        if tls.exists():
            password=load(self.work/'private/backend-keystore.json')['password']
        else:
            password = j1_run.tls_files(tls)
            write(self.work/'private/backend-keystore.json',{'password':password})
        env = dict(os.environ, DB_URL='jdbc:mysql://127.0.0.1:3306/'+self.schema,
                   DB_USERNAME='root', DB_PASSWORD=self.db.env['MYSQL_PWD'], DB_POOL_SIZE='12',
                   LOGIN_THROTTLE_HMAC_KEY=j1_run.secret('com.xyh.cyber-security.login-throttle-hmac'),
                   SERVER_PORT=str(self.args.port), SERVER_ADDRESS='127.0.0.1', SESSION_COOKIE_SECURE='true',
                   OUTBOX_RELAY_ENABLED='false', INGEST_CONSUMER_ENABLED='false', CYBER_DRIFT_ENABLED='false',
                   SERVER_SSL_ENABLED='true', SERVER_SSL_CLIENT_AUTH='need', SERVER_SSL_ENABLED_PROTOCOLS='TLSv1.3',
                   SERVER_SSL_KEY_STORE=str(tls/'server.p12'), SERVER_SSL_KEY_STORE_TYPE='PKCS12',
                   SERVER_SSL_KEY_STORE_PASSWORD=password, SERVER_SSL_TRUST_STORE=str(tls/'trust.p12'),
                   SERVER_SSL_TRUST_STORE_TYPE='PKCS12', SERVER_SSL_TRUST_STORE_PASSWORD=password)
        self.base = 'https://127.0.0.1:'+str(self.args.port)
        self.context = j1_run.ssl_context(tls)
        self.backend = self.start_process([self.args.java, '--enable-native-access=ALL-UNNAMED', '-Xmx2g',
            '-Dcyber.guard.automation-enabled=false', '-Dcyber.guard.lab-rehearsal-enabled=true',
            '-Dcyber.guard.bootstrap-reports-enabled='+('true' if getattr(self,'bootstrap_reports',True) else 'false'),
            '-Dcyber.guard.artifact-root='+str(self.artifacts), '-Dcyber.guard.report-trust-file='+str(self.work/'private/trust.json'),
            '-Dcyber.model-artifact.root='+str(Path.home()/'Workspace/deliveries'),
            '-Dspring.session.timeout=4h', '-Dserver.servlet.session.timeout=4h', '-Dserver.tomcat.threads.max=12',
            '-jar', self.work/'bin/backend.jar'], 'backend.log', env)
        for _ in range(90):
            require(self.backend.poll() is None, 'LAB_BACKEND_EXITED')
            try:
                urllib.request.urlopen(self.base+'/api/v2/auth/csrf', context=self.context, timeout=2).close()
                break
            except (OSError, urllib.error.URLError):
                time.sleep(1)
        else:
            raise ValueError('LAB_BACKEND_TIMEOUT')
        self.op = j1_run.Session(self.base, self.context).login(load(self.work/'private/isolated-operator.json'))
        reviewer = load(self.args.reviewer_file)
        self.rev = j1_run.Session(self.base, self.context).login({'username': reviewer.get('username','guard-reviewer'),'password':reviewer['password']})

    def prepare_existing_bundle(self):
        """K9-6：复用源 schema 中已由 K6 报告封存并独立批准的组合，不新建组合或报告。"""
        plan = load(self.args.import_plan)
        self.policy = plan['decisionPolicy']
        self.bundle = self.args.existing_bundle
        found = self.db.query("SELECT JSON_OBJECT('status',status,'subject',subject_sha256,'revision',revision) FROM guard_release_bundle "
                              "WHERE public_id='"+str(uuid.UUID(self.bundle))+"'", self.schema).decode().splitlines()
        require(len(found) == 1, 'LAB_EXISTING_BUNDLE_MISSING')
        row = json.loads(found[0])
        require(row['status'] in ('approved','active') and row['subject'] == getattr(self.args, 'subject_sha256', R4_SUBJECT_SHA256), 'LAB_EXISTING_BUNDLE_INVALID')
        self.subject_sha = row['subject']
        self.versions = plan['releaseBundle']['protocolVersions']
        self.plan_sha = self.policy['evaluationPlanSha256']
        self.provenance = synthetic_provenance(self.source, self.policy, plan['releaseBundle']['extractorSha256'], self.executor_sha)
        reports = load(self.args.existing_reports)
        self.proofs = {kind: reports[kind] for kind in ('final','platform','canary')}
        for ref in self.proofs.values():
            require(sha(self.artifacts/ref['ref']) == ref['sha256'], 'LAB_EXISTING_REPORT_MISMATCH')
        self.state.update(bundleId=self.bundle, bundleRevision=row['revision'], subjectSha256=self.subject_sha)
        write(self.work/'bundle-lifecycle.json', {'synthetic':True,'existing':True,'status':row['status'],'proofs':self.proofs})

    def prepare_bundle(self):
        if getattr(self.args,'existing_bundle',None):
            return self.prepare_existing_bundle()
        plan = load(self.args.import_plan)
        policy = plan['decisionPolicy']
        require(digest(policy) == digest(load(self.artifacts/'packages/host-guard-round2-20261011-r4/policy-m2-lab.json')),
                'LAB_POLICY_MISMATCH')
        # 冻结策略原样登记，若已存在则回读比较，不改 UUID 或任何阈值。
        exists = self.db.query("SELECT COUNT(*) FROM guard_decision_policy WHERE public_id='"+policy['policyId']+"'", self.schema)
        if int(exists) == 0:
            result = self.op.v2('/decision-policies', policy)
            self.rev.v2('/decision-policies/'+result['id']+'/reviews', {'decision':'approve','reason':'synthetic G3 rehearsal; frozen r4'}, 1)
        body = dict(plan['releaseBundle'], modelId=plan['existingModel']['id'], policyId=policy['policyId'],
                    evaluationPlanId=plan['existingEvaluationPlan']['id'], capabilityIds=sorted(x['id'] for x in plan['existingCapabilities']))
        bundle = self.op.v2('/release-bundles', body)
        self.bundle = bundle['id']
        self.subject_sha = bundle['subjectSha256']
        self.policy = policy
        self.versions = body['protocolVersions']
        self.plan_sha = policy['evaluationPlanSha256']
        self.provenance = synthetic_provenance(self.source, policy, body['extractorSha256'], self.executor_sha)
        reports = []
        self.proofs = {}
        for kind in ('final','platform','canary'):
            payload = synthetic_payload(kind, self.rows, self.subject_sha, self.plan_sha, self.versions, self.executor_sha, self.provenance)
            ref = self.signed('synthetic-'+kind, payload)
            self.proofs[kind] = ref
            reports.append(self.op.v2('/release-bundles/'+self.bundle+'/imports',
                                     dict(reportRef=ref['ref'],sha256=ref['sha256'],runnerIdentity=ref['runnerIdentity']))['id'])
        seal = self.op.v2('/release-bundles/'+self.bundle+'/sealings', {'evaluationIds':reports}, 1)
        approved = self.rev.v2('/release-bundles/'+self.bundle+'/decisions', {'decision':'approve','reason':'synthetic isolated schema only'}, seal['revision'])
        self.state.update(bundleId=self.bundle, bundleRevision=approved['revision'], subjectSha256=self.subject_sha)
        write(self.work/'bundle-lifecycle.json', {'synthetic':True,'candidate':bundle,'evaluationIds':reports,'sealed':seal,'approved':approved})

    def prepare_identities(self):
        # 授权表为 DATETIME(3)，先按相同精度冻结，避免 MySQL 四舍五入缩小签名边界。
        base=datetime.now(UTC)
        base=base.replace(microsecond=(base.microsecond//1000)*1000)
        self.valid_from = base-timedelta(seconds=30)
        self.valid_until = base+timedelta(hours=2)
        self.asset = self.op.v2('/assets', dict(assetKey=self.work.name,platform='macos',environment='lab',owner='synthetic G3 rehearsal'))['id']
        self.boot, self.scope = uid(), uid()
        sensor = self.op.v2('/sensors', dict(assetId=self.asset,platform='macos',captureScopeId=self.scope))
        self.sensor = sensor['id']
        (self.work/'private/sensor.credential').write_text(sensor['credential'])
        (self.work/'private/sensor.credential').chmod(0o600)
        executor = self.op.v2('/executors',dict(assetId=self.asset,platform='macos',capabilityProbeRef='synthetic:memory-firewall'))
        self.executor, self.executor_boot = executor['id'], uid()
        (self.work/'private/executor.credential').write_text(executor['credential']);(self.work/'private/executor.credential').chmod(0o600)
        self.executor_token = executor['credential']
        scopes = []
        caps = load(self.args.import_plan)['existingCapabilities']
        for row in self.rows:
            local = self.original[row['scenarioId']]
            scope = 'peer_inbound' if row['family'] in ('port_scan','normal') else 'peer_service'
            family = row['family'] if row['family']!='normal' else 'port_scan'
            cap = next(c['id'] for c in caps if c['payload']['family']==family)
            val = dict(direction='inbound',transport='tcp',addressFamily='ipv4',scope=scope,
                       servicePort=None if scope=='peer_inbound' else local['port'],capabilityId=cap)
            if val not in scopes:scopes.append(val)
        auth = self.op.v2('/assets/'+self.asset+'/authorizations',dict(interfaces=['lo0'],observationAllowed=True,executionScopes=scopes,
                            validFrom=self.valid_from.isoformat().replace('+00:00','Z'),validUntil=self.valid_until.isoformat().replace('+00:00','Z'),
                            evidenceRef=str(self.artifact_dir.relative_to(self.artifacts))+'/source.json'))
        self.auth = auth['id']
        approved = self.rev.v2('/authorizations/'+self.auth+'/decisions',dict(decision='approve',reason='synthetic loopback rehearsal only'),1)
        self.auth_revision = approved['revision']
        self.rev.v2('/release-bundles/'+self.bundle+'/activations',dict(assetIds=[self.asset],authorizationIds=[self.auth]),self.state['bundleRevision'])
        config = dict(contractVersion='host-guard/5.0.0-rc.2',profileSha256=load(self.args.import_plan)['releaseBundle']['featureProfileSha256'],
                      captureHealthVersion=self.versions['health'],interfaceIds=['lo0'],limits={'maxBatchSize':100},
                      captureScopeId=self.scope,addressFamily='ipv4',buildSha256=sha(self.work/'bin/guardlive'))
        cid = self.op.v2('/sensors/'+self.sensor+'/configs', config)['id']
        self.rev.v2('/sensor-configs/'+cid+'/decisions',dict(decision='approve',reason='synthetic replay build'),1)
        self.op.machine(self.sensor,sensor['credential'],'heartbeats',dict(bootId=self.boot,version='G3 rehearsal',configHash=digest(config),lastSequence=0,clockSkewMs=None))
        # 执行器心跳仅登记本次 boot；仍无真实动作权限。
        self.executor_call('heartbeats', dict(bootId=self.executor_boot,adapterVersion='hostguard-executor/1',capabilityHash=digest(sorted(c['id'] for c in caps)),pendingRecovery=False,activeRuleCount=0,clockSkewMs=0))

        normalized=dict(digestVersion='guard-state/1',assetId=self.asset,executorId=self.executor,executorBootId=self.executor_boot,rules=[],pendingRevocations=[])
        self.executor_call('reconciliations',dict(executorBootId=self.executor_boot,observedAt=stamp(),digestVersion='guard-state/1',stateDigest=digest(normalized),ownedRules=[],pendingRevocations=[],recoveryErrors=[]))
        tls=self.work/'private/tls'
        write(self.work/'private/substitute.json',dict(baseUrl=self.base,assetId=self.asset,executorId=self.executor,bootId=self.executor_boot,
              capabilityHash=digest(sorted(c['id'] for c in caps)),caFile=str(tls/'ca.pem'),certificateFile=str(tls/'client.pem'),keyFile=str(tls/'client.key')))
        self.substitute=self.start_process([sys.executable,ROOT/'scripts/p7/lab_substitute.py','--directory',self.work],'substitute.log')

    def executor_call(self, operation, body):
        return self.op.call('POST','/api/v2/machine/executors/'+self.executor+'/'+operation,body,
                            {'Authorization':'Bearer '+self.executor_token,'Idempotency-Key':uid()},(200,201,202))['data']

    def prepare_targets(self):
        fingerprints = pki.create(self.work/'private/ipc')
        from cryptography import x509
        self.target_port = self.args.port+1
        peer_secret = os.urandom(32)
        (self.work/'private/peer.key').write_bytes(peer_secret);(self.work/'private/peer.key').chmod(0o600)
        (self.work/'private/budget.key').write_bytes(os.urandom(32));(self.work/'private/budget.key').chmod(0o600)
        entries, allowed = [], []
        for row, original_peer in ((row, peer) for row in self.rows for peer in self.original[row['scenarioId']]['peers']):
            peer = '127.30.0.'+str(len(entries)+2)
            parts = ['host-guard-peer-v1',self.asset,self.sensor,1,peer]
            peer_key = hmac.new(peer_secret,json.dumps(parts,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
            original = self.original[row['scenarioId']]
            scope = 'peer_inbound' if row['family'] in ('port_scan','normal') else 'peer_service'
            entries.append(dict(scenarioId=row['scenarioId'],originalLocal=original['host'],originalPeer=original_peer,
                                canaryLocal='127.0.0.1',canaryPeer=peer,peerKey=peer_key,direction='inbound',transport='tcp',
                                addressFamily='ipv4',scope=scope,servicePort=original['port']))
            for port in ([0] if scope=='peer_inbound' else original['ports']):
                allowed.append(dict(local='127.0.0.1',peer=peer,peerKey=peer_key,direction='inbound',scope=scope,servicePort=port))
        self.local_entries = entries
        tls = self.work/'private/tls';ipc=self.work/'private/ipc'
        backend_tls = dict(baseUrl=self.base,caFile=str(tls/'ca.pem'),certificateFile=str(tls/'client.pem'),keyFile=str(tls/'client.key'))
        config = dict(listen='127.0.0.1:'+str(self.target_port),certificateFile=str(ipc/'server.pem'),keyFile=str(ipc/'server.key'),caFile=str(ipc/'ca.pem'),
                      authorizedUntil=self.valid_until.isoformat().replace('+00:00','Z'),
                      scope=dict(AssetID=self.asset,SensorID=self.sensor,BootID=self.boot,CaptureScopeID=self.scope,Environment='lab',
                                 ExecutorBootID=self.executor_boot,KeyEpoch=1,LocalAddresses=['127.0.0.1'],
                                 CollectorCertSHA256=fingerprints['collector'],ExecutorCertSHA256=fingerprints['executor'],MaxReferences=10000),
                      registration=dict(backend=backend_tls,credentialFile=str(self.work/'private/executor.credential'),budgetKeyFile=str(self.work/'private/budget.key'),
                                        identityFile=str(self.work/'private/registrar.json'),executorId=self.executor,allowed=allowed))
        write(self.work/'private/targets.json',config)
        self.targets = self.start_process([self.work/'bin/guardtargets','-config',self.work/'private/targets.json'],'targets.log')
        self.target_context = ssl.create_default_context(cafile=str(ipc/'ca.pem'))
        self.target_context.load_cert_chain(str(ipc/'collector.pem'),str(ipc/'collector.key'))
        for _ in range(30):
            require(self.targets.poll() is None,'LAB_TARGETS_EXITED')
            try:
                with socket.create_connection(('127.0.0.1',self.target_port),.2):break
            except OSError:time.sleep(.1)
        self.initial = []
        # 仅为 synthetic 会话建立初始目标锚点，使用版本控制内的契约示例；
        # 不读取旧运行目录，也不把该示例上传到模型、评分或观察表。
        scenarios = {row['scenarioId']: row for row in self.rows}
        for entry in entries:
            row = scenarios[entry['scenarioId']]
            observation=load(ROOT/'docs/contracts/examples/observation.json')
            now = stamp()
            observation.update(assetId=self.asset,sensorId=self.sensor,bootId=self.boot,captureScopeId=self.scope,environment='lab',
                               peerKey=entry['peerKey'],keyEpoch=1,asOf=now,lastPacketAt=now,emittedAt=now,
                               firstSeenAt=(lab_report.timestamp(now)-timedelta(microseconds=round(observation['features']['elapsedMs']*1000))).isoformat().replace('+00:00','Z'))
            observation['quality'].update(captureGap=False,latePacket=False,truncated=False,offloadSuspected=False,capacityDrop=False,clockSkewMs=0)
            observation['direction']='inbound'; observation['servicePort']=entry['servicePort']
            request=dict(observation=observation,endpoints={'Local':'127.0.0.1:'+str(entry['servicePort']),'Peer':entry['canaryPeer']+':55000','Protocol':6},scope=entry['scope'])
            data=canonical(request)
            with urllib.request.urlopen(urllib.request.Request('https://127.0.0.1:'+str(self.target_port)+'/v1/targets/lease',data=data,headers={'Content-Type':'application/json'}),context=self.target_context,timeout=3) as response:
                lease=json.loads(response.read())
            ref=lease['ref'] if 'ref' in lease else lease['targetRef']
            binding = json.loads(self.db.query("SELECT JSON_OBJECT('id',public_id) FROM guard_target_binding WHERE target_ref='"+ref+"'",self.schema))
            self.initial.append(dict(scenarioId=row['scenarioId'],targetBindingId=binding['id'],peerKey=entry['peerKey'],keyEpoch=1,captureScopeId=self.scope,targetRef=ref))

    def freeze_session(self):
        start = datetime.now(UTC)+timedelta(seconds=140)
        clock = clock_plan(self.rows,start)
        scenario_file=self.artifact_dir/'scenarios.json'; mapping_file=self.artifact_dir/'mapping.json'
        write(scenario_file,dict(contractVersion=VERSION,scenarios=self.rows))
        mapping_id=uid()
        write(mapping_file,dict(contractVersion=VERSION,mappingId=mapping_id,sessionId=self.state['sessionId'],entries=self.initial))
        manifest=dict(contractVersion=VERSION,sessionId=self.state['sessionId'],assetId=self.asset,bundleId=self.bundle,authorizationId=self.auth,
                      authorizationRevision=self.auth_revision,environment='lab',runnerIdentity=self.runner_name,evidenceKind='synthetic',
                      validFrom=self.valid_from.isoformat().replace('+00:00','Z'),validUntil=self.valid_until.isoformat().replace('+00:00','Z'),
                      timeoutSeconds=7200,protocolVersions=self.versions,subjectSha256=self.subject_sha,evaluationPlanSha256=self.plan_sha,
                      sensorId=self.sensor,bootId=self.boot,executorId=self.executor,executorBootId=self.executor_boot,
                      mappingRef=str(mapping_file.relative_to(self.artifacts)),mappingSha256=sha(mapping_file),mappingId=mapping_id,
                      scenarioRef=str(scenario_file.relative_to(self.artifacts)),scenarioSha256=sha(scenario_file),provenance=self.provenance,time=clock,speed=1)
        isolation=self.signed('isolation',dict(sessionId=manifest['sessionId'],assetId=self.asset,mappingSha256=manifest['mappingSha256'],executorId=self.executor,
                            validUntil=manifest['validUntil'],networkIsolationVerified=True,evidenceKind='synthetic',mechanism='file replay; no packet injection; loopback-only listeners'),True)
        admission=self.signed('admission',dict(sessionId=manifest['sessionId'],subjectSha256=self.subject_sha,j1Passed=False,j2Registered=False,evidenceKind='synthetic'))
        manifest['proofs']=dict(p5=self.proofs['platform'],p6=self.proofs['final'],isolation=isolation,admission=admission)
        ref=self.signed('session',manifest)
        self.manifest=manifest
        self.state.update(manifestRef=ref,manifest=manifest,assetId=self.asset,sensorId=self.sensor,bootId=self.boot,executorId=self.executor,executorBootId=self.executor_boot)
        self.state['frozenFiles'].update({str(scenario_file):sha(scenario_file),str(mapping_file):sha(mapping_file)})
        private=dict(contractVersion='host-guard-sensor-mapping/1.1',sessionId=manifest['sessionId'],sessionSha256=digest(manifest),mappingId=mapping_id,
                     mappingSha256=manifest['mappingSha256'],scenarioSha256=manifest['scenarioSha256'],buildSha256=sha(self.work/'bin/guardlive'),
                     extractorSha256=manifest['provenance']['extractorSha256'],entries=self.local_entries)
        private_ref=self.signed('private-mapping',private)
        private_path=self.artifacts/private_ref['ref']
        ipc=self.work/'private/ipc';tls=self.work/'private/tls'
        config=dict(assetId=self.asset,sensorId=self.sensor,bootId=self.boot,captureScopeId=self.scope,environment='lab',captureScope='all_inbound_tcp',
                    localAddresses=sorted(set(v['host'] for v in self.original.values())),secretFile=str(self.work/'private/peer.key'),keyEpoch=1,
                    interface='lo0',allowedInterfaces=['lo0'],authorizedUntil=manifest['validUntil'],
                    upload=dict(baseUrl=self.base,caFile=str(tls/'ca.pem'),certificateFile=str(tls/'client.pem'),keyFile=str(tls/'client.key'),
                                credentialFile=str(self.work/'private/sensor.credential'),spoolDir=str(self.work/'spool'),healthWindowMs=1000),
                    lab=dict(runId=manifest['sessionId'],sessionSha256=digest(manifest),mappingSha256=manifest['mappingSha256'],scenarioId=self.rows[0]['scenarioId'],
                             mappingFile=str(private_path),trustFile=str(self.work/'private/trust.json'),eventsFile=str(self.work/'observations-events.jsonl'),rehearsal=True,
                             targets=dict(baseUrl='https://127.0.0.1:'+str(self.target_port),caFile=str(ipc/'ca.pem'),certificateFile=str(ipc/'collector.pem'),keyFile=str(ipc/'collector.key')),
                             inputs=[dict(scenarioId=r['scenarioId'],path=str(self.artifacts/r['pcapRef'])) for r in self.rows]))
        write(self.work/'private/sensor.json',config)
        self.state['frozenFiles'][str(self.work/'private/sensor.json')]=sha(self.work/'private/sensor.json')
        self.state['frozenFiles'][str(self.work/'bin/guardlive')]=sha(self.work/'bin/guardlive')
        self.save_state()
        create=self.op.v2('/lab-validation-runs',dict(sessionRef=ref['ref'],sha256=ref['sha256'],runnerIdentity=self.runner_name))
        approved=self.rev.v2('/lab-validation-runs/'+manifest['sessionId']+'/decisions',dict(decision='approve',reason='synthetic rehearsal only'),create['revision'])
        self.op.v2('/lab-validation-runs/'+manifest['sessionId']+'/starts',{},approved['revision'])
        write(self.work/'runtime.json',dict(realBackend=True,realSensor=True,modelSha256=self.provenance['modelSha256'],speed=1,
                  backendSha256=sha(self.work/'bin/backend.jar'),sensorSha256=sha(self.work/'bin/guardlive'),guardtargetsSha256=sha(self.work/'bin/guardtargets'),
                  replayOnly=True,packetInjection=False,realPF=False,syntheticTrustFileSha256=sha(self.work/'private/trust.json'),startedAt=stamp()))

    def lab_op(self, operation, body):
        view=self.op.v2('/lab-validation-runs/'+self.state['sessionId'],method='GET')
        return self.op.v2('/lab-validation-runs/'+self.state['sessionId']+'/'+operation,body,view['revision'])

    def stop_substitute(self):
        """捕获完成后先核对替身退出，再做大量报告查询；缺终态或任一失败都不能通过。"""
        if self.substitute.poll() is None:
            self.substitute.terminate()
            try:self.substitute.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.substitute.kill();self.substitute.wait()
                require(False,'LAB_SUBSTITUTE_CLEANUP_TIMEOUT')
        require(self.substitute.returncode==0,'LAB_SUBSTITUTE_EXIT_FAILED')
        self.verify_substitute_cleanup()
        self.state['substituteExitCode']=0;self.save_state()

    def verify_substitute_cleanup(self):
        """恢复只读取原会话的完整替身记录，不用新进程覆盖旧失败。"""
        rows=[json.loads(line) for line in (self.work/'substitute.jsonl').read_text().splitlines()]
        require(rows and rows[-1].get('kind')=='stopped'
                and all(r.get('kind')!='failure' and r.get('installedRules')==[]
                        and r.get('commandIds',[])==[] for r in rows),
                'LAB_SUBSTITUTE_CLEANUP_UNVERIFIED')

    def collect(self):
        view=self.op.v2('/lab-validation-runs/'+self.state['sessionId'],method='GET')
        if view['runStatus']!='completed':
            self.lab_op('completions',dict(outcome='completed',reason='all frozen PCAP segments finished'))
        # 只在评分窗内引用事实；预热判定由服务端单独列 outsideScoringDecisionIds。
        observations={o['observationId']:o for o in map(json.loads,(self.work/'observations.jsonl').read_text().splitlines())}
        decisions=[json.loads(line) for line in self.db.query("SELECT JSON_OBJECT('id',public_id,'evidence',CAST(evidence_json AS JSON),'decidedAt',DATE_FORMAT(decided_at,'%Y-%m-%dT%H:%i:%s.%fZ')) FROM guard_decision WHERE asset_id=(SELECT id FROM asset WHERE public_id='"+self.state['assetId']+"') ORDER BY id",self.schema).splitlines()]
        decisions=[d for d in decisions if d['evidence']['triggerObservationId'] in observations]
        scenarios = {row['scenarioId']: row for row in self.rows}
        by_peer={e['peerKey']:scenarios[e['scenarioId']] for e in self.local_entries}
        scored=[]
        for row in decisions:
            proof=row['evidence'];trigger=observations[proof['triggerObservationId']];scenario=by_peer[trigger['peerKey']]
            delta=timedelta(microseconds=self.manifest['time']['scenarioOffsets'][scenario['scenarioId']])
            if lab_report.timestamp(scenario['sourceStart'])+delta <= lab_report.timestamp(trigger['asOf']) <= lab_report.timestamp(scenario['sourceEnd'])+delta:
                self.lab_op('events',dict(eventId=uid(),scenarioId=scenario['scenarioId'],kind='decision',referenceId=row['id']))
                scored.append(dict(row,scenarioId=scenario['scenarioId']))
        # 观察旁路只登记少量代表事实；全部质量分母由服务端从原始表重算。
        events=(self.work/'observations-events.jsonl').read_text().splitlines()
        first={}
        for line in events:
            row=json.loads(line);first.setdefault(row['scenarioId'],row)
        for row in first.values():self.lab_op('events',row)
        replays=load(self.work/'sensor-report.json')['replays']
        for replay in replays:
            value=dict(contractVersion=VERSION,sessionId=self.state['sessionId'],sessionSha256=digest(self.manifest),scenarioId=replay['scenarioId'],
                       mappingSha256=self.manifest['mappingSha256'],startedAt=replay['wallStartedAt'],endedAt=replay['wallFinishedAt'],completed=True)
            ref=self.signed('result-'+replay['scenarioId'],value)
            self.lab_op('events',dict(eventId=uid(),scenarioId=replay['scenarioId'],kind='scenario_result',reportRef=ref['ref'],sha256=ref['sha256']))
        ensure_write(self.work/'all-decisions.json',decisions)
        ensure_write(self.work/'decisions.json',scored)
        report_input=self.op.v2('/lab-validation-runs/'+self.state['sessionId']+'/report-input',method='GET')
        ensure_write(self.work/'report-input.json',report_input)
        report=lab_report.generate(report_input);ensure_write(self.work/'report.json',report)
        ref=self.signed('g3-report',report)
        lab_report.verify(load(self.artifacts/ref['ref']),load(self.work/'private/trust.json'),report_input)
        self.lab_op('reports',dict(reportRef=ref['ref'],sha256=ref['sha256'],runnerIdentity=self.runner_name))
        self.state.update(reportImported=True,finishedAt=stamp())

    def run(self):
        require(self.args.mode in ('dry-run','rehearse'),'LAB_PF_BLOCKED_BY_R4_E3_PRECONDITION')
        require(not self.work.exists(),'LAB_RUN_DIRECTORY_EXISTS')
        os.umask(0o077);self.work.mkdir(parents=True,mode=0o700)
        self.source=load(self.args.scenario);self.rows=freeze_scenarios(self.source,self.artifacts)
        if getattr(self.args,'scenarios',None):
            # 只缩小本次会话的场景集合；每段仍按冻结登记逐文件核验，不改任何片段。
            wanted=self.args.scenarios.split(',');self.rows=[r for r in self.rows if r['scenarioId'] in wanted]
            require(len(self.rows)==len(wanted),'LAB_SCENARIO_SELECTION_INVALID')
        write(self.work/'frozen-source.json',self.source)
        write(self.work/'frozen-scenarios.json',self.rows)
        if self.args.mode=='dry-run':
            self.dry_run();return
        require(self.args.mode=='rehearse','LAB_PF_REQUIRES_STAGED_FORMAL_PLAN')
        self.artifact_dir=self.artifacts/'rehearsals'/self.work.name
        self.artifact_dir.mkdir(parents=True,mode=0o700,exist_ok=False)
        write(self.artifact_dir/'source.json',self.source)
        key_dir=Path.home()/'Workspace/ai/keys/cyber-guard-rehearsals'/self.work.name
        key_dir.mkdir(parents=True,mode=0o700,exist_ok=False)
        self.key,self.isolation_key=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
        self.runner_name,self.isolation_name='g3-rehearsal-'+self.state['sessionId'],'g3-isolation-'+self.state['sessionId']
        trust=load(self.args.report_trust)
        if getattr(self.args,'extra_trust',None):
            trust.update(load(self.args.extra_trust))
        for name,key in ((self.runner_name,self.key),(self.isolation_name,self.isolation_key)):
            (key_dir/(name+'.der')).write_bytes(key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            trust[name]=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        write(self.work/'private/trust.json',trust)
        self.executor_sha=executor_digest()
        self.db=j1_run.Database(self.args.mysql_service)
        before=self.snapshot();write(self.work/'business-before.json',before)
        write(self.work/'database-clone.json',self.db.clone(getattr(self.args,'source_schema','cyber_security'),self.schema,self.work/'business-backup.sql'))
        # 复制口令摘要到隔离库专用申请人，独立审查人仍使用另一个真实账号；不改变业务库权限。
        original=load(self.args.operator_file)
        username='g3-operator-'+self.state['sessionId'][:8]
        quoted=lambda value:"'"+value.replace("'","''")+"'"
        self.db.query("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) SELECT "+quoted(uid())+","+quoted(username)+",'G3 isolated rehearsal',password_hash,'active' FROM sys_user WHERE username="+quoted(original['username']),self.schema)
        self.db.query("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,'global','*' FROM sys_user u CROSS JOIN sys_role r WHERE u.username="+quoted(username)+" AND r.role_key IN ('platform_admin','model_operator','security_analyst')",self.schema)
        write(self.work/'private/isolated-operator.json',dict(username=username,password=original['password']))
        self.state['schemaName']=self.schema;self.save_state()
        (self.work/'bin').mkdir()
        for source,name in ((ROOT/'backend/target/cyber-security-backend-0.1.0-SNAPSHOT.jar','backend.jar'),):
            require(source.is_file(),'LAB_BUILD_REQUIRED');shutil.copy2(source,self.work/'bin'/name)
        for command in ('guardlive','guardtargets'):
            subprocess.run([str(self.args.go),'build','-o',str(self.work/'bin'/command),'./cmd/'+command],cwd=ROOT/'sensor',check=True,stdout=subprocess.DEVNULL)
        self.original={}
        for row in self.rows:
            selection=next(v for v in load(self.args.selection) if v['segmentId']==row['scenarioId'])
            self.original[row['scenarioId']]=original_mapping(row,selection,self.artifacts)
        self.start_backend()
        self.prepare_bundle();self.prepare_identities();self.prepare_targets();self.freeze_session()
        process=self.start_process([self.work/'bin/guardlive','-config',self.work/'private/sensor.json','-lab-plan',
                                    '-out',self.work/'observations.jsonl','-report',self.work/'sensor-report.json','-drain-timeout','120s'],'sensor.log')
        while process.poll() is None:
            require(self.backend.poll() is None and self.targets.poll() is None and self.substitute.poll() is None,'LAB_COMPONENT_EXITED')
            time.sleep(1)
        code=process.returncode
        require(code==0,'LAB_SENSOR_FAILED')
        self.state['captureComplete']=True;self.save_state()
        self.stop_substitute()
        self.collect();self.save_state()

    def resume(self):
        self.state=check_resume(load(self.work/'state.json'),self.work,sha(self.args.scenario))
        if self.state.get('reportImported') is True:return
        self.schema=self.state['schemaName'];self.db=j1_run.Database(self.args.mysql_service)
        self.manifest=self.state['manifest'];self.rows=load(self.work/'frozen-scenarios.json')
        self.bundle=self.state['bundleId'];self.runner_name=self.manifest['runnerIdentity']
        self.provenance=self.manifest['provenance'];self.source=load(self.work/'frozen-source.json')
        self.artifact_dir=(self.artifacts/self.state['manifestRef']['ref']).parent
        private=load(self.work/'private/sensor.json')['lab']['mappingFile']
        self.local_entries=load(private)['payload']['entries']
        key_path=Path.home()/'Workspace/ai/keys/cyber-guard-rehearsals'/self.work.name/(self.runner_name+'.der')
        self.key=serialization.load_der_private_key(key_path.read_bytes(),password=None)
        require(self.state.get('substituteExitCode')==0,'LAB_SUBSTITUTE_CLEANUP_UNVERIFIED')
        self.verify_substitute_cleanup()
        self.start_backend();self.collect();self.save_state()

    def finish(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        if self.db is not None and self.work.exists():
            after=self.snapshot()
            if not (self.work/'business-after.json').exists():write(self.work/'business-after.json',after)
            same=load(self.work/'business-before.json')==after
            write(self.work/('business-parity-'+uuid.uuid4().hex+'.json'),dict(identical=same))
            require(same,'BUSINESS_DATABASE_CHANGED')
        if self.args.mode=='rehearse' and self.work.exists() and not (self.work/'gate.json').exists():
            from scripts.p7.g3_rehearsal import evaluate_directory
            write(self.work/'gate.json',evaluate_directory(self.work))


def main():
    home=Path.home()/'Workspace'
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('dry-run','rehearse','pf'),default='dry-run')
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--scenario',type=Path,default=ROOT/'.cache/j2-20261011/g3-scenario.json')
    parser.add_argument('--artifacts',type=Path,default=home/'ai/artifacts/cyber-guard')
    parser.add_argument('--selection',type=Path,default=ROOT/'.cache/j1-20261011-reg-preroll30/selection.json')
    parser.add_argument('--import-plan',type=Path,default=ROOT/'.cache/j2-20261011/import-rehearsal/lab-plan.json')
    parser.add_argument('--operator-file',type=Path,default=ROOT/'.cache/j1-20261011-v9/private/operator.json')
    parser.add_argument('--reviewer-file',type=Path,default=home/'ai/keys/cyber-guard-reviewer/credentials.json')
    parser.add_argument('--report-trust',type=Path,default=home/'ai/keys/cyber-guard-trust/report-trust.json')
    parser.add_argument('--mysql-service',type=Path,default=home/'development/services/databases/mysql-server-8.0.42')
    parser.add_argument('--java',type=Path,default=home/'development/runtimes/java/temurin-25.0.2/Contents/Home/bin/java')
    parser.add_argument('--go',type=Path,default=home/'development/runtimes/go/go-1.26.4/bin/go')
    parser.add_argument('--port',type=int,default=19443)
    parser.add_argument('--r4-bundle-id',help='pf 前置核验所用的业务库 r4 bundleId')
    parser.add_argument('--subject-sha256',type=subject_sha256,default=R4_SUBJECT_SHA256,help='期望组合 subject；默认保留 r4')
    parser.add_argument('--authorization-reference',help='A6 单轮授权引用；本次仅作前置门禁')
    parser.add_argument('--source-schema',default='cyber_security',help='K9-6：从已模拟 A18 的隔离 schema 克隆')
    parser.add_argument('--existing-bundle',help='K9-6：复用源 schema 中已批准的 r4，不新建组合')
    parser.add_argument('--existing-reports',type=Path,help='K9-6：final/platform/canary 的 {ref,sha256,runnerIdentity}')
    parser.add_argument('--extra-trust',type=Path,help='K9-6：额外的演练报告信任项（仅本次隔离后端）')
    parser.add_argument('--scenarios',help='逗号分隔的场景子集')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    # 复用既有组合只用于隔离演练：源必须是 K9 隔离 schema，且须给出证明文件。
    require(args.source_schema=='cyber_security' or (args.mode=='rehearse' and re.fullmatch(r'cyber_guard_[a-z0-9_]{1,52}',args.source_schema)),
            'LAB_SOURCE_SCHEMA_INVALID')
    require((args.existing_bundle is None)==(args.existing_reports is None)
            and (args.existing_bundle is None or args.source_schema!='cyber_security'),'LAB_EXISTING_BUNDLE_ARGUMENTS_INVALID')
    if args.mode == 'pf':
        require(args.r4_bundle_id and args.authorization_reference, 'LAB_PF_R4_NOT_ACTIVE')
        formal_r4_preflight(j1_run.Database(args.mysql_service), args.r4_bundle_id, args.subject_sha256)
    runner=Runner(args)
    try:
        if args.resume:runner.resume()
        else:runner.run()
    except Exception as exc:
        traceback.print_exc()
        if runner.work.exists():write(runner.work/'failure.json',dict(at=stamp(),error=type(exc).__name__,code=str(exc) if isinstance(exc,ValueError) else 'LAB_RUNTIME_FAILED'))
        raise
    finally:runner.finish()


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(str(exc) if isinstance(exc,ValueError) else 'LAB_RUNTIME_FAILED; inspect private run logs',file=sys.stderr)
        raise SystemExit(2)
