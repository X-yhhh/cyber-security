#!/usr/bin/env python3
"""A6 正式 G3（J3/J4）编排：真实后端自动化、真实 lab 传感器回放与 root 常驻 PF 执行器。

与 lab_run.py 的 rehearse 共用冻结场景、对端映射、会话清单和报告流程，差异只在正式部分：
- 目标库为业务库，或用于整链路预演的业务库克隆（`--target clone`，结束删除并核对业务库不变）；
- 指定组合（默认 r4，已封存、独立批准）只激活到本次新建的回环 lab 资产，授权两小时；
- 后端开启自动化与 RabbitMQ 检测消费，命令由本次专用签名密钥签发；
- 执行器为 root 暂存副本中的 `executor run`/`recover`（scripts/p5/g3_executor.py），真实 PF；
- 会话 evidenceKind=lab，runner 为正式 mac-lab-runner，隔离证明由独立隔离核验身份签署，
  p5 取 A6 首轮正式 platform 报告，p6 取补齐 provenance/sourceEligibility 的 P6 final。
观察来自冻结 PCAP 的文件回放（不注入报文）；PF 规则只作用于 lo0 上 127.30.0.0/24 回放对端。
任何失败显式停止并保留目录，不重跑挑结果、不调阈值。
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from executor import pki
from executor.common import canonical
from executor.contract import capability_set_sha256, protected_ports_sha256
from scripts.p7 import j1_run, lab_report, lab_run
from scripts.p7.lab_run import (UTC, VERSION, at, clock_plan, digest, ensure_write, freeze_scenarios, load,
                                original_mapping, require, sha, stamp, uid, write)

HOME = Path.home() / 'Workspace'
KEYS = HOME / 'ai/keys'
BUSINESS = 'cyber_security'
R4_BUNDLE = '74f1e067-538b-44aa-977d-fe3f6ff0a581'
PLATFORM_RUNNER = 'mac-lab-runner/2026-10-10'
# lab 会话契约的 runnerIdentity 只允许 [A-Za-z0-9_.:-]，正式会话另用不含 '/' 的 lab runner 身份。
RUNNER = 'mac-lab-runner-2026-10-12'
ISOLATION = 'lab-isolation-verifier/2026-10-12'
EVALUATOR = 'p6-evaluator/2026-10-10'
PLATFORM_REF = 'reports/a6-20261012/round1/platform.json'
A18_FINAL_REF = 'reports/a18-20261012/business/lab-m2-final.json'
P6_FINAL_REF = 'reports/g3-20261012/p6-final-provenance.json'
OFFICIAL_TRUST = KEYS / 'cyber-guard-trust/report-trust.json'
PROTECTION = ROOT / 'scripts/p5/lab-protection.json'
SOURCE_ELIGIBILITY = ['brute_force:model:', 'dos_flood:model:', 'dos_slow:model:', 'port_scan:model:', 'port_scan:rule:scan-ports']


def keychain(service):
    return j1_run.secret(service)


def signer(path):
    return serialization.load_der_private_key(Path(path).read_bytes(), None)


def sign(payload, key, key_id):
    from scripts.p5.platform_report import sign as envelope
    return envelope(payload, key, key_id)


def ensure_identity(trust_file, name, directory, filename):
    """0600 私钥；公钥只追加到指定信任文件，门禁预演使用运行目录内的独立身份。"""
    path = directory / filename
    if not path.exists():
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key = signer(path)
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    trust = load(trust_file)
    if trust.get(name) != public:
        require(name not in trust, 'LAB_IDENTITY_TRUST_CONFLICT')
        trust[name] = public
        temporary = Path(str(trust_file) + '.next')
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            stream.write(json.dumps(trust, separators=(',', ':')))
        temporary.replace(trust_file)
    return key


def p6_provenance():
    """数据/切分/标签/代码摘要取自 P6 第 2 次评价计划与 closeout，不新算任何成绩。"""
    plan = load(HOME / 'ai/artifacts/cyber-guard/packages/host-guard-round2-20261011-r4/evaluation-plan.json')
    closeout = load(ROOT / '.cache/p6-20261009/closeout.json')
    labels = load(ROOT / '.cache/p3-a-20261007/frozen/manifest.json')
    return {'datasetSha256': plan['testDatasetSha256'], 'splitSha256': plan['splitManifestSha256'],
            'labelRulesSha256': labels['labelReviewSignoffSha256'], 'codeSha256': digest(closeout['codeSha256'])}


def ensure_p6_final(artifacts):
    """A18 正式 final 的同一评价结论，补齐 lab 准入需要的 provenance 与按来源离线资格；由同一评价身份签发。"""
    path = artifacts / P6_FINAL_REF
    if not path.exists():
        base = load(artifacts / A18_FINAL_REF)['payload']
        closeout = load(ROOT / '.cache/p6-20261009/closeout.json')['sourceEligibility']
        eligible = sorted([f + ':model:' for f, v in closeout.items() if v['model']['offlineEligible']] +
                          [f + ':rule:' + r for f, v in closeout.items() for r, x in v.get('rules', {}).items() if x['offlineEligible']])
        require(eligible == SOURCE_ELIGIBILITY, 'LAB_P6_ELIGIBILITY_CHANGED')
        payload = dict(base, provenance=p6_provenance(), sourceEligibility=eligible,
                       supersedes={'reportRef': A18_FINAL_REF, 'sha256': sha(artifacts / A18_FINAL_REF)},
                       authorization='A6 G3 2026-10-12',
                       limits=base['limits'] + '；sourceEligibility 仅为离线数值资格（P6 closeout），自动资格仍待 G3')
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        ensure_write(path, sign(payload, signer(KEYS / 'cyber-guard-evaluator/evaluator.der'), EVALUATOR))
    return {'ref': P6_FINAL_REF, 'sha256': sha(path), 'runnerIdentity': EVALUATOR}


def validate_arguments(args):
    """在取密、建目录或克隆前拒绝越界参数；合成证据仅允许进入独立克隆预演。"""
    require(not args.admission_probe or args.target == 'clone', 'LAB_PROBE_CLONE_ONLY')
    require(args.probe_seconds > 0, 'LAB_PROBE_DURATION_INVALID')
    if args.gate_rehearsal:
        require(args.target == 'clone' and args.admission_probe, 'LAB_GATE_CLONE_PROBE_ONLY')
        require(re.fullmatch(r'cyber_guard_[a-z0-9_]{1,52}', args.source_schema), 'LAB_GATE_SOURCE_INVALID')
        trust = args.report_trust
        require(trust.is_file() and not trust.is_symlink() and trust.resolve() != OFFICIAL_TRUST.resolve(),
                'LAB_GATE_CLONE_TRUST_REQUIRED')
        require(not OFFICIAL_TRUST.exists() or not trust.samefile(OFFICIAL_TRUST), 'LAB_GATE_CLONE_TRUST_REQUIRED')
    else:
        require(args.source_schema == BUSINESS, 'LAB_FORMAL_SOURCE_MUST_BE_BUSINESS')
    if not args.admission_probe:
        require(args.rendezvous is not None and args.stage_manifest and args.authorization_reference,
                'LAB_ROOT_ARGUMENTS_REQUIRED')
    require(args.final_ref is not None or args.subject_sha256 == lab_run.R4_SUBJECT_SHA256, 'LAB_FINAL_REF_REQUIRED')
    try:
        require(str(uuid.UUID(args.bundle_id)) == args.bundle_id, 'LAB_BUNDLE_ID_INVALID')
    except (ValueError, TypeError) as error:
        raise ValueError('LAB_BUNDLE_ID_INVALID') from error


class Rabbit:
    """每次运行独立 vhost，结束删除，不触碰已有 vhost。"""
    def __init__(self, name):
        self.name, self.user = name, 'admin'
        self.password = keychain('com.xyh.cyber-security.rabbitmq-it.password')
    def call(self, method, path, body=None):
        token = base64.b64encode(f'{self.user}:{self.password}'.encode()).decode()
        request = urllib.request.Request('http://127.0.0.1:15672/api' + path, method=method,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers={'Authorization': 'Basic ' + token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    def create(self):
        quoted = urllib.parse.quote(self.name, safe='')
        self.call('PUT', '/vhosts/' + quoted)
        self.call('PUT', f'/permissions/{quoted}/{self.user}', {'configure': '.*', 'write': '.*', 'read': '.*'})
    def delete(self):
        self.call('DELETE', '/vhosts/' + urllib.parse.quote(self.name, safe=''))


class Formal(lab_run.Runner):
    # 子类可缩短演示窗口；正式 G3 默认值保持冻结时的两小时，不改变原流程。
    authorization_minutes = 120
    authorization_backdate_seconds = 30
    formal_g3_eligible = True
    human_session = j1_run.Session
    csrf_path = '/api/v1/auth/csrf'
    session_timeout_seconds = 7200

    def scenario_rows(self):
        return freeze_scenarios(self.source, self.artifacts)

    def __init__(self, args):
        validate_arguments(args)
        super().__init__(args)
        self.target = BUSINESS if args.target == 'business' else 'cyber_guard_g3pf_' + uuid.uuid4().hex[:20]
        self.schema = self.target
        self.rabbit = Rabbit('cyber-security-g3-' + uuid.uuid4().hex[:12])
        self.rabbit_created = False
        self.root_dir = None
        self.state.update(schemaName=self.schema, mode='pf-' + args.target, evidenceKind='lab',
                          formalG3Eligible=not args.admission_probe and self.formal_g3_eligible, realPF=not args.admission_probe,
                          gateRehearsal=args.gate_rehearsal, sourceSchema=args.source_schema, rabbitVhost=self.rabbit.name)

    # ---- 准备 ----
    def operator(self):
        """独立申请身份：platform_admin + model_operator（全局），与审批人 guard-reviewer 分离。"""
        directory = self.work / 'private/operator' if self.args.gate_rehearsal else KEYS / 'cyber-guard-g3-operator'
        username = 'g3-gate-' + self.state['sessionId'][:8] if self.args.gate_rehearsal else 'g3-operator'
        path = directory / 'credentials.json'
        if not path.exists():
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            write(path, {'username': username, 'password': secrets.token_urlsafe(18), 'roles': ['platform_admin', 'model_operator'],
                         'purpose': 'A6 G3 申请/运行身份（与 guard-reviewer 分离）', 'createdAt': stamp()})
        credentials = load(path)
        exists = int(self.db.query(f"SELECT COUNT(*) FROM sys_user WHERE username='{username}'", self.schema))
        if not exists:
            lib = ROOT / '.cache/b3-20261010/lib'
            hashed = subprocess.run([str(self.args.java), '-cp', f'{lib}/spring-security-crypto-6.5.11.jar:{lib}/spring-jcl-6.2.19.jar',
                                     str(ROOT / '.cache/b3-20261010/HashPassword.java')], input=credentials['password'],
                                    capture_output=True, text=True, check=True, timeout=60).stdout
            require(hashed.startswith('$2a$12$') and len(hashed) == 60, 'LAB_OPERATOR_HASH_INVALID')
            key = uid()
            self.db.query("INSERT INTO sys_user(user_key,username,display_name,status,password_hash) VALUES "
                          f"('{key}','{username}','A6 G3 operator','active','{hashed}');"
                          "INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,'global','*' FROM sys_user u "
                          f"JOIN sys_role r ON r.role_key IN ('platform_admin','model_operator') WHERE u.user_key='{key}';", self.schema)
        roles = self.db.query("SELECT r.role_key FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id JOIN sys_role r ON r.id=ur.role_id "
                              f"WHERE u.username='{username}' ORDER BY r.role_key", self.schema).decode().split()
        require(roles == ['model_operator', 'platform_admin'], 'LAB_OPERATOR_ROLES_INVALID')
        write(self.work / 'private/isolated-operator.json', {'username': credentials['username'], 'password': credentials['password']})

    def start_backend(self):
        tls = self.work / 'private/tls'
        password = j1_run.tls_files(tls)
        write(self.work / 'private/backend-keystore.json', {'password': password})
        signing = Ed25519PrivateKey.generate()
        self.signing_id = 'g3-command-' + self.state['sessionId'][:8]
        signing_path = self.work / 'private/command-signing.der'
        signing_path.write_bytes(signing.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        signing_path.chmod(0o600)
        now = datetime.now(UTC)
        self.command_trust = {self.signing_id: {'status': 'active', 'publicKeyDer': base64.b64encode(signing.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            'notBefore': (now - timedelta(minutes=1)).isoformat().replace('+00:00', 'Z'), 'notAfter': (now + timedelta(hours=4)).isoformat().replace('+00:00', 'Z')}}
        self.rabbit.create()
        self.rabbit_created = True
        env = dict(os.environ, DB_URL='jdbc:mysql://127.0.0.1:3306/' + self.schema, DB_USERNAME='root', DB_PASSWORD=self.db.env['MYSQL_PWD'],
                   DB_POOL_SIZE='16', LOGIN_THROTTLE_HMAC_KEY=keychain('com.xyh.cyber-security.login-throttle-hmac'),
                   SERVER_PORT=str(self.args.port), SERVER_ADDRESS='127.0.0.1', SESSION_COOKIE_SECURE='true',
                   OUTBOX_RELAY_ENABLED='true', INGEST_CONSUMER_ENABLED='true', CYBER_DRIFT_ENABLED='false', OUTBOX_RELAY_POLL_MS='200',
                   RABBITMQ_HOST='127.0.0.1', RABBITMQ_PORT='5672', RABBITMQ_VHOST=self.rabbit.name,
                   RABBITMQ_USERNAME=self.rabbit.user, RABBITMQ_PASSWORD=self.rabbit.password,
                   SERVER_SSL_ENABLED='true', SERVER_SSL_CLIENT_AUTH='want', SERVER_SSL_ENABLED_PROTOCOLS='TLSv1.3',
                   SERVER_SSL_KEY_STORE=str(tls / 'server.p12'), SERVER_SSL_KEY_STORE_TYPE='PKCS12', SERVER_SSL_KEY_STORE_PASSWORD=password,
                   SERVER_SSL_TRUST_STORE=str(tls / 'trust.p12'), SERVER_SSL_TRUST_STORE_TYPE='PKCS12', SERVER_SSL_TRUST_STORE_PASSWORD=password)
        self.base = 'https://127.0.0.1:' + str(self.args.port)
        self.context = j1_run.ssl_context(tls)
        jfr = ['-XX:StartFlightRecording=filename=' + str(self.work / 'backend.jfr') + ',settings=profile,dumponexit=true'] if self.args.jfr else []
        self.backend = self.start_process([self.args.java, '--enable-native-access=ALL-UNNAMED', '-Xmx3g', *jfr,
            '-Dcyber.guard.automation-enabled=true', '-Dcyber.guard.lab-rehearsal-enabled=false',
            '-Dcyber.guard.bootstrap-reports-enabled=' + ('true' if self.args.gate_rehearsal else 'false'),
            '-Dcyber.guard.signing-key-id=' + self.signing_id, '-Dcyber.guard.signing-key-file=' + str(signing_path),
            '-Dcyber.guard.protection-file=' + str(PROTECTION),
            '-Dcyber.guard.artifact-root=' + str(self.artifacts), '-Dcyber.guard.report-trust-file=' + str(self.args.report_trust),
            '-Dcyber.model-artifact.root=' + str(HOME / 'deliveries'),
            '-Dspring.session.timeout=4h', '-Dserver.servlet.session.timeout=4h', '-Dserver.tomcat.threads.max=24',
            '-jar', self.work / 'bin/backend.jar'], 'backend.log', env)
        for _ in range(120):
            require(self.backend.poll() is None, 'LAB_BACKEND_EXITED')
            try:
                urllib.request.urlopen(self.base + self.csrf_path, context=self.context, timeout=2).close()
                break
            except OSError:
                time.sleep(1)
        else:
            raise ValueError('LAB_BACKEND_TIMEOUT')
        self.op = self.human_session(self.base, self.context).login(load(self.work / 'private/isolated-operator.json'))
        reviewer = load(self.args.reviewer_file)
        self.rev = self.human_session(self.base, self.context).login({'username': reviewer.get('username', 'guard-reviewer'), 'password': reviewer['password']})

    def prepare_bundle(self):
        """核对指定组合与报告的绑定；非 r4 必须提供自身 final，不能重贴旧报告标签。"""
        plan = load(self.args.import_plan)
        self.policy = plan['decisionPolicy']
        self.bundle = self.args.bundle_id
        view = self.op.v2('/release-bundles/' + self.bundle, method='GET')
        require(view['status'] in ('approved', 'active') and view['subjectSha256'] == self.args.subject_sha256
                and view['environment'] == 'lab', 'LAB_BUNDLE_NOT_APPROVED')
        self.subject_sha, self.versions = view['subjectSha256'], plan['releaseBundle']['protocolVersions']
        self.plan_sha = self.policy['evaluationPlanSha256']
        subject = json.loads(self.db.query("SELECT subject_json FROM guard_release_bundle WHERE public_id='" + self.bundle + "'", self.schema))
        require(digest(subject) == self.subject_sha and subject['protocolVersions'] == self.versions
                and subject['policySha256'] == digest(self.policy)
                and subject['extractorSha256'] == plan['releaseBundle']['extractorSha256']
                and subject['evaluationPlanSha256'] == self.plan_sha, 'LAB_IMPORT_PLAN_MISMATCH')
        platform_ref, platform = self.read_proof(self.args.platform_ref, 'platform')
        if self.args.final_ref is None:
            require(self.subject_sha == lab_run.R4_SUBJECT_SHA256, 'LAB_FINAL_REF_REQUIRED')
            ensure_p6_final(self.artifacts)
        final_ref, final = self.read_proof(self.args.final_ref or P6_FINAL_REF, 'final')
        self.executor_sha = platform['executorSha256']
        require(self.executor_sha == lab_run.executor_digest(), 'LAB_EXECUTOR_CODE_CHANGED')
        provenance = final['provenance']
        self.provenance = dict({k: provenance[k] for k in ('datasetSha256', 'splitSha256', 'labelRulesSha256', 'codeSha256')},
                               modelSha256=self.source['bindings']['modelSha256'], policySha256=digest(self.policy),
                               extractorSha256=plan['releaseBundle']['extractorSha256'], executorSha256=self.executor_sha)
        self.proofs = {'platform': platform_ref, 'final': final_ref}
        self.state.update(bundleId=self.bundle, bundleRevision=view['revision'], subjectSha256=self.subject_sha, bundleStatusBefore=view['status'])

    def read_proof(self, ref, kind):
        """报告只读且保持原签名；正式路径拒绝引导/合成证据，后端再验签。"""
        path = (self.artifacts / ref).resolve()
        code = 'LAB_P5_PROOF_INVALID' if kind == 'platform' else 'LAB_P6_PROOF_INVALID'
        require(not Path(ref).is_absolute() and path.is_relative_to(self.artifacts), code)
        envelope = load(path)
        payload = envelope['payload']
        require(payload.get('runKind') == kind and payload.get('passed') is True
                and payload.get('subjectSha256') == self.subject_sha
                and payload.get('evaluationPlanSha256') == self.plan_sha
                and payload.get('protocolVersions') == self.versions and envelope.get('keyId'), code)
        evidence = payload.get('evidenceKind')
        require(self.args.gate_rehearsal or evidence not in ('bootstrap', 'synthetic'), code)
        require(kind != 'platform' or self.args.gate_rehearsal or evidence == 'real_pf', code)
        return {'ref': ref, 'sha256': sha(path), 'runnerIdentity': envelope['keyId']}, payload

    def mapping_entries(self):
        """回放对端统一映射到 127.30.0.0/24；每个原始对端一个执行对象，攻击与正常不共享。"""
        entries, allowed = [], []
        for row in self.rows:
            original = self.original[row['scenarioId']]
            scope = 'peer_inbound' if row['family'] in ('port_scan', 'normal') else 'peer_service'
            for original_peer in original['peers']:
                peer = '127.30.0.' + str(len(entries) + 2)
                parts = ['host-guard-peer-v1', self.asset, self.sensor, 1, peer]
                key = hmac.new(self.peer_secret, json.dumps(parts, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
                entries.append(dict(scenarioId=row['scenarioId'], originalLocal=original['host'], originalPeer=original_peer,
                                    canaryLocal='127.0.0.1', canaryPeer=peer, peerKey=key, direction='inbound', transport='tcp',
                                    addressFamily='ipv4', scope=scope, servicePort=original['port']))
                for port in ([0] if scope == 'peer_inbound' else original['ports']):
                    allowed.append(dict(local='127.0.0.1', peer=peer, peerKey=key, direction='inbound', scope=scope, servicePort=port))
        require(len(entries) <= 100, 'LAB_TOO_MANY_PEERS')
        return entries, allowed

    def prepare_identities(self):
        base = datetime.now(UTC)
        base = base.replace(microsecond=(base.microsecond // 1000) * 1000)
        self.valid_from, self.valid_until = base - timedelta(seconds=self.authorization_backdate_seconds), base + timedelta(minutes=self.authorization_minutes)
        self.asset = self.op.v2('/assets', dict(assetKey=self.work.name, platform='macos', environment='lab', owner='A6 G3 loopback lab (lo0)'))['id']
        self.boot, self.scope = uid(), uid()
        sensor = self.op.v2('/sensors', dict(assetId=self.asset, platform='macos', captureScopeId=self.scope))
        self.sensor = sensor['id']
        (self.work / 'private/sensor.credential').write_text(sensor['credential'])
        (self.work / 'private/sensor.credential').chmod(0o600)
        probe_ref = 'user-mode-admission-probe' if self.args.admission_probe else 'root-stage:' + self.args.stage_manifest
        executor = self.op.v2('/executors', dict(assetId=self.asset, platform='macos', capabilityProbeRef=probe_ref))
        self.executor, self.executor_token = executor['id'], executor['credential']
        (self.work / 'private/executor.credential').write_text(executor['credential'])
        (self.work / 'private/executor.credential').chmod(0o600)
        caps = load(self.args.import_plan)['existingCapabilities']
        self.caps = caps
        scopes = []
        for row in self.rows:
            local = self.original[row['scenarioId']]
            scope = 'peer_inbound' if row['family'] in ('port_scan', 'normal') else 'peer_service'
            family = row['family'] if row['family'] != 'normal' else 'port_scan'
            cap = next(c['id'] for c in caps if c['payload']['family'] == family)
            value = dict(direction='inbound', transport='tcp', addressFamily='ipv4', scope=scope,
                         servicePort=None if scope == 'peer_inbound' else local['port'], capabilityId=cap)
            if value not in scopes:
                scopes.append(value)
        auth = self.op.v2('/assets/' + self.asset + '/authorizations', dict(interfaces=['lo0'], observationAllowed=True, executionScopes=scopes,
                          validFrom=self.valid_from.isoformat().replace('+00:00', 'Z'), validUntil=self.valid_until.isoformat().replace('+00:00', 'Z'),
                          evidenceRef=str(self.artifact_dir.relative_to(self.artifacts)) + '/source.json'))
        self.auth = auth['id']
        approved = self.rev.v2('/authorizations/' + self.auth + '/decisions', dict(decision='approve', reason='本机回环 lab 独立批准，窗口不超过 %s 分钟' % self.authorization_minutes), 1)
        self.auth_revision = approved['revision']
        view = self.op.v2('/release-bundles/' + self.bundle, method='GET')
        activation = self.rev.v2('/release-bundles/' + self.bundle + '/activations', dict(assetIds=[self.asset], authorizationIds=[self.auth]), view['revision'])
        self.state['activation'] = activation
        if self.target == BUSINESS:
            lab_run.formal_r4_preflight(self.db, self.bundle, self.args.subject_sha256)
        config = dict(contractVersion='host-guard/5.0.0-rc.2', profileSha256=load(self.args.import_plan)['releaseBundle']['featureProfileSha256'],
                      captureHealthVersion=self.versions['health'], interfaceIds=['lo0'], limits={'maxBatchSize': 100},
                      captureScopeId=self.scope, addressFamily='ipv4', buildSha256=sha(self.work / 'bin/guardlive'))
        cid = self.op.v2('/sensors/' + self.sensor + '/configs', config)['id']
        self.rev.v2('/sensor-configs/' + cid + '/decisions', dict(decision='approve', reason='A6 G3 lab replay build'), 1)
        self.op.machine(self.sensor, sensor['credential'], 'heartbeats', dict(bootId=self.boot, version='A6 G3', configHash=digest(config), lastSequence=0, clockSkewMs=None))
        self.save_state()

    def start_executor(self):
        """root 执行器输入：控制面登记的身份与能力；本机 PF 范围由 root 侧固定组装。"""
        self.peer_secret = os.urandom(32)
        (self.work / 'private/peer.key').write_bytes(self.peer_secret)
        (self.work / 'private/peer.key').chmod(0o600)
        self.budget_key = os.urandom(32)
        (self.work / 'private/budget.key').write_bytes(self.budget_key)
        (self.work / 'private/budget.key').chmod(0o600)
        self.fingerprints = pki.create(self.work / 'private/ipc')
        self.target_port = self.args.port + 1
        self.local_entries, self.allowed = self.mapping_entries()
        protection = load(PROTECTION)
        inbound = sorted(c['id'] for c in self.caps if c['payload'].get('scope') == 'peer_inbound')
        servicePorts = sorted({e['servicePort'] for e in self.local_entries if e['scope'] == 'peer_service'})
        c = dict(capabilityIds=sorted(c['id'] for c in self.caps), inboundCapabilities=[
            {'capabilityId': cap, 'protectionSetSha256': digest(protection), 'protectedPortsSha256': protected_ports_sha256(protection['protectedServicePorts'])} for cap in inbound])
        tls, ipc = self.work / 'private/tls', self.work / 'private/ipc'
        data = dict(assetId=self.asset, executorId=self.executor, sensorId=self.sensor, captureScopeId=self.scope,
                    authorization=dict(id=self.auth, revision=self.auth_revision, status='active',
                                       validFrom=self.valid_from.isoformat().replace('+00:00', 'Z'), validUntil=self.valid_until.isoformat().replace('+00:00', 'Z')),
                    controlPlaneURL=self.base, targetURL='https://127.0.0.1:' + str(self.target_port),
                    peerAddresses=sorted({e['canaryPeer'] for e in self.local_entries}, key=lambda a: int(a.rsplit('.', 1)[1])),
                    servicePorts=servicePorts, capabilityIds=c['capabilityIds'], inboundCapabilityIds=inbound,
                    capabilityHash=capability_set_sha256(c), protection=protection, bundleId=self.bundle, policySha256=digest(self.policy),
                    commandTrust=self.command_trust, credential=self.executor_token, budgetKey=base64.b64encode(self.budget_key).decode(),
                    controlPlaneCA=base64.b64encode((tls / 'ca.pem').read_bytes()).decode(),
                    targetCA=base64.b64encode((ipc / 'ca.pem').read_bytes()).decode(),
                    targetCertificate=base64.b64encode((ipc / 'executor.pem').read_bytes()).decode(),
                    targetKey=base64.b64encode((ipc / 'executor.key').read_bytes()).decode())
        self.root_dir = self.args.rendezvous or self.work / 'private/probe-executor'
        if self.args.rendezvous is None and self.args.admission_probe:
            self.root_dir.mkdir(mode=0o700)
        require(self.root_dir.is_dir() and not (self.root_dir / 'input.json').exists(), 'LAB_RENDEZVOUS_INVALID')
        self.state['executorCapabilityHash'] = data['capabilityHash']
        if self.args.admission_probe:
            return self.probe_executor(data)
        write(self.root_dir / 'input.json', data)
        deadline = time.monotonic() + self.args.root_timeout
        while not (self.root_dir / 'boot.json').exists():
            require(not (self.root_dir / 'error.json').exists(), 'LAB_ROOT_EXECUTOR_FAILED')
            require(time.monotonic() < deadline, 'LAB_ROOT_EXECUTOR_NOT_READY')
            time.sleep(1)
        self.executor_boot = load(self.root_dir / 'boot.json')['executorBootId']
        # 执行器 boot 只能由控制面心跳登记；等待真实执行器心跳进入数据库。
        for _ in range(60):
            row = self.db.query(f"SELECT boot_id FROM guard_executor WHERE public_id='{self.executor}'", self.schema).decode().strip()
            if row == self.executor_boot:
                break
            time.sleep(1)
        else:
            raise ValueError('LAB_EXECUTOR_HEARTBEAT_MISSING')
        self.state.update(executorBootId=self.executor_boot)
        self.save_state()

    def probe_executor(self, data):
        """仅诊断（克隆）：用户态只发执行器心跳登记 boot，不领取命令、不安装规则。"""
        import threading
        self.executor_boot = uid()
        http = j1_run.Session(self.base, self.context)
        stop = self.probe_stop = threading.Event()
        self.probe_latency = []
        def beat():
            while not stop.wait(1):
                began = time.monotonic()
                try:
                    http.call('POST', '/api/v2/machine/executors/' + self.executor + '/heartbeats', dict(bootId=self.executor_boot, adapterVersion='hostguard-executor/1',
                              capabilityHash=data['capabilityHash'], pendingRecovery=False, activeRuleCount=0, clockSkewMs=0),
                              {'Authorization': 'Bearer ' + self.executor_token, 'Idempotency-Key': uid()}, (200,))
                    self.probe_latency.append([stamp(), round(time.monotonic() - began, 3)])
                except Exception as error:
                    self.state.setdefault('probeHeartbeatErrors', []).append(str(error)[:120])
        normalized = dict(digestVersion='guard-state/1', assetId=self.asset, executorId=self.executor, executorBootId=self.executor_boot, rules=[], pendingRevocations=[])
        headers = lambda: {'Authorization': 'Bearer ' + self.executor_token, 'Idempotency-Key': uid()}
        http.call('POST', '/api/v2/machine/executors/' + self.executor + '/heartbeats', dict(bootId=self.executor_boot, adapterVersion='hostguard-executor/1',
                  capabilityHash=data['capabilityHash'], pendingRecovery=False, activeRuleCount=0, clockSkewMs=0), headers(), (200,))
        http.call('POST', '/api/v2/machine/executors/' + self.executor + '/reconciliations', dict(executorBootId=self.executor_boot, observedAt=stamp(),
                  digestVersion='guard-state/1', stateDigest=digest(normalized), ownedRules=[], pendingRevocations=[], recoveryErrors=[]), headers(), (200,))
        self.probe_thread = threading.Thread(target=beat, daemon=True)
        self.probe_thread.start()
        time.sleep(3)
        row = self.db.query(f"SELECT boot_id FROM guard_executor WHERE public_id='{self.executor}'", self.schema).decode().strip()
        self.state['probeExecutorBootRegistered'] = row == self.executor_boot
        self.state.update(executorBootId=self.executor_boot, admissionProbe=True, realPF=False, formalG3Eligible=False)

    def prepare_targets(self):
        ipc = self.work / 'private/ipc'
        tls = self.work / 'private/tls'
        backend_tls = dict(baseUrl=self.base, caFile=str(tls / 'ca.pem'), certificateFile=str(tls / 'client.pem'), keyFile=str(tls / 'client.key'))
        config = dict(listen='127.0.0.1:' + str(self.target_port), certificateFile=str(ipc / 'server.pem'), keyFile=str(ipc / 'server.key'), caFile=str(ipc / 'ca.pem'),
                      authorizedUntil=self.valid_until.isoformat().replace('+00:00', 'Z'),
                      scope=dict(AssetID=self.asset, SensorID=self.sensor, BootID=self.boot, CaptureScopeID=self.scope, Environment='lab',
                                 ExecutorBootID=self.executor_boot, KeyEpoch=1, LocalAddresses=['127.0.0.1'],
                                 CollectorCertSHA256=self.fingerprints['collector'], ExecutorCertSHA256=self.fingerprints['executor'], MaxReferences=10000),
                      registration=dict(backend=backend_tls, credentialFile=str(self.work / 'private/executor.credential'),
                                        budgetKeyFile=str(self.work / 'private/budget.key'), identityFile=str(self.work / 'private/registrar.json'),
                                        executorId=self.executor, allowed=self.allowed))
        write(self.work / 'private/targets.json', config)
        self.targets = self.start_process([self.work / 'bin/guardtargets', '-config', self.work / 'private/targets.json'], 'targets.log')
        import socket, ssl
        self.target_context = ssl.create_default_context(cafile=str(ipc / 'ca.pem'))
        self.target_context.load_cert_chain(str(ipc / 'collector.pem'), str(ipc / 'collector.key'))
        for _ in range(30):
            require(self.targets.poll() is None, 'LAB_TARGETS_EXITED')
            try:
                with socket.create_connection(('127.0.0.1', self.target_port), .2):
                    break
            except OSError:
                time.sleep(.1)
        self.initial = []
        scenarios = {row['scenarioId']: row for row in self.rows}
        for entry in self.local_entries:
            observation = load(ROOT / 'docs/contracts/examples/observation.json')
            now = stamp()
            observation.update(assetId=self.asset, sensorId=self.sensor, bootId=self.boot, captureScopeId=self.scope, environment='lab',
                               peerKey=entry['peerKey'], keyEpoch=1, asOf=now, lastPacketAt=now, emittedAt=now,
                               firstSeenAt=(lab_report.timestamp(now) - timedelta(microseconds=round(observation['features']['elapsedMs'] * 1000))).isoformat().replace('+00:00', 'Z'))
            observation['quality'].update(captureGap=False, latePacket=False, truncated=False, offloadSuspected=False, capacityDrop=False, clockSkewMs=0)
            observation['direction'] = 'inbound'
            observation['servicePort'] = entry['servicePort']
            request = dict(observation=observation, endpoints={'Local': '127.0.0.1:' + str(entry['servicePort']), 'Peer': entry['canaryPeer'] + ':55000', 'Protocol': 6}, scope=entry['scope'])
            with urllib.request.urlopen(urllib.request.Request('https://127.0.0.1:' + str(self.target_port) + '/v1/targets/lease', data=canonical(request),
                                                               headers={'Content-Type': 'application/json'}), context=self.target_context, timeout=3) as response:
                lease = json.loads(response.read())
            ref = lease['ref'] if 'ref' in lease else lease['targetRef']
            binding = json.loads(self.db.query("SELECT JSON_OBJECT('id',public_id) FROM guard_target_binding WHERE target_ref='" + ref + "'", self.schema))
            self.initial.append(dict(scenarioId=scenarios[entry['scenarioId']]['scenarioId'], targetBindingId=binding['id'], peerKey=entry['peerKey'],
                                     keyEpoch=1, captureScopeId=self.scope, targetRef=ref))

    def freeze_session(self):
        start = datetime.now(UTC) + timedelta(seconds=140)
        clock = clock_plan(self.rows, start, staggered=True)
        scenario_file, mapping_file = self.artifact_dir / 'scenarios.json', self.artifact_dir / 'mapping.json'
        write(scenario_file, dict(contractVersion=VERSION, scenarios=self.rows))
        mapping_id = uid()
        write(mapping_file, dict(contractVersion=VERSION, mappingId=mapping_id, sessionId=self.state['sessionId'], entries=self.initial))
        manifest = dict(contractVersion=VERSION, sessionId=self.state['sessionId'], assetId=self.asset, bundleId=self.bundle, authorizationId=self.auth,
                        authorizationRevision=self.auth_revision, environment='lab', runnerIdentity=self.runner_name, evidenceKind='lab',
                        validFrom=self.valid_from.isoformat().replace('+00:00', 'Z'), validUntil=self.valid_until.isoformat().replace('+00:00', 'Z'),
                        timeoutSeconds=self.session_timeout_seconds, protocolVersions=self.versions, subjectSha256=self.subject_sha, evaluationPlanSha256=self.plan_sha,
                        sensorId=self.sensor, bootId=self.boot, executorId=self.executor, executorBootId=self.executor_boot,
                        mappingRef=str(mapping_file.relative_to(self.artifacts)), mappingSha256=sha(mapping_file), mappingId=mapping_id,
                        scenarioRef=str(scenario_file.relative_to(self.artifacts)), scenarioSha256=sha(scenario_file), provenance=self.provenance, time=clock, speed=1)
        mechanism = ('file replay of frozen PCAPs (no packet injection); replay peers mapped to 127.30.0.0/24 on lo0; '
                     'backend/guardtargets listen on 127.0.0.1 only; ')
        if self.args.admission_probe:
            mechanism += 'user-mode executor sends heartbeats only; no command claims or PF rules'
            verified_by = 'assistant: isolated clone admission probe (no PF execution)'
        else:
            mechanism += 'PF rules confined to the executor anchor on lo0'
            verified_by = 'assistant on behalf of user: ' + self.args.authorization_reference
        isolation = self.signed('isolation', dict(sessionId=manifest['sessionId'], assetId=self.asset, mappingSha256=manifest['mappingSha256'], executorId=self.executor,
                                validUntil=manifest['validUntil'], networkIsolationVerified=True, evidenceKind='lab',
                                mechanism=mechanism, verifiedBy=verified_by), True)
        admission = self.signed('admission', dict(sessionId=manifest['sessionId'], subjectSha256=self.subject_sha, j1Passed=True, j2Registered=True, evidenceKind='lab',
                                j1Closeout=sha(ROOT / '.cache/j1v9-20261011/closeout.json'), j2Scenario=sha(self.args.scenario),
                                plannedM2=self.source['plannedM2'], authorization=self.args.authorization_reference or 'clone-admission-probe'))
        manifest['proofs'] = dict(p5=self.proofs['platform'], p6=self.proofs['final'], isolation=isolation, admission=admission)
        ref = self.signed('session', manifest)
        self.manifest = manifest
        self.state.update(manifestRef=ref, manifest=manifest, assetId=self.asset, sensorId=self.sensor, bootId=self.boot,
                          executorId=self.executor, executorBootId=self.executor_boot)
        self.state['frozenFiles'].update({str(scenario_file): sha(scenario_file), str(mapping_file): sha(mapping_file)})
        private = dict(contractVersion='host-guard-sensor-mapping/1.1', sessionId=manifest['sessionId'], sessionSha256=digest(manifest), mappingId=mapping_id,
                       mappingSha256=manifest['mappingSha256'], scenarioSha256=manifest['scenarioSha256'], buildSha256=sha(self.work / 'bin/guardlive'),
                       extractorSha256=manifest['provenance']['extractorSha256'], entries=self.local_entries)
        private_path = self.artifacts / self.signed('private-mapping', private)['ref']
        ipc, tls = self.work / 'private/ipc', self.work / 'private/tls'
        config = dict(assetId=self.asset, sensorId=self.sensor, bootId=self.boot, captureScopeId=self.scope, environment='lab', captureScope='all_inbound_tcp',
                      localAddresses=sorted(set(v['host'] for v in self.original.values())), secretFile=str(self.work / 'private/peer.key'), keyEpoch=1,
                      interface='lo0', allowedInterfaces=['lo0'], authorizedUntil=manifest['validUntil'],
                      upload=dict(baseUrl=self.base, caFile=str(tls / 'ca.pem'), certificateFile=str(tls / 'client.pem'), keyFile=str(tls / 'client.key'),
                                  credentialFile=str(self.work / 'private/sensor.credential'), spoolDir=str(self.work / 'spool'), healthWindowMs=1000),
                      lab=dict(runId=manifest['sessionId'], sessionSha256=digest(manifest), mappingSha256=manifest['mappingSha256'], scenarioId=self.rows[0]['scenarioId'],
                               mappingFile=str(private_path), trustFile=str(self.args.report_trust), eventsFile=str(self.work / 'observations-events.jsonl'), rehearsal=False,
                               targets=dict(baseUrl='https://127.0.0.1:' + str(self.target_port), caFile=str(ipc / 'ca.pem'), certificateFile=str(ipc / 'collector.pem'), keyFile=str(ipc / 'collector.key')),
                               inputs=[dict(scenarioId=r['scenarioId'], path=str(self.artifacts / r['pcapRef'])) for r in self.rows]))
        write(self.work / 'private/sensor.json', config)
        self.save_state()
        create = self.op.v2('/lab-validation-runs', dict(sessionRef=ref['ref'], sha256=ref['sha256'], runnerIdentity=self.runner_name))
        approved = self.rev.v2('/lab-validation-runs/' + manifest['sessionId'] + '/decisions', dict(decision='approve', reason='A6 G3 正式会话（J3/J4）'), create['revision'])
        self.op.v2('/lab-validation-runs/' + manifest['sessionId'] + '/starts', {}, approved['revision'])
        write(self.work / 'runtime.json', dict(realBackend=True, realSensor=True, realPF=not self.args.admission_probe,
                                               formalG3Eligible=not self.args.admission_probe and self.formal_g3_eligible, gateRehearsal=self.args.gate_rehearsal,
                                               automationEnabled=True, target=self.target,
                                               modelSha256=self.provenance['modelSha256'], speed=1, backendSha256=sha(self.work / 'bin/backend.jar'),
                                               sensorSha256=sha(self.work / 'bin/guardlive'), guardtargetsSha256=sha(self.work / 'bin/guardtargets'),
                                               stageManifestSha256=self.args.stage_manifest, replayOnly=True, packetInjection=False, startedAt=stamp()))

    # ---- 收尾 ----
    def asset_rows(self, sql):
        return [json.loads(line) for line in self.db.query(sql.replace('{asset}', "(SELECT id FROM asset WHERE public_id='" + self.asset + "')"), self.schema).decode().splitlines() if line.strip()]

    def drain(self):
        """采集结束后等待全部动作清理（TTL 或撤销）且执行器无规则，再请求 root 侧停止。"""
        require(not self.args.admission_probe, 'LAB_PROBE_HAS_NO_PF_EXECUTOR')
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = load(self.root_dir / 'status.json') if (self.root_dir / 'status.json').exists() else {}
            open_actions = int(self.db.query("SELECT COUNT(*) FROM guard_action WHERE asset_id=(SELECT id FROM asset WHERE public_id='" + self.asset +
                                             "') AND observed_state IN ('pending','dispatched','applied','uncertain')", self.schema) or 0)
            if status.get('activeRuleCount') == 0 and not status.get('pendingReceipts') and open_actions == 0:
                break
            time.sleep(3)
        self.state['drain'] = dict(at=stamp(), status=load(self.root_dir / 'status.json') if (self.root_dir / 'status.json').exists() else None)
        (self.root_dir / 'stop').write_text(stamp())
        deadline = time.monotonic() + 400
        while not (self.root_dir / 'result.json').exists():
            require(not (self.root_dir / 'error.json').exists() or (self.root_dir / 'result.json').exists(), 'LAB_ROOT_EXECUTOR_FAILED')
            require(time.monotonic() < deadline, 'LAB_ROOT_EXECUTOR_STOP_TIMEOUT')
            time.sleep(2)
        self.state['rootResult'] = load(self.root_dir / 'result.json')
        self.save_state()

    def collect(self):
        require(not self.args.admission_probe, 'LAB_PROBE_NOT_G3_EVIDENCE')
        view = self.op.v2('/lab-validation-runs/' + self.state['sessionId'], method='GET')
        if view['runStatus'] != 'completed':
            self.lab_op('completions', dict(outcome='completed', reason='all frozen PCAP segments finished; executor drained'))
        observations = {o['observationId']: o for o in map(json.loads, (self.work / 'observations.jsonl').read_text().splitlines())}
        decisions = self.asset_rows("SELECT JSON_OBJECT('id',public_id,'evidence',CAST(evidence_json AS JSON),'decision',decision) FROM guard_decision WHERE asset_id={asset} ORDER BY id")
        scenarios = {row['scenarioId']: row for row in self.rows}
        by_peer = {e['peerKey']: scenarios[e['scenarioId']] for e in self.local_entries}
        offsets = self.manifest['time']['scenarioOffsets']
        def scenario_of(trigger_id):
            trigger = observations.get(trigger_id)
            if trigger is None:
                return None, None
            return by_peer.get(trigger['peerKey']), trigger
        def in_window(scenario, trigger):
            delta = timedelta(microseconds=offsets[scenario['scenarioId']])
            return lab_report.timestamp(scenario['sourceStart']) + delta <= lab_report.timestamp(trigger['asOf']) <= lab_report.timestamp(scenario['sourceEnd']) + delta
        registered, failures = [], []
        def event(body):
            try:
                self.lab_op('events', body)
                registered.append(body)
            except RuntimeError as error:
                failures.append(dict(body, error=str(error)[-160:]))
        decision_scenario = {}
        for row in decisions:
            scenario, trigger = scenario_of(row['evidence'].get('triggerObservationId'))
            if scenario is None:
                continue
            decision_scenario[row['id']] = scenario
            if in_window(scenario, trigger) or row['evidence'].get('decision') in ('block_candidate', 'block') or row['decision'] in ('block', 'block_candidate'):
                event(dict(eventId=uid(), scenarioId=scenario['scenarioId'], kind='decision', referenceId=row['id']))
        commands = self.asset_rows("SELECT JSON_OBJECT('id',c.public_id,'decision',d.public_id) FROM guard_command c JOIN guard_action a ON a.id=c.action_id "
                                   "JOIN guard_decision d ON d.id=a.decision_id WHERE a.asset_id={asset} ORDER BY c.id")
        for row in commands:
            scenario = decision_scenario.get(row['decision'])
            if scenario is not None:
                event(dict(eventId=uid(), scenarioId=scenario['scenarioId'], kind='command', referenceId=row['id']))
        receipts = self.asset_rows("SELECT JSON_OBJECT('id',r.public_id,'decision',d.public_id,'projected',r.projected) FROM guard_action_receipt r "
                                   "JOIN guard_command c ON c.id=r.command_id JOIN guard_action a ON a.id=c.action_id JOIN guard_decision d ON d.id=a.decision_id "
                                   "WHERE a.asset_id={asset} ORDER BY r.id")
        for row in receipts:
            scenario = decision_scenario.get(row['decision'])
            if scenario is None:
                continue
            event(dict(eventId=uid(), scenarioId=scenario['scenarioId'], kind='receipt', referenceId=row['id']))
            if row['projected']:
                event(dict(eventId=uid(), scenarioId=scenario['scenarioId'], kind='verified_receipt', referenceId=row['id']))
        first = {}
        for line in (self.work / 'observations-events.jsonl').read_text().splitlines():
            row = json.loads(line)
            first.setdefault(row['scenarioId'], row)
        for row in first.values():
            event(row)
        for replay in load(self.work / 'sensor-report.json')['replays']:
            value = dict(contractVersion=VERSION, sessionId=self.state['sessionId'], sessionSha256=digest(self.manifest), scenarioId=replay['scenarioId'],
                         mappingSha256=self.manifest['mappingSha256'], startedAt=replay['wallStartedAt'], endedAt=replay['wallFinishedAt'], completed=True)
            ref = self.signed('result-' + replay['scenarioId'], value)
            event(dict(eventId=uid(), scenarioId=replay['scenarioId'], kind='scenario_result', reportRef=ref['ref'], sha256=ref['sha256']))
        ensure_write(self.work / 'all-decisions.json', decisions)
        ensure_write(self.work / 'events-registered.json', registered)
        ensure_write(self.work / 'events-rejected.json', failures)
        report_input = self.op.v2('/lab-validation-runs/' + self.state['sessionId'] + '/report-input', method='GET')
        ensure_write(self.work / 'report-input.json', report_input)
        report = lab_report.generate(report_input)
        ensure_write(self.work / 'report.json', report)
        ref = self.signed('g3-report', report)
        lab_report.verify(load(self.artifacts / ref['ref']), load(self.args.report_trust), report_input)
        self.lab_op('reports', dict(reportRef=ref['ref'], sha256=ref['sha256'], runnerIdentity=self.runner_name))
        qualifications = self.op.v2('/lab-validation-runs/' + self.state['sessionId'] + '/qualifications', method='GET')
        ensure_write(self.work / 'qualifications.json', qualifications)
        self.state.update(reportImported=True, reportRef=ref, finishedAt=stamp())

    def run(self):
        validate_arguments(self.args)
        require(not self.work.exists(), 'LAB_RUN_DIRECTORY_EXISTS')
        os.umask(0o077)
        self.work.mkdir(parents=True, mode=0o700)
        (self.work / 'private').mkdir(mode=0o700)
        self.source = load(self.args.scenario)
        self.rows = self.scenario_rows()
        write(self.work / 'frozen-source.json', self.source)
        write(self.work / 'frozen-scenarios.json', self.rows)
        self.artifact_dir = self.artifacts / 'g3' / self.work.name
        self.artifact_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        write(self.artifact_dir / 'source.json', self.source)
        if self.args.gate_rehearsal:
            self.runner_name = 'g3-gate-runner-' + self.state['sessionId']
            self.isolation_name = 'g3-gate-isolation-' + self.state['sessionId']
            runner_dir = self.work / 'private/runner'
            isolation_dir = self.work / 'private/isolation'
        else:
            self.runner_name, self.isolation_name = RUNNER, ISOLATION
            runner_dir, isolation_dir = KEYS / 'cyber-guard-lab-runner', KEYS / 'cyber-guard-isolation'
        self.key = ensure_identity(self.args.report_trust, self.runner_name, runner_dir, 'runner.der')
        self.isolation_key = ensure_identity(self.args.report_trust, self.isolation_name, isolation_dir, 'isolation.der')
        self.db = j1_run.Database(self.args.mysql_service)
        before = self.snapshot()
        write(self.work / 'business-before.json', before)
        if self.target == BUSINESS:
            # 正式写入前整库备份（0600），并恢复到随机 schema 核对一致后删除该 schema。
            backup = self.work / 'private/business-backup.sql'
            drill = 'cyber_guard_g3restore_' + uuid.uuid4().hex[:16]
            write(self.work / 'database-backup.json', self.db.clone(BUSINESS, drill, backup))
            self.db.query('DROP DATABASE `' + drill + '`')
            require(self.snapshot() == before, 'BUSINESS_DATABASE_CHANGED_DURING_BACKUP')
            self.state['backup'] = {'path': str(backup), 'sha256': sha(backup), 'restoreDrillSchema': drill, 'restoreDrillDropped': True}
        else:
            write(self.work / 'database-clone.json', self.db.clone(self.args.source_schema, self.schema, self.work / 'private/source-backup.sql'))
        self.operator()
        self.save_state()
        (self.work / 'bin').mkdir()
        shutil.copy2(self.args.backend_jar, self.work / 'bin/backend.jar')
        for command in ('guardlive', 'guardtargets'):
            subprocess.run([str(self.args.go), 'build', '-o', str(self.work / 'bin' / command), './cmd/' + command], cwd=ROOT / 'sensor', check=True, stdout=subprocess.DEVNULL)
        self.original = {}
        selections = load(self.args.selection)
        for row in self.rows:
            self.original[row['scenarioId']] = original_mapping(row, next(v for v in selections if v['segmentId'] == row['scenarioId']), self.artifacts)
        self.start_backend()
        self.prepare_bundle()
        self.prepare_identities()
        self.start_executor()
        self.prepare_targets()
        self.freeze_session()
        handoff = self.op.call('GET', '/api/v2/machine/sensors/' + self.sensor + '/lab-validation-runs/' + self.state['sessionId'], None,
                               {'Authorization': 'Bearer ' + (self.work / 'private/sensor.credential').read_text().strip()})['data']
        write(self.work / 'handoff-state.json', handoff['state'])
        process = self.start_process([self.work / 'bin/guardlive', '-config', self.work / 'private/sensor.json', '-lab-plan',
                                      '-out', self.work / 'observations.jsonl', '-report', self.work / 'sensor-report.json', '-drain-timeout', '120s'], 'sensor.log')
        probe_until = time.monotonic() + self.args.probe_seconds
        while process.poll() is None:
            require(self.backend.poll() is None and self.targets.poll() is None, 'LAB_COMPONENT_EXITED')
            require(not (self.root_dir / 'error.json').exists(), 'LAB_ROOT_EXECUTOR_FAILED')
            if self.args.admission_probe and time.monotonic() > probe_until:
                process.terminate()
                process.wait(30)
                self.state['admissionProbeResult'] = 'sensor_running_after_probe_window'
                self.complete_probe()
                return
            time.sleep(1)
        require(process.returncode == 0, 'LAB_SENSOR_FAILED')
        self.state['captureComplete'] = True
        self.save_state()
        if self.args.admission_probe:
            self.state['admissionProbeResult'] = 'capture_completed'
            self.complete_probe()
            return
        self.drain()
        self.collect()
        self.save_state()

    def stop_probe(self):
        """停止并等待用户态心跳线程，避免删库/停后端时仍有请求在途。"""
        if hasattr(self, 'probe_stop'):
            self.probe_stop.set()
            thread = getattr(self, 'probe_thread', None)
            if thread is not None:
                # Session.call 的 HTTP 超时为 60 秒，须等待在途请求退出后才停后端/删库。
                thread.join(timeout=65)
                require(not thread.is_alive(), 'LAB_PROBE_HEARTBEAT_STOP_TIMEOUT')
            self.state['probeHeartbeatStopped'] = True
            # 包括 D3/异常的 finally 路径：清理后端与克隆前先封存时延，不丢弃失败运行证据。
            ensure_write(self.work / 'probe-latency.json', getattr(self, 'probe_latency', []))

    def complete_probe(self):
        """只封存预演诊断；无执行回执时禁止生成、签名或导入正式 G3 报告。"""
        self.stop_probe()
        self.state.update(realPF=False, formalG3Eligible=False, reportImported=False, finishedAt=stamp())
        self.save_state()

    def finish(self):
        self.stop_probe()
        if self.root_dir is not None and not (self.root_dir / 'stop').exists():
            (self.root_dir / 'stop').write_text(stamp())
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if self.rabbit_created:
            try:
                self.rabbit.delete()
                self.state['rabbitVhostDeleted'] = True
            except OSError:
                self.state['rabbitVhostDeleted'] = False
        if self.db is not None and self.work.exists():
            after = self.snapshot()
            write(self.work / ('business-after-' + uuid.uuid4().hex[:8] + '.json'), after)
            before = load(self.work / 'business-before.json')
            if self.target != BUSINESS:
                exists = self.db.query(f"SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='{self.schema}'").strip() == b'1'
                if exists:
                    self.db.query('DROP DATABASE `' + self.schema + '`')
                self.state['businessUnchanged'] = before == after
                self.state['cloneDropped'] = True
            else:
                self.state['changedTables'] = {t: {'rowsBefore': before.get(t, {}).get('rows'), 'rowsAfter': after.get(t, {}).get('rows')}
                                               for t in sorted(set(before) | set(after)) if before.get(t) != after.get(t)}
            self.save_state()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=('clone', 'business'), required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--rendezvous', type=Path, help='正式 PF 必填：root g3-executor 的 rendezvous 目录（已存在、空、本用户所有）')
    parser.add_argument('--stage-manifest')
    parser.add_argument('--authorization-reference')
    parser.add_argument('--root-timeout', type=int, default=1800)
    parser.add_argument('--probe-seconds', type=int, default=90)
    parser.add_argument('--jfr', action='store_true', help='诊断：后端开启 JFR profile 录制')
    parser.add_argument('--admission-probe', action='store_true', help='仅诊断（只允许 clone）：执行器只发心跳，检查会话准入与传感器交接后停止')
    parser.add_argument('--gate-rehearsal', action='store_true', help='仅 clone + admission-probe：克隆专用信任、身份和引导报告，运行真实自动化路径')
    parser.add_argument('--source-schema', default=BUSINESS, help='门禁预演须显式指定 cyber_guard_ 开头的隔离源库；正式路径只接受业务库')
    parser.add_argument('--bundle-id', default=R4_BUNDLE)
    parser.add_argument('--subject-sha256', type=lab_run.subject_sha256, default=lab_run.R4_SUBJECT_SHA256)
    parser.add_argument('--platform-ref', default=PLATFORM_REF)
    parser.add_argument('--final-ref', help='非 r4 必填：绑定该 subject 的 final；r4 默认复用既有正式 final')
    parser.add_argument('--backend-jar', type=Path, default=ROOT / '.cache/a18-20261012/bin/backend.jar',
                        help='默认保留历史 r4 二进制；r5 必须显式指定本阶段重新构建的 backend.jar')
    parser.add_argument('--scenario', type=Path, default=ROOT / '.cache/j2-20261011/g3-scenario.json')
    parser.add_argument('--artifacts', type=Path, default=HOME / 'ai/artifacts/cyber-guard')
    parser.add_argument('--selection', type=Path, default=ROOT / '.cache/j1-20261011-reg-preroll30/selection.json')
    parser.add_argument('--import-plan', type=Path, default=ROOT / '.cache/j2-20261011/import-rehearsal/lab-plan.json')
    parser.add_argument('--reviewer-file', type=Path, default=KEYS / 'cyber-guard-reviewer/credentials.json')
    parser.add_argument('--report-trust', type=Path, default=OFFICIAL_TRUST)
    parser.add_argument('--mysql-service', type=Path, default=HOME / 'development/services/databases/mysql-server-8.0.42')
    parser.add_argument('--java', type=Path, default=HOME / 'development/runtimes/java/temurin-25.0.2/Contents/Home/bin/java')
    parser.add_argument('--go', type=Path, default=HOME / 'development/runtimes/go/go-1.26.4/bin/go')
    parser.add_argument('--port', type=int, default=19643)
    args = parser.parse_args(argv)
    args.artifacts = args.artifacts.resolve()
    args.mode = 'pf'
    validate_arguments(args)
    return args


def main():
    args = parse_args()
    runner = Formal(args)
    try:
        runner.run()
    except Exception as exc:
        import traceback
        traceback.print_exc()
        if runner.work.exists():
            write(runner.work / ('failure-' + uuid.uuid4().hex[:8] + '.json'), dict(at=stamp(), error=type(exc).__name__,
                  code=str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'LAB_RUNTIME_FAILED'))
        raise
    finally:
        runner.finish()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc) if isinstance(exc, (ValueError, RuntimeError)) else 'LAB_RUNTIME_FAILED; inspect run logs', file=sys.stderr)
        raise SystemExit(2)
