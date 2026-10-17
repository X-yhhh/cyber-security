"""复用现有 v2 权限、独立审批与幂等日志；SQL 仅用于按本次资产/时间收集事实和备份。"""
from pathlib import Path
import json
import uuid
from scripts.demo.common import instant, require, sha, uid, write
from scripts.p8.toolkit import Journal, sessions
from scripts.p8.status import machine_rows


class Control:
    def __init__(self, c, enrollment, directory):
        self.c, self.ids, self.directory = c, enrollment, Path(directory)
        self.applicant, self.reviewer = sessions(c)
        self.journal = Journal(self.directory / 'api', {'config': c, 'enrollment': enrollment})
        from scripts.p8.register_alert_only import Database
        self.db = Database(Path(c['mysqlService']))
        self.schema = c['schema']
        self.asset = uid(enrollment['assetId'])
        self.aid = "(SELECT id FROM asset WHERE public_id='" + self.asset + "')"

    def rows(self, sql):
        # SQL 只由本模块固定模板生成；所有 UUID/时间在拼接前校验，schema 已通过配置验证。
        data = self.db.query('SET TRANSACTION READ ONLY; START TRANSACTION WITH CONSISTENT SNAPSHOT; ' + sql + '; COMMIT;', self.schema)
        if isinstance(data, bytes):
            data = data.decode()
        return [json.loads(s) for s in data.strip().splitlines() if s]

    def bundle(self):
        b = self.applicant.request('GET', '/release-bundles/' + uid(self.c['bundleId']))
        require(b['subjectSha256'] == self.c['subjectSha256'] and b['environment'] == 'lab' and b['status'] in ('approved', 'active'), 'DEMO_BUNDLE_NOT_REUSABLE')
        subject = self.rows("SELECT subject_json FROM guard_release_bundle WHERE public_id='" + uid(self.c['bundleId']) + "'")[0]
        from executor.common import digest
        require(digest(subject) == self.c['subjectSha256'], 'DEMO_SUBJECT_CHANGED')
        b['subject'] = subject
        policy = self.applicant.request('GET', '/decision-policies/' + subject['policyId'])
        require(policy['definition']['policyVersion'] == 'host-guard-decision/2026-10-08.1+demo-budget-20261017', 'DEMO_RECOVERY_POLICY_REQUIRED')
        require(policy['definition']['mode'] == 'auto' and policy['definition']['maxTtlSeconds'] == 60 and policy['definition']['maxContinuousBlockSeconds'] == 120, 'DEMO_FROZEN_POLICY_REQUIRED')
        families = {p['family']: p for p in policy['definition'].get('familyPolicies', [])}
        require(families.get('dos_flood', {}).get('autoEligible') is False and families['dos_flood'].get('modelAutoEligible') is False, 'FLOOD_MUST_BE_ALERT_ONLY')
        require(set(subject['capabilityIds']) == {x['id'] for x in self.c['capabilities']}, 'DEMO_CAPABILITIES_CHANGED')
        from scripts.p7.import_bundle import verify_capability
        for cap in self.c['capabilities']:
            verify_capability(self.applicant, cap)
        return b

    def reset_state(self):
        bindings = self.applicant.request('GET', '/release-bundles/' + self.c['bundleId'] + '/bindings')['items']
        require(len(bindings) < 200, 'BINDING_VIEW_TRUNCATED')
        own = [b for b in bindings if b['assetId'] == self.asset]
        active = self.rows("SELECT JSON_OBJECT('count',COUNT(*)) FROM asset_authorization WHERE asset_id=" + self.aid + " AND status IN ('pending','active') AND valid_until>UTC_TIMESTAMP(6)")
        commands = self.rows("SELECT JSON_OBJECT('count',COUNT(*)) FROM guard_action WHERE asset_id=" + self.aid + " AND observed_state NOT IN ('revoked','expired','rejected')")
        return {'bindingSuspended': all(b['status'] == 'suspended' for b in own),
                'authorizationRevoked': active[0]['count'] == 0, 'noActiveActions': commands[0]['count'] == 0,
                'bundleActive': self.bundle()['status'] == 'active'}

    def backup(self):
        """同一只读快照导出并完整恢复核验后才允许演示业务写入；不暂停持续监测。"""
        folder = self.directory / 'backup'
        folder.mkdir(mode=0o700)
        try:
            from scripts.demo.backup import backup_restore
            snapshot, backup = backup_restore(self.db, self.schema, 'cyber_r6_restore_' + uuid.uuid4().hex[:16], folder)
            result = {'passed': True, 'file': str(backup), 'sha256': sha(backup), 'sourceSha256': snapshot['contentSha256']}
        finally:
            self.db.drop_owned()
        write(folder / 'result.json', result)
        return result

    def authorize(self, g, iface, mode):
        scopes = []
        if mode == 'pf':
            for cap in self.c['capabilities']:
                p = cap['payload']
                if p['family'] == 'dos_flood':
                    continue
                ports = [None] if p.get('scope') == 'peer_inbound' else [self.c['ports'][k] for k in (('ftp', 'ssh') if p['family'] == 'brute_force' else ('http',))]
                for port in ports:
                    scopes.append(dict(direction='inbound', transport='tcp', addressFamily='ipv4',
                                       scope=p.get('scope', 'peer_service'), servicePort=port, capabilityId=uid(cap['id'])))
        auth = self.journal.step('authorization', self.applicant, '/assets/' + self.asset + '/authorizations',
                                dict(interfaces=[iface], observationAllowed=True, executionScopes=scopes,
                                     validFrom=g['validFrom'], validUntil=g['validUntil'], evidenceRef=g['reference']))
        approved = self.journal.step('approval', self.reviewer, '/authorizations/' + auth['id'] + '/decisions',
                                    {'decision': 'approve', 'reason': '限本次演示运行 ' + g['runId']}, auth['revision'])
        bundle = self.bundle()
        previous = self.journal.data['steps'].get('activation')
        revision = previous['request']['revision'] if previous else bundle['revision']
        self.journal.step('activation', self.reviewer, '/release-bundles/' + bundle['id'] + '/activations',
                          {'assetIds': [self.asset], 'authorizationIds': [auth['id']]}, revision)
        return {k: approved.get(k, auth.get(k)) for k in ('id', 'revision', 'status')} | {'validFrom': g['validFrom'], 'validUntil': g['validUntil']}

    def revoke(self):
        """仅撤销本次 Journal 记录的准确授权；不调用组合 suspension，不删除历史事实。"""
        step = self.journal.data['steps'].get('authorization')
        if not step:
            return True
        if 'result' not in step:
            r = step['request']
            self.journal.step('authorization', self.applicant, r['path'], r['body'], r['revision'])
        auth_id = self.journal.data['steps']['authorization']['result']['id']
        auth = self.reviewer.request('GET', '/authorizations/' + uid(auth_id))
        require(auth['assetId'] == self.asset, 'CLEANUP_AUTHORIZATION_SCOPE_MISMATCH')
        if auth['status'] != 'revoked':
            self.journal.step('revocation', self.reviewer, '/authorizations/' + auth_id + '/revocations',
                              {'reason': '演示运行结束或异常收尾'}, auth['revision'])
        return self.reviewer.request('GET', '/authorizations/' + auth_id)['status'] == 'revoked'

    def healthy(self):
        rows = machine_rows(self.applicant, 'sensor-heartbeats', self.asset)
        sensor = next((r for r in rows if r['id'] == self.ids['sensorId']), None)
        if not sensor or sensor.get('freshness') != 'fresh':
            return False
        data = self.applicant.request('GET', '/health-windows?assetId=' + self.asset + '&sensorId=' + self.ids['sensorId'] + '&limit=1')
        return len(data['items']) == 1 and data['items'][0].get('healthState') == 'healthy' and data['items'][0].get('freshness') == 'fresh'

    def budgets(self):
        return self.rows("SELECT JSON_OBJECT('id',t.public_id,'chargedMs',b.charged_ms,'cycleStartedAt',CONCAT(DATE_FORMAT(b.cycle_started_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z'),"
                         "'healthProofSha256',b.health_proof_sha256,'revoked',EXISTS(SELECT 1 FROM guard_budget_event e WHERE e.budget_target_id=t.id AND e.event_kind='revoked' "
                         "AND CAST(REPLACE(REPLACE(JSON_UNQUOTE(JSON_EXTRACT(e.proof_json,'$.cycleStartedAt')),'T',' '),'Z','') AS DATETIME(6))=b.cycle_started_at)) "
                         "FROM guard_budget_target t JOIN guard_target_budget b ON b.budget_target_id=t.id WHERE t.asset_id=" + self.aid)

    def recovered(self):
        rows = self.budgets()
        return all(b['chargedMs'] == 0 and not b['revoked'] for b in rows)

    def facts(self, started, ended):
        from datetime import datetime, timezone
        start = datetime.fromtimestamp(instant(started), timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')
        end = datetime.fromtimestamp(instant(ended), timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')
        def collect(sql):
            rows = self.rows(sql + ' LIMIT 100001')
            require(len(rows) <= 100000, 'REPORT_FACT_LIMIT_EXCEEDED')
            return rows
        decisions = collect("SELECT JSON_OBJECT('id',public_id,'at',CONCAT(DATE_FORMAT(decided_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z'),"
                            "'decision',decision,'family',evidence_json->>'$.family','source',evidence_json->>'$.source') FROM guard_decision WHERE asset_id=" + self.aid + " AND decided_at>='" + start + "' AND decided_at<='" + end + "' ORDER BY id")
        commands = collect("SELECT JSON_OBJECT('id',c.public_id,'decisionId',d.public_id,'at',CONCAT(DATE_FORMAT(c.issued_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z'),"
                           "'scope',c.payload_json->>'$.scope','blockUntil',c.payload_json->>'$.blockUntil','state',a.observed_state,'budgetTargetId',t.public_id) FROM guard_command c JOIN guard_action a ON a.id=c.action_id "
                           "JOIN guard_decision d ON d.id=a.decision_id JOIN guard_budget_target t ON t.id=a.budget_target_id WHERE a.asset_id=" + self.aid + " AND c.issued_at>='" + start + "' AND c.issued_at<='" + end + "' ORDER BY c.id")
        receipts = collect("SELECT JSON_OBJECT('commandId',c.public_id,'status',r.status,'projected',r.projected,'at',CONCAT(DATE_FORMAT(r.observed_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z')) "
                           "FROM guard_action_receipt r JOIN guard_command c ON c.id=r.command_id WHERE r.asset_id=" + self.aid + " AND r.observed_at>='" + start + "' AND r.observed_at<='" + end + "' ORDER BY r.id")
        events = collect("SELECT JSON_OBJECT('id',e.public_id,'targetId',t.public_id,'kind',e.event_kind,'at',CONCAT(DATE_FORMAT(e.created_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z')) "
                         "FROM guard_budget_event e JOIN guard_budget_target t ON t.id=e.budget_target_id WHERE t.asset_id=" + self.aid + " AND e.created_at>='" + start + "' AND e.created_at<='" + end + "' ORDER BY e.id")
        return {'decisions': decisions, 'commands': commands, 'receipts': receipts, 'budgetEvents': events}
