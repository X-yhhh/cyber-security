"""复用现有 v2 权限、独立审批与幂等日志；SQL 仅用于按本次资产/时间收集事实和备份。"""
from pathlib import Path
import json
import uuid
from scripts.demo.common import instant, load, require, sha, uid, write
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

    def bundle(self, mode):
        require(mode in ('pf', 'alert-only'), 'DEMO_MODE_INVALID')
        b = self.applicant.request('GET', '/release-bundles/' + uid(self.c['bundleId']))
        require(b['subjectSha256'] == self.c['subjectSha256'] and b['environment'] == 'lab' and b['status'] in ('approved', 'active'), 'DEMO_BUNDLE_NOT_REUSABLE')
        subject = self.rows("SELECT subject_json FROM guard_release_bundle WHERE public_id='" + uid(self.c['bundleId']) + "'")[0]
        from executor.common import digest
        require(digest(subject) == self.c['subjectSha256'], 'DEMO_SUBJECT_CHANGED')
        b['subject'] = subject
        policy = self.applicant.request('GET', '/decision-policies/' + subject['policyId'])
        policy_mode = policy['definition'].get('mode')
        if policy_mode == 'alert_only':
            require(mode == 'alert-only', 'DEMO_ALERT_ONLY_BUNDLE_PF_FORBIDDEN')
            require('rule-inbound-20261018' in policy['definition']['policyVersion'].split('+'), 'DEMO_RULE_POLICY_REQUIRED')
            require(set(subject['capabilityIds']) == {x['id'] for x in self.c['capabilities']}, 'DEMO_CAPABILITIES_CHANGED')
            from scripts.p7.import_bundle import verify_capability
            for cap in self.c['capabilities']:
                verify_capability(self.applicant, cap)
        elif policy_mode == 'auto':
            require(policy['definition']['policyVersion'] == 'host-guard-decision/2026-10-08.1+demo-budget-20261017', 'DEMO_RECOVERY_POLICY_REQUIRED')
            require(policy['definition']['mode'] == 'auto' and policy['definition']['maxTtlSeconds'] == 60 and policy['definition']['maxContinuousBlockSeconds'] == 120, 'DEMO_FROZEN_POLICY_REQUIRED')
            families = {p['family']: p for p in policy['definition'].get('familyPolicies', [])}
            require(families.get('dos_flood', {}).get('autoEligible') is False and families['dos_flood'].get('modelAutoEligible') is False, 'FLOOD_MUST_BE_ALERT_ONLY')
            require(set(subject['capabilityIds']) == {x['id'] for x in self.c['capabilities']}, 'DEMO_CAPABILITIES_CHANGED')
            from scripts.p7.import_bundle import verify_capability
            for cap in self.c['capabilities']:
                verify_capability(self.applicant, cap)
        else:
            require(False, 'DEMO_BUNDLE_MODE_UNSUPPORTED')
        return b

    def reset_state(self, mode):
        bindings = self.applicant.request('GET', '/release-bundles/' + self.c['bundleId'] + '/bindings')['items']
        require(len(bindings) < 200, 'BINDING_VIEW_TRUNCATED')
        own = [b for b in bindings if b['assetId'] == self.asset]
        active = self.rows("SELECT JSON_OBJECT('count',COUNT(*)) FROM asset_authorization WHERE asset_id=" + self.aid + " AND status IN ('pending','active') AND valid_until>UTC_TIMESTAMP(6)")
        commands = self.rows("SELECT JSON_OBJECT('count',COUNT(*)) FROM guard_action WHERE asset_id=" + self.aid + " AND observed_state NOT IN ('revoked','expired','rejected')")
        return {'bindingSuspended': all(b['status'] == 'suspended' for b in own),
                'authorizationRevoked': active[0]['count'] == 0, 'noActiveActions': commands[0]['count'] == 0,
                'bundleActive': self.bundle(mode)['status'] == 'active'}

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
        bundle = self.bundle(mode)
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
        def sql_time(value):
            return datetime.fromtimestamp(instant(value), timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')

        state = load(self.directory / 'state.json')
        worker_path = self.directory / 'worker.json'
        worker = load(worker_path) if worker_path.exists() else {}
        marks = {m['id']: m for m in worker.get('scenes', [])}
        scene_windows = []
        for scene in state.get('scenes', []):
            mark = marks.get(scene['id'], {})
            if mark.get('finished') and mark.get('startedAt') and mark.get('endedAt'):
                window_end = instant(mark['endedAt']) + scene.get('latencyLimitMs', 0) / 1000
                scene_windows.append((scene['id'], sql_time(mark['startedAt']),
                                      datetime.fromtimestamp(window_end, timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f'),
                                      instant(mark['startedAt']), window_end))

        selects = []
        decisions = "JSON_OBJECT('id',d.public_id,'at',CONCAT(DATE_FORMAT(d.decided_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z')," \
                    "'decision',d.decision,'family',d.evidence_json->>'$.family','source',d.evidence_json->>'$.source'," \
                    "'ruleId',d.evidence_json->>'$.ruleId','direction',e.direction)"
        selects.append("SELECT JSON_OBJECT('kind','decision','value'," + decisions + ") FROM guard_decision d JOIN guard_episode e ON e.id=d.episode_id "
                       "WHERE d.asset_id=" + self.aid + " AND d.decided_at>='" + start + "' AND d.decided_at<='" + end + "'")
        command_value = "JSON_OBJECT('id',c.public_id,'decisionId',d.public_id,'at',CONCAT(DATE_FORMAT(c.issued_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z')," \
                        "'scope',c.payload_json->>'$.scope','blockUntil',c.payload_json->>'$.blockUntil','state',a.observed_state,'budgetTargetId',t.public_id," \
                        "'source',d.evidence_json->>'$.source')"
        selects.append("SELECT JSON_OBJECT('kind','command','value'," + command_value + ") FROM guard_command c JOIN guard_action a ON a.id=c.action_id "
                       "JOIN guard_decision d ON d.id=a.decision_id JOIN guard_budget_target t ON t.id=a.budget_target_id "
                       "WHERE a.asset_id=" + self.aid + " AND c.issued_at>='" + start + "' AND c.issued_at<='" + end + "'")
        receipt_value = "JSON_OBJECT('commandId',c.public_id,'status',r.status,'projected',r.projected,'at',CONCAT(DATE_FORMAT(r.observed_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z'))"
        selects.append("SELECT JSON_OBJECT('kind','receipt','value'," + receipt_value + ") FROM guard_action_receipt r JOIN guard_command c ON c.id=r.command_id "
                       "WHERE r.asset_id=" + self.aid + " AND r.observed_at>='" + start + "' AND r.observed_at<='" + end + "'")
        event_value = "JSON_OBJECT('id',e.public_id,'targetId',t.public_id,'kind',e.event_kind,'at',CONCAT(DATE_FORMAT(e.created_at,'%Y-%m-%dT%H:%i:%s.%f'),'Z'))"
        selects.append("SELECT JSON_OBJECT('kind','budgetEvent','value'," + event_value + ") FROM guard_budget_event e JOIN guard_budget_target t ON t.id=e.budget_target_id "
                       "WHERE t.asset_id=" + self.aid + " AND e.created_at>='" + start + "' AND e.created_at<='" + end + "'")

        # 汇总和各场景窗口在同一个一致性快照中查询，避免逐条导出数千条规则评价。
        rule_windows = [('*', start, end), *((scene_id, window_start, window_end) for scene_id, window_start, window_end, _, _ in scene_windows)]
        for scene_id, window_start, window_end in rule_windows:
            escaped_scene = scene_id.replace("'", "''")
            value = "JSON_OBJECT('ruleId',r.rule_id,'family',r.family,'applicable',r.applicable,'matched',r.matched," \
                    "'direction',o.direction,'count',COUNT(*),'firstAt',CONCAT(DATE_FORMAT(MIN(r.created_at),'%Y-%m-%dT%H:%i:%s.%f'),'Z'))"
            selects.append("SELECT JSON_OBJECT('kind','ruleEvaluation','sceneId','" + escaped_scene + "','value'," + value + ") "
                           "FROM guard_rule_evaluation r JOIN guard_observation o ON o.id=r.observation_id "
                           "WHERE r.asset_id=" + self.aid + " AND r.created_at>='" + window_start + "' AND r.created_at<='" + window_end + "' "
                           "GROUP BY r.rule_id,r.family,r.applicable,r.matched,o.direction")

        rows = self.rows('SELECT * FROM (' + ' UNION ALL '.join(selects) + ') facts LIMIT 100001')
        require(len(rows) <= 100000, 'REPORT_FACT_LIMIT_EXCEEDED')
        facts = {'decisions': [], 'commands': [], 'receipts': [], 'budgetEvents': [], 'ruleEvaluations': []}
        for row in rows:
            kind, value = row['kind'], row['value']
            if kind == 'ruleEvaluation':
                facts['ruleEvaluations'].append({'sceneId': row['sceneId'], **value})
            else:
                facts[{'decision': 'decisions', 'command': 'commands', 'receipt': 'receipts', 'budgetEvent': 'budgetEvents'}[kind]].append(value)

        direction_counts = {'inbound': 0, 'unknown': 0, 'outbound': 0}
        def empty_scene_observations():
            return {scene_id: {'directionCounts': dict.fromkeys(direction_counts, 0),
                               'controlConnections': None, 'newControlConnections': None}
                    for scene_id, _, _, _, _ in scene_windows}

        scene_observations = empty_scene_observations()
        observation_facts_error = None
        try:
            peer_key = self._runtime_peer_key()
            observations_path = self.directory / 'observations.jsonl'
            require(not observations_path.is_symlink() and observations_path.is_file(), 'REPORT_OBSERVATIONS_MISSING')
            connection_sets = {scene_id: {} for scene_id, _, _, _, _ in scene_windows}
            observation_count = 0
            with observations_path.open() as stream:
                for line in stream:
                    observation_count += 1
                    require(observation_count <= 100000, 'REPORT_FACT_LIMIT_EXCEEDED')
                    observation = json.loads(line)
                    at = instant(observation['emittedAt'])
                    direction = observation['direction']
                    require(direction in direction_counts, 'REPORT_OBSERVATION_DIRECTION_INVALID')
                    if instant(started) <= at <= instant(ended):
                        direction_counts[direction] += 1
                    parent = observation['parentConnectionId']
                    require(parent, 'REPORT_PARENT_CONNECTION_MISSING')
                    for scene_id, _, _, window_start, window_end in scene_windows:
                        if window_start <= at <= window_end:
                            scene_observations[scene_id]['directionCounts'][direction] += 1
                            if observation.get('peerKey') == peer_key:
                                connection_sets[scene_id].setdefault(parent, set()).add(direction)
            for scene_id, connections in connection_sets.items():
                scene_observations[scene_id]['controlConnections'] = sum(bool(directions & {'outbound', 'unknown'}) for directions in connections.values())
                scene_observations[scene_id]['newControlConnections'] = sum('outbound' in directions for directions in connections.values())
        except Exception as error:
            code = str(error)
            if isinstance(error, ValueError) and code and all(ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for ch in code):
                observation_facts_error = code
            elif isinstance(error, OSError):
                observation_facts_error = 'REPORT_OBSERVATIONS_UNAVAILABLE'
            else:
                observation_facts_error = 'REPORT_OBSERVATIONS_INVALID'
            direction_counts = {'inbound': 0, 'unknown': 0, 'outbound': 0}
            scene_observations = empty_scene_observations()
        facts['directionCounts'] = direction_counts
        facts['sceneObservations'] = scene_observations
        facts['observationFactsError'] = observation_facts_error
        return facts

    def _runtime_peer_key(self):
        """复用运行时唯一的 peer.key 派生实现。"""
        from scripts.demo.runtime import peer_key
        return peer_key(self.c, self.ids)
