"""A5 登记流程约束；只使用假数据库与假申请人，不启动服务或触碰业务库。"""
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts.demo import register_lab_alert_only as register


class FakeDatabase:
    def __init__(self, rows):
        self.rows = rows
        self.queries = []

    def query(self, sql, *_):
        self.queries.append(sql)
        return self.rows.pop(0)


class FakeApplicant:
    def __init__(self):
        self.calls = []

    def v2(self, path, body, revision):
        self.calls.append((path, body, revision))
        return {'id': 'new-id'}


def test_source_database_rows_reject_each_changed_r6_prime_id():
    subject = {'modelId': register.R6_PRIME_MODEL_ID, 'policyId': register.R6_PRIME_POLICY_ID,
               'environment': 'authorized', 'capabilityIds': ['cap-1']}
    policy = {'mode': 'alert_only', 'policyVersion': 'host-guard/1+rule-inbound-20261018',
              'supportedCapabilityIds': ['cap-1']}
    valid = [register.R6_PRIME_BUNDLE_ID, register.R6_PRIME_POLICY_ID,
             json.dumps(subject), json.dumps(policy), 'reviewed']
    for index, value, code in (
            (0, 'other-bundle', 'R6_PRIME_BUNDLE_ID_MISMATCH'),
            (1, 'other-policy', 'R6_PRIME_POLICY_ID_MISMATCH'),
            (2, json.dumps({**subject, 'modelId': 'other-model'}), 'R6_PRIME_MODEL_ID_MISMATCH')):
        fields = valid.copy()
        fields[index] = value
        with pytest.raises(RuntimeError, match=code):
            register.source_identity(FakeDatabase([('\t'.join(fields)).encode()]), 'cyber_security')


def test_source_database_rows_accept_exact_r6_prime_identity():
    subject = {'modelId': register.R6_PRIME_MODEL_ID, 'policyId': register.R6_PRIME_POLICY_ID,
               'environment': 'authorized', 'capabilityIds': ['cap-1']}
    definition = {'mode': 'alert_only', 'policyVersion': 'host-guard/1+rule-inbound-20261018',
                  'supportedCapabilityIds': ['cap-1']}
    row = '\t'.join((register.R6_PRIME_BUNDLE_ID, register.R6_PRIME_POLICY_ID,
                     json.dumps(subject), json.dumps(definition), 'reviewed'))
    assert register.source_identity(FakeDatabase([row.encode()]), 'cyber_security') == (subject, definition)


def test_business_mode_requires_successful_rehearsal_result():
    with pytest.raises(RuntimeError, match='SUCCESSFUL_REHEARSAL_REQUIRED'):
        register.validate_rehearsal_inputs('business', None, {'jarSha256': 'same'})


def test_business_mode_rejects_rehearsal_with_different_inputs(tmp_path):
    result = {'passed': True, 'mode': 'rehearsal', 'inputs': {'jarSha256': 'old'}}
    path = tmp_path / 'result.json'
    path.write_text(json.dumps(result))
    with pytest.raises(RuntimeError, match='REHEARSAL_INPUTS_MISMATCH'):
        register.validate_rehearsal_inputs('business', path, {'jarSha256': 'current'})


def test_business_mode_rejects_failed_or_wrong_mode_rehearsal(tmp_path):
    path = tmp_path / 'result.json'
    path.write_text(json.dumps({'passed': False, 'mode': 'rehearsal', 'inputs': {}}))
    with pytest.raises(RuntimeError, match='REHEARSAL_INPUTS_MISMATCH'):
        register.validate_rehearsal_inputs('business', path, {})
    path.write_text(json.dumps({'passed': True, 'mode': 'business', 'inputs': {}}))
    with pytest.raises(RuntimeError, match='REHEARSAL_INPUTS_MISMATCH'):
        register.validate_rehearsal_inputs('business', path, {})


def test_business_allows_changed_database_snapshot_when_inputs_match_and_reaches_register(tmp_path, monkeypatch):
    inputs = {'jarSha256': 'same-input'}
    rehearsal_path = tmp_path / 'rehearsal-result.json'
    rehearsal_path.write_text(json.dumps({'passed': True, 'mode': 'rehearsal', 'inputs': inputs,
                                          'sourceBeforeSha256': 'older-database-snapshot'}))
    current_snapshot = {'contentSha256': 'current-database-snapshot', 'schemaSha256': 'schema',
                        'tables': {str(index): {} for index in range(89)}}

    class WorkflowDatabase:
        owned_schema = None

        def query(self, *_):
            return b'28'

        def backup_restore(self, *_):
            return current_snapshot, tmp_path / 'backup.sql'

        def snapshot(self, _):
            return current_snapshot

        def drop_owned(self):
            pass

    materials = ({'capabilityIds': ['capability-1']}, {}, {'evaluation': {}, 'provenance': {}},
                 {}, {}, {}, inputs, register.R6_PRIME_BINDING_PREFIX + '1' * 28)
    database = WorkflowDatabase()
    register_call = Mock()
    monkeypatch.setattr(register, 'Database', lambda *_: database)
    monkeypatch.setattr(register, 'source_material', lambda *_: materials)
    monkeypatch.setattr(register, 'stop_backend', lambda *_: None)
    monkeypatch.setattr(register, 'start_backend', lambda: None)
    monkeypatch.setattr(register, 'register', register_call)
    monkeypatch.setattr(register, 'deltas', lambda *_: ({}, []))
    monkeypatch.setattr(register, 'active_r6_prime_binding', lambda *_: materials[7])
    monkeypatch.setattr(register, 'sha', lambda *_: 'evidence-hash')
    monkeypatch.setattr(register, 'write', lambda *_: None)
    monkeypatch.setattr(register.j1_run, 'stamp', lambda: '2026-10-28T00:00:00Z')
    args = SimpleNamespace(
        mode='business', source='cyber_security', work=tmp_path / 'work',
        jar=tmp_path / 'backend.jar', artifacts=tmp_path / 'artifacts',
        trust=tmp_path / 'trust.json', evaluator=tmp_path / 'evaluator.key',
        operator=tmp_path / 'operator.json', reviewer=tmp_path / 'reviewer.json',
        java_home=tmp_path / 'java', mysql_service=tmp_path / 'mysql', rehearsal=rehearsal_path)

    register.main(args)

    register_call.assert_called_once()


def test_registration_refuses_activation_endpoint_before_fake_applicant_call(tmp_path):
    applicant = FakeApplicant()
    with pytest.raises(RuntimeError, match='ACTIVATION_FORBIDDEN'):
        register.step('activate', applicant, '/release-bundles/new-id/activations', {}, None,
                      tmp_path, {})
    assert applicant.calls == []


def _snapshot():
    names = ('guard_decision_policy', 'guard_release_bundle', 'guard_bundle_capability',
             'guard_evaluation_run', 'audit_log')
    tables = {name: {'count': 1, 'rows': {'old': 'row'}, 'sha256': name + '-before',
                     'invariantSha256': name + '-identity'} for name in names}
    return {'schemaSha256': 'same-schema', 'tables': tables}


def test_table_deltas_reject_added_policy_row():
    before = _snapshot()
    after = deepcopy(before)
    policy = after['tables']['guard_decision_policy']
    policy['rows']['unexpected-policy'] = 'new-row'
    policy['count'] += 1
    policy['sha256'] = 'policy-after'
    expected = register.expected_deltas(4)
    with pytest.raises(RuntimeError, match='BUSINESS_DELTA_MISMATCH'):
        register.deltas(before, after, expected)


def test_snapshot_schema_requires_eighty_nine_tables():
    register.validate_snapshot_schema({'tables': {str(index): {} for index in range(89)}})
    with pytest.raises(RuntimeError, match='DATABASE_TABLE_COUNT_MISMATCH:88'):
        register.validate_snapshot_schema({'tables': {str(index): {} for index in range(88)}})


def test_rehearsal_rejects_changes_to_source_release_tables():
    before = {'tables': {name: {'sha256': name} for name in
                         ('guard_release_bundle', 'guard_decision_policy', 'guard_asset_binding')}}
    after = deepcopy(before)
    after['tables']['guard_asset_binding']['sha256'] = 'changed'
    with pytest.raises(RuntimeError, match='SOURCE_RELEASE_FACT_CHANGED:guard_asset_binding'):
        register.validate_source_release_unchanged(before, after)


def test_table_deltas_accept_one_lab_bundle_without_policy_change():
    before = _snapshot()
    after = deepcopy(before)
    for table, count in register.expected_deltas(4).items():
        if count:
            current = after['tables'][table]
            current['rows'].update({f'new-{i}': 'row' for i in range(count)})
            current['count'] += count
            current['sha256'] = table + '-after'
    changes, _ = register.deltas(before, after, register.expected_deltas(4))
    assert changes == {'guard_decision_policy': 0, 'guard_release_bundle': 1,
                       'guard_bundle_capability': 4, 'guard_evaluation_run': 1}


def test_lab_final_keeps_evaluation_and_provenance_unchanged_and_records_derivation():
    source = {'subject': {'environment': 'authorized'}, 'subjectSha256': 'source-hash',
              'environment': 'authorized', 'evaluation': {'rows': 7}, 'provenance': {'source': 'r6-prime'}}
    derived = register.lab_final(source, {'environment': 'lab', 'policyId': register.R6_PRIME_POLICY_ID})
    assert derived['environment'] == 'lab'
    assert derived['evaluation'] == source['evaluation']
    assert derived['provenance'] == source['provenance']
    assert derived['derivation'][-1]['description'] == register.DERIVATION_TEXT


def test_alert_only_registration_has_no_policy_write_or_activation_path():
    applicant = FakeApplicant()
    with pytest.raises(RuntimeError, match='REGISTER_ENDPOINT_FORBIDDEN'):
        register.step('policy', applicant, '/decision-policies', {}, None, Mock(), {})
    assert applicant.calls == []


def test_r6_prime_binding_must_stay_active():
    binding = register.R6_PRIME_BINDING_PREFIX + '1' * 28
    db = FakeDatabase([(binding + '\tactive').encode()])
    assert register.active_r6_prime_binding(db, 'cyber_security') == binding
    inactive = FakeDatabase([(binding + '\tsuspended').encode()])
    with pytest.raises(RuntimeError, match='R6_PRIME_BINDING_NOT_ACTIVE'):
        register.active_r6_prime_binding(inactive, 'cyber_security')


def test_r6_prime_bundle_policy_and_model_ids_are_fixed():
    assert register.R6_PRIME_BUNDLE_ID == 'd89e7b99-ea61-40b1-b376-dbb90f004ef6'
    assert register.R6_PRIME_POLICY_ID == '68a57070-df9f-51fe-9837-daa0858f68c1'
    assert register.R6_PRIME_MODEL_ID == 'f7734c7c-1c9a-52dd-8e89-79f36b2f3815'
