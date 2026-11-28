"""DB-13 保留工具：库名与授权闸门、清单一致性、分批删除计数与引用核验（假数据库，不连 MySQL）。"""
import json
import re

import pytest

from scripts.p8 import retention as r

CLONE = 'cyber_r6_restore_0123456789abcdef'
ASSET = 'cb7e844b-01b1-453f-a6a2-8cf248979b9a'


class FakeDb:
    """按 SQL 特征返回固定结果；记录所有写语句。"""

    def __init__(self, candidates, children=(3, 1), refs=(0, 0, 0, 0, 0), asset_checks='0\t0\t0', env='authorized'):
        self.candidates, self.children, self.refs = candidates, children, refs
        self.asset_checks, self.env = asset_checks, env
        self.writes, self.deleted = [], {k: set() for k in r.RULES}
        self.verify_sql = None

    def query(self, sql, schema=None):
        body = sql.split('\n', 1)[1] if sql.startswith("SET time_zone") else sql
        if 'START TRANSACTION' in body:
            self.writes.append(body)
            return self._delete(body)
        if body.startswith('SET SESSION TRANSACTION READ ONLY;\n'):
            body = body.split('\n', 1)[1]
        if body.startswith('SELECT id,public_id,environment FROM asset'):
            return f'5\t{ASSET}\t{self.env}\n'.encode()
        if body.startswith('SELECT (SELECT COUNT(*) FROM guard_action'):
            return (self.asset_checks + '\n').encode()
        for rule, table in r.TABLE.items():
            prefix = {'R1': 'SELECT i.id FROM guard_idempotency', 'R2': 'SELECT h.id FROM guard_capture_health_window',
                      'R3': 'SELECT o.id FROM guard_observation'}[rule]
            if body.startswith(prefix):
                return ''.join(f'{i}\n' for i in self.candidates[rule] if i not in self.deleted[rule]).encode()
            if body.startswith(f'SELECT public_id FROM {table}'):
                ids = re.search(r'IN \(([\d,]+)\)', body).group(1).split(',')
                return ''.join(f'00000000-0000-4000-8000-{int(i):012d}\n' for i in ids).encode()
            if body.startswith(f'SELECT COUNT(*) FROM {table} WHERE id IN'):
                ids = {int(i) for i in re.search(r'IN \(([\d,]+)\)', body).group(1).split(',')}
                return f'{len(ids - self.deleted[rule])}\n'.encode()
        if body.startswith('SELECT COUNT(*) FROM guard_rule_evaluation WHERE observation_id IN'):
            return f'{self.children[0] * len(re.search(r"IN [(]([0-9,]+)[)]", body).group(1).split(","))}\n'.encode()
        if body.startswith('SELECT COUNT(*) FROM guard_inference WHERE observation_id IN'):
            return f'{self.children[1] * len(re.search(r"IN [(]([0-9,]+)[)]", body).group(1).split(","))}\n'.encode()
        if body.startswith('CREATE TEMPORARY TABLE ret_public'):
            self.verify_sql = sql
            return ''.join(f'{v}\n' for v in self.refs).encode()
        raise AssertionError('unexpected SQL: ' + body[:120])

    def _delete(self, body):
        out = []
        for statement in re.findall(r'DELETE FROM (\w+) WHERE (\w+) IN \(([\d,]+)\)', body):
            table, column, ids = statement
            ids = [int(i) for i in ids.split(',')]
            if column == 'observation_id':
                factor = self.children[0] if table == 'guard_rule_evaluation' else self.children[1]
                out.append(len(ids) * factor)
                continue
            rule = next(k for k, t in r.TABLE.items() if t == table)
            fresh = [i for i in ids if i not in self.deleted[rule]]
            self.deleted[rule].update(fresh)
            out.append(len(fresh))
        return ''.join(f'{v}\n' for v in out).encode()


def run(tmp_path, db, command, *extra, schema=CLONE):
    argv = [command, '--schema', schema, '--work', str(tmp_path / 'plan'), '--asset', ASSET, '--as-of', '2026-12-07', *extra]
    return r.main(argv, database=db)


def test_cutoffs_and_literals():
    assert r.cutoffs('2026-12-07', r.DEFAULT_DAYS) == {
        'idempotency': '2026-11-30 00:00:00', 'health': '2026-11-07 00:00:00', 'observation': '2026-11-07 00:00:00'}
    for bad in ('2026-12-7', "2026-12-07'; DROP", None):
        with pytest.raises(r.RetentionError, match='AS_OF_INVALID'):
            r.cutoffs(bad, r.DEFAULT_DAYS)
    with pytest.raises(r.RetentionError, match='RETENTION_DAYS_INVALID'):
        r.cutoffs('2026-12-07', dict(r.DEFAULT_DAYS, health=0))
    with pytest.raises(r.RetentionError, match='SQL_LITERAL_INVALID'):
        r.quote("x' OR 1=1")


def test_candidate_sql_keeps_references_out():
    cut = r.cutoffs('2026-12-07', r.DEFAULT_DAYS)
    r1, r2, r3 = (r.candidate_sql(k, [5], cut) for k in r.RULES)
    assert r1.count('JSON_CONTAINS_PATH') == 4 and 'healthWindowId' in r1 and 'batchId' in r1
    assert "verification_status='healthy'" in r2 and 'a.rid IS NULL' in r2 and 'h.asset_id IN (5)' in r2
    for needle in ('selectedObservations', 'triggerObservationId', 'a.rid IS NULL', 'guard_episode_evidence e WHERE e.observation_id',
                   'e.inference_id=i.id', 'guard_feedback', "o.direction='unknown'"):
        assert needle in r3
    with pytest.raises(r.RetentionError, match='ASSETS_REQUIRED'):
        r.candidate_sql('R2', [], cut)


@pytest.mark.parametrize('schema,auth,confirm,write,code', [
    ('cyber_security', None, False, True, 'BUSINESS_REQUIRES_AUTHORIZATION'),
    ('cyber_security', 'D-N6', False, True, 'BUSINESS_REQUIRES_AUTHORIZATION'),
    ('cyber_security_copy', 'D-N6', True, True, 'SCHEMA_NOT_ALLOWED'),
    ('cyber_r6_restore_xyz', None, False, False, 'SCHEMA_NOT_ALLOWED'),
])
def test_schema_gate(schema, auth, confirm, write, code):
    with pytest.raises(r.RetentionError, match=code):
        r.check_schema(schema, auth, confirm, write)


def test_schema_gate_allows_read_only_business_and_clones():
    r.check_schema('cyber_security', write=False)
    r.check_schema('cyber_security', 'D-N6', True, write=True)
    r.check_schema(CLONE, write=True)


def test_plan_apply_verify_round_trip(tmp_path):
    db = FakeDb({'R1': list(range(1, 12)), 'R2': [20, 21, 22], 'R3': [30, 31]})
    assert run(tmp_path, db, 'plan') == 0
    plan = json.loads((tmp_path / 'plan/plan.json').read_text())
    assert {k: v['count'] for k, v in plan['rules'].items()} == {'R1': 11, 'R2': 3, 'R3': 2}
    assert plan['rules']['R3']['ruleEvaluations'] == 6 and plan['rules']['R3']['inferences'] == 2
    assert (tmp_path / 'plan').stat().st_mode & 0o077 == 0
    assert run(tmp_path, db, 'apply', '--batch', '4') == 0
    applied = json.loads((tmp_path / 'plan/apply.json').read_text())
    assert applied['rules']['R1']['deleted'] == {'guard_idempotency': 11}
    assert applied['rules']['R3']['deleted'] == {'guard_rule_evaluation': 6, 'guard_inference': 2, 'guard_observation': 2}
    # R1 分 3 批（4+4+3），每批一个事务；R3 子表先删。
    r1 = db.writes[0]
    assert r1.count('START TRANSACTION;') == 3 and r1.count('COMMIT;') == 3
    r3 = db.writes[-1]
    assert r3.index('guard_rule_evaluation') < r3.index('guard_inference') < r3.index('DELETE FROM guard_observation')
    assert run(tmp_path, db, 'verify') == 0
    # 核验会话不能设只读（临时表），也不能出现任何 DELETE/UPDATE。
    assert db.verify_sql and 'READ ONLY' not in db.verify_sql and not re.search(r'\b(DELETE|UPDATE|DROP)\b', db.verify_sql)
    verified = json.loads((tmp_path / 'plan/verify.json').read_text())
    assert verified['passed'] and set(verified['remaining'].values()) == {0}


def test_verify_fails_on_dangling_reference(tmp_path):
    db = FakeDb({'R1': [1], 'R2': [2], 'R3': [3]}, refs=(0, 1, 0, 0, 0))
    run(tmp_path, db, 'plan'); run(tmp_path, db, 'apply')
    assert run(tmp_path, db, 'verify') == 1
    assert json.loads((tmp_path / 'plan/verify.json').read_text())['references']['decisionReferences'] == 1


def test_apply_refuses_changed_candidates_or_edited_plan(tmp_path):
    db = FakeDb({'R1': [1, 2], 'R2': [3], 'R3': [4]})
    run(tmp_path, db, 'plan')
    db.candidates['R2'] = [3, 5]
    with pytest.raises(r.RetentionError, match='CANDIDATES_CHANGED_SINCE_PLAN'):
        run(tmp_path, db, 'apply')
    assert db.writes and 'guard_capture_health_window' not in ''.join(db.writes)
    db2 = FakeDb({'R1': [1, 2], 'R2': [3], 'R3': [4]})
    (tmp_path / 'p2').mkdir()
    run(tmp_path / 'p2', db2, 'plan')
    (tmp_path / 'p2/plan/R1.ids').write_text('1\n')
    with pytest.raises(r.RetentionError, match='PLAN_FILE_CHANGED'):
        run(tmp_path / 'p2', db2, 'apply')
    assert db2.writes == []


def test_apply_refuses_child_count_drift(tmp_path):
    db = FakeDb({'R1': [], 'R2': [], 'R3': [7, 8]})
    run(tmp_path, db, 'plan')
    db.children = (2, 1)
    with pytest.raises(r.RetentionError, match='CHILD_COUNT_MISMATCH'):
        run(tmp_path, db, 'apply')


@pytest.mark.parametrize('checks,env,code', [('1\t0\t0', 'authorized', 'ASSET_HAS_ACTIONS_OR_LAB_EVIDENCE'),
                                            ('0\t2\t0', 'authorized', 'ASSET_HAS_ACTIONS_OR_LAB_EVIDENCE'),
                                            ('0\t0\t0', 'lab', 'ASSET_NOT_AUTHORIZED_ENVIRONMENT')])
def test_asset_preconditions(tmp_path, checks, env, code):
    db = FakeDb({'R1': [], 'R2': [], 'R3': []}, asset_checks=checks, env=env)
    with pytest.raises(r.RetentionError, match=code):
        run(tmp_path, db, 'plan')
    assert not (tmp_path / 'plan/plan.json').exists()
