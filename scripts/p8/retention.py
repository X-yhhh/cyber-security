"""DB-13 / V2-0.6 业务库数据保留：只读预演（plan）、按预演清单分批删除（apply）与删除后引用核验（verify）。

只处理三类“超期且不被任何证据引用”的行，规则与默认保留期如下（默认值是方案建议，执行前由用户决定）：

  R1 guard_idempotency：机器上传与心跳的幂等结果——健康窗口、观察批次、传感器心跳、执行器心跳四种响应形状，
     创建早于 as_of − idempotency_days。人工操作、lab、预算、命令领取等其余形状一律保留。
  R2 guard_capture_health_window：指定资产的 healthy 窗口，interval_end 早于 as_of − health_days，且未被审计引用。
     非 healthy 窗口均有 guard.health.rejected 审计，随审计保留。
  R3 guard_observation：指定资产、direction=unknown、创建早于 as_of − observation_days，且未被 episode 证据
     （观察或其推理）、反馈、审计、判定证据（selectedObservations、triggerObservationId）引用；
     连带删除它的 guard_rule_evaluation 与 guard_inference。

指定资产必须是 authorized 环境、没有任何处置动作、没有 replay_healthy 窗口；lab/回放资产不进入本工具。
判定、episode、动作、事件、反馈、审计、组合、策略、模型与配置不删除。

apply 只接受 plan 写出的清单，并在执行前重新计算候选集合，集合摘要必须与清单一致才删除。
业务库（cyber_security）只能带 --authorization 与 --confirm-business 执行；其余库名必须是随机克隆库。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p7 import j1_run  # noqa: E402

BUSINESS = 'cyber_security'
CLONE = re.compile(r'cyber_r6_(rehearsal|restore)_[0-9a-f]{16}')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
DEFAULT_DAYS = {'idempotency': 7, 'health': 30, 'observation': 30}
RULES = ('R1', 'R2', 'R3')
TABLE = {'R1': 'guard_idempotency', 'R2': 'guard_capture_health_window', 'R3': 'guard_observation'}
SESSION = "SET time_zone='+00:00'; SET SESSION max_execution_time=0;\n"
READ_ONLY = SESSION + 'SET SESSION TRANSACTION READ ONLY;\n'

# 四种机器响应形状：键集合与状态码同时匹配才算，避免误删同名字段的人工操作结果。
MACHINE_SHAPES = (
    (200, ('contentSha256', 'healthWindowId', 'serverTime', 'verificationStatus')),
    (202, ('acceptedCount', 'batchId', 'duplicateCount', 'rejectedCount', 'rejections', 'status')),
    (200, ('serverTime',)),
    (200, ('serverTime', 'status')),
)


class RetentionError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise RetentionError(code)


def quote(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9A-Za-z_:.$ -]+', value), 'SQL_LITERAL_INVALID')
    return "'" + value + "'"


def cutoffs(as_of, days):
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}', as_of or ''), 'AS_OF_INVALID')
    base = dt.datetime.strptime(as_of, '%Y-%m-%d')
    for key in DEFAULT_DAYS:
        require(isinstance(days[key], int) and 1 <= days[key] <= 3650, 'RETENTION_DAYS_INVALID')
    return {key: (base - dt.timedelta(days=value)).strftime('%Y-%m-%d %H:%M:%S') for key, value in days.items()}


def candidate_sql(rule, assets, cut):
    """返回只选 id 的候选查询；assets 为内部资产 id 列表。"""
    ids = ','.join(str(int(a)) for a in assets)
    require(ids, 'ASSETS_REQUIRED')
    if rule == 'R1':
        shapes = ' OR '.join(
            f"(i.http_status={status} AND JSON_LENGTH(i.response_json)={len(keys)} AND "
            f"JSON_CONTAINS_PATH(i.response_json,'all',{','.join(quote('$.' + k) for k in keys)}))"
            for status, keys in MACHINE_SHAPES)
        return (f"SELECT i.id FROM guard_idempotency i WHERE i.created_at<{quote(cut['idempotency'])} "
                f"AND i.response_json IS NOT NULL AND ({shapes}) ORDER BY i.id")
    if rule == 'R2':
        return (f"SELECT h.id FROM guard_capture_health_window h LEFT JOIN ({AUDIT_REFS}) a ON a.rid=h.public_id "
                f"WHERE h.asset_id IN ({ids}) AND h.verification_status='healthy' AND h.interval_end<{quote(cut['health'])} "
                "AND a.rid IS NULL ORDER BY h.id")
    require(rule == 'R3', 'RULE_UNKNOWN')
    return (f"SELECT o.id FROM guard_observation o LEFT JOIN ({decision_refs()}) r ON r.oid=o.public_id "
            f"LEFT JOIN ({AUDIT_REFS}) a ON a.rid=o.public_id WHERE o.asset_id IN ({ids}) AND o.direction='unknown' AND o.created_at<{quote(cut['observation'])} "
            "AND r.oid IS NULL AND a.rid IS NULL "
            "AND NOT EXISTS (SELECT 1 FROM guard_episode_evidence e WHERE e.observation_id=o.id) "
            "AND NOT EXISTS (SELECT 1 FROM guard_inference i JOIN guard_episode_evidence e ON e.inference_id=i.id WHERE i.observation_id=o.id) "
            "AND NOT EXISTS (SELECT 1 FROM guard_feedback f WHERE f.observation_id=o.id) "
            "ORDER BY o.id")


# 全部审计资源编号（不限资源类型），用哈希反连接排除任何被审计引用的行。
AUDIT_REFS = ("SELECT DISTINCT CAST(resource_id AS CHAR(160) CHARACTER SET ascii) COLLATE ascii_bin rid FROM audit_log "
              "WHERE resource_id IS NOT NULL")


def decision_refs():
    """判定证据里引用的全部观察 public_id（选定证据与触发观察）。"""
    return ("SELECT CAST(j.oid AS CHAR(36) CHARACTER SET ascii) COLLATE ascii_bin oid FROM guard_decision d, "
            "JSON_TABLE(d.evidence_json,'$.selectedObservations[*]' COLUMNS (oid VARCHAR(64) PATH '$.observationId')) j "
            "WHERE j.oid IS NOT NULL UNION "
            "SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(d.evidence_json,'$.triggerObservationId')) AS CHAR(36) CHARACTER SET ascii) "
            "COLLATE ascii_bin FROM guard_decision d WHERE JSON_TYPE(JSON_EXTRACT(d.evidence_json,'$.triggerObservationId'))='STRING'")


def id_digest(ids):
    return hashlib.sha256(('\n'.join(str(i) for i in ids) + '\n').encode()).hexdigest()


def check_schema(schema, authorization=None, confirm=False, write=False):
    if schema == BUSINESS:
        if write:
            require(authorization and confirm, 'BUSINESS_REQUIRES_AUTHORIZATION')
        return
    require(CLONE.fullmatch(schema or ''), 'SCHEMA_NOT_ALLOWED')


class Retention:
    def __init__(self, db, schema):
        self.db, self.schema = db, schema

    def query(self, sql, read_only=True):
        return self.db.query((READ_ONLY if read_only else SESSION) + sql, self.schema).decode()

    def rows(self, sql):
        return [line.split('\t') for line in self.query(sql).splitlines() if line]

    def assets(self, public_ids):
        require(public_ids and all(UUID.fullmatch(p) for p in public_ids), 'ASSET_ID_INVALID')
        found = self.rows('SELECT id,public_id,environment FROM asset WHERE public_id IN (' + ','.join(quote(p) for p in public_ids) + ')')
        require(len(found) == len(set(public_ids)), 'ASSET_NOT_FOUND')
        result = []
        for internal, public, environment in found:
            require(environment == 'authorized', 'ASSET_NOT_AUTHORIZED_ENVIRONMENT')
            checks = self.rows(
                f"SELECT (SELECT COUNT(*) FROM guard_action a JOIN guard_decision d ON d.id=a.decision_id WHERE d.asset_id={int(internal)}),"
                f"(SELECT COUNT(*) FROM guard_capture_health_window WHERE asset_id={int(internal)} AND verification_status='replay_healthy'),"
                f"(SELECT COUNT(*) FROM guard_observation WHERE asset_id={int(internal)} AND environment<>'authorized')")[0]
            require(checks == ['0', '0', '0'], 'ASSET_HAS_ACTIONS_OR_LAB_EVIDENCE')
            result.append(int(internal))
        return sorted(result)

    def candidates(self, rule, assets, cut):
        return [int(line) for line in self.query(candidate_sql(rule, assets, cut)).split()]

    def public_ids(self, rule, ids):
        out = []
        for chunk in chunks(ids, 20000):
            out += self.query(f"SELECT public_id FROM {TABLE[rule]} WHERE id IN ({','.join(map(str, chunk))}) ORDER BY id").split()
        return out

    def plan(self, assets_public, as_of, days, out):
        cut = cutoffs(as_of, days)
        assets = self.assets(assets_public)
        record = {'schema': self.schema, 'asOf': as_of, 'days': days, 'cutoffs': cut, 'assets': assets_public,
                  'assetIds': assets, 'plannedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'rules': {}}
        for rule in RULES:
            start = time.monotonic()
            ids = self.candidates(rule, assets, cut)
            entry = {'table': TABLE[rule], 'count': len(ids), 'idSha256': id_digest(ids), 'seconds': round(time.monotonic() - start, 3)}
            if rule == 'R3':
                entry['ruleEvaluations'] = self.count_children('guard_rule_evaluation', ids)
                entry['inferences'] = self.count_children('guard_inference', ids)
            write_ids(out / f'{rule}.ids', ids)
            if rule in ('R2', 'R3'):
                write_ids(out / f'{rule}.public', self.public_ids(rule, ids))
            record['rules'][rule] = entry
        write_json(out / 'plan.json', record)
        return record

    def count_children(self, table, ids):
        total = 0
        for chunk in chunks(ids, 20000):
            total += int(self.query(f"SELECT COUNT(*) FROM {table} WHERE observation_id IN ({','.join(map(str, chunk))})"))
        return total

    def apply(self, plan_dir, batch, out):
        plan = json.loads((plan_dir / 'plan.json').read_text())
        require(plan['schema'] == self.schema, 'PLAN_SCHEMA_MISMATCH')
        assets = self.assets(plan['assets'])
        require(assets == plan['assetIds'], 'PLAN_ASSETS_MISMATCH')
        result = {'schema': self.schema, 'plan': plan, 'startedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'rules': {}}
        for rule in RULES:
            ids = read_ids(plan_dir / f'{rule}.ids')
            require(id_digest(ids) == plan['rules'][rule]['idSha256'], 'PLAN_FILE_CHANGED')
            current = self.candidates(rule, assets, plan['cutoffs'])
            require(id_digest(current) == plan['rules'][rule]['idSha256'], 'CANDIDATES_CHANGED_SINCE_PLAN')
            start, deleted = time.monotonic(), {}
            for group in chunks(list(chunks(ids, batch)), 10):
                for table, count in self.delete(rule, group, plan['cutoffs'], assets).items():
                    deleted[table] = deleted.get(table, 0) + count
            require(deleted.get(TABLE[rule], 0) == len(ids), 'DELETED_COUNT_MISMATCH')
            if rule == 'R3':
                require(deleted.get('guard_rule_evaluation', 0) == plan['rules'][rule]['ruleEvaluations']
                        and deleted.get('guard_inference', 0) == plan['rules'][rule]['inferences'], 'CHILD_COUNT_MISMATCH')
            result['rules'][rule] = {'deleted': deleted, 'seconds': round(time.monotonic() - start, 3)}
            write_json(out / 'apply.json', result, replace=True)
        result['finishedAt'] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(out / 'apply.json', result, replace=True)
        return result

    def delete(self, rule, groups, cut, assets):
        """每批一个事务；删除语句重复候选条件，任何一步失败都整批回滚并停止。"""
        ids_sql = ','.join(str(int(a)) for a in assets)
        script, tables = [], []
        for ids in groups:
            values = ','.join(map(str, ids))
            script.append('START TRANSACTION;')
            if rule == 'R1':
                statements = [('guard_idempotency', f"DELETE FROM guard_idempotency WHERE id IN ({values}) AND created_at<{quote(cut['idempotency'])}")]
            elif rule == 'R2':
                statements = [('guard_capture_health_window', f"DELETE FROM guard_capture_health_window WHERE id IN ({values}) AND asset_id IN ({ids_sql}) "
                               f"AND verification_status='healthy' AND interval_end<{quote(cut['health'])}")]
            else:
                statements = [('guard_rule_evaluation', f"DELETE FROM guard_rule_evaluation WHERE observation_id IN ({values})"),
                              ('guard_inference', f"DELETE FROM guard_inference WHERE observation_id IN ({values})"),
                              ('guard_observation', f"DELETE FROM guard_observation WHERE id IN ({values}) AND asset_id IN ({ids_sql}) "
                               f"AND direction='unknown' AND created_at<{quote(cut['observation'])}")]
            for table, sql in statements:
                script += [sql + ';', 'SELECT ROW_COUNT();']
                tables.append(table)
            script.append('COMMIT;')
        counts = [int(v) for v in self.query('\n'.join(script), read_only=False).split()]
        require(len(counts) == len(tables), 'DELETE_OUTPUT_UNEXPECTED')
        totals = {}
        for table, count in zip(tables, counts):
            totals[table] = totals.get(table, 0) + count
        return totals

    def verify(self, plan_dir):
        """删除后：候选行不再存在；审计与判定证据没有指向已删 public_id 的引用；外键无孤儿。"""
        plan = json.loads((plan_dir / 'plan.json').read_text())
        require(plan['schema'] == self.schema, 'PLAN_SCHEMA_MISMATCH')
        report = {'remaining': {}, 'references': {}}
        for rule in RULES:
            ids = read_ids(plan_dir / f'{rule}.ids')
            remaining = 0
            for chunk in chunks(ids, 20000):
                remaining += int(self.query(f"SELECT COUNT(*) FROM {TABLE[rule]} WHERE id IN ({','.join(map(str, chunk))})"))
            report['remaining'][rule] = remaining
        public = [p for rule in ('R2', 'R3') for p in (plan_dir / f'{rule}.public').read_text().split()]
        require(all(UUID.fullmatch(p) for p in public), 'PUBLIC_ID_FILE_INVALID')
        load = ['CREATE TEMPORARY TABLE ret_public (public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY);']
        for chunk in chunks(public, 5000):
            load.append('INSERT INTO ret_public VALUES ' + ','.join("('" + p + "')" for p in chunk) + ';')
        checks = {
            'auditReferences': 'SELECT COUNT(*) FROM audit_log a JOIN ret_public p ON p.public_id=a.resource_id',
            'decisionReferences': f'SELECT COUNT(*) FROM ({decision_refs()}) r JOIN ret_public p ON p.public_id=r.oid',
            'orphanRuleEvaluations': 'SELECT COUNT(*) FROM guard_rule_evaluation r LEFT JOIN guard_observation o ON o.id=r.observation_id WHERE o.id IS NULL',
            'orphanInferences': 'SELECT COUNT(*) FROM guard_inference i LEFT JOIN guard_observation o ON o.id=i.observation_id WHERE o.id IS NULL',
            'orphanEvidence': 'SELECT COUNT(*) FROM guard_episode_evidence e LEFT JOIN guard_observation o ON o.id=e.observation_id '
                              'LEFT JOIN guard_inference i ON i.id=e.inference_id WHERE o.id IS NULL OR i.id IS NULL',
        }
        names = list(checks)
        # 只读会话不允许建临时表（MySQL 1792）；本会话只写会话级临时表 ret_public，不改任何业务表。
        values = self.query('\n'.join(load) + '\n' + '\n'.join(checks[n] + ';' for n in names), read_only=False).split()
        require(len(values) == len(names), 'VERIFY_OUTPUT_UNEXPECTED')
        report['references'] = {n: int(v) for n, v in zip(names, values)}
        report['passed'] = all(v == 0 for v in report['remaining'].values()) and all(v == 0 for v in report['references'].values())
        return report


def chunks(values, size):
    require(size > 0, 'BATCH_INVALID')
    return [values[i:i + size] for i in range(0, len(values), size)]


def write_ids(path, ids):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        stream.write(''.join(f'{i}\n' for i in ids))


def read_ids(path):
    return [int(v) for v in path.read_text().split()]


def write_json(path, value, replace=False):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL)
    with os.fdopen(os.open(path, flags, 0o600), 'w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def private_dir(path, exist_ok=False):
    path.mkdir(mode=0o700, parents=False, exist_ok=exist_ok)
    require(path.stat().st_mode & 0o077 == 0, 'WORK_DIR_NOT_PRIVATE')
    return path


def main(argv=None, database=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('command', choices=('plan', 'apply', 'verify'))
    p.add_argument('--schema', required=True)
    p.add_argument('--work', type=Path, required=True, help='私有目录：plan 新建；apply/verify 读取其中的清单')
    p.add_argument('--mysql-service', type=Path, default=Path.home() / 'Workspace/development/services/databases/mysql-server-8.0.42')
    p.add_argument('--asset', action='append', default=[], help='资产 public_id，可重复')
    p.add_argument('--as-of', help='UTC 日期 YYYY-MM-DD，各保留期从当日 00:00 往前推')
    p.add_argument('--idempotency-days', type=int, default=DEFAULT_DAYS['idempotency'])
    p.add_argument('--health-days', type=int, default=DEFAULT_DAYS['health'])
    p.add_argument('--observation-days', type=int, default=DEFAULT_DAYS['observation'])
    p.add_argument('--batch', type=int, default=5000)
    p.add_argument('--authorization', help='业务库执行必填，如 D-N6')
    p.add_argument('--confirm-business', action='store_true')
    args = p.parse_args(argv)
    check_schema(args.schema, args.authorization, args.confirm_business, write=args.command == 'apply')
    db = database or j1_run.Database(args.mysql_service, 3600)
    tool = Retention(db, args.schema)
    if args.command == 'plan':
        days = {'idempotency': args.idempotency_days, 'health': args.health_days, 'observation': args.observation_days}
        result = tool.plan(args.asset, args.as_of, days, private_dir(args.work))
    elif args.command == 'apply':
        require(1 <= args.batch <= 20000, 'BATCH_INVALID')
        result = tool.apply(args.work, args.batch, args.work)
        if args.schema == BUSINESS:
            result['authorization'] = args.authorization
            write_json(args.work / 'apply.json', result, replace=True)
    else:
        result = tool.verify(args.work)
        write_json(args.work / 'verify.json', result, replace=True)
    print(json.dumps({k: v for k, v in result.items() if k != 'plan'}, ensure_ascii=False, indent=2))
    return 0 if result.get('passed', True) else 1


if __name__ == '__main__':
    sys.exit(main())
