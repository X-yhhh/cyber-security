"""在线整库备份：同一只读事务导出行、摘要和 JSON 精度修复；不阻断 en0 写入。

仅支持本项目 MySQL 8 InnoDB 基表。遇到视图/触发器/例程/事件拒绝，避免悄悄漏备份。
恢复只写本次随机临时库，比较完整数据与 DDL；失败保留备份，绝不恢复到源业务库。
"""
import os
import re
import subprocess
from scripts.demo.common import require, sha, write
from scripts.p8.register_alert_only import Database, ident, hex_value


class TransactionView(Database):
    """复用既有逐列/JSON DOUBLE 精度验证，但所有源库读取固定在一个连接的同一快照。"""
    def __init__(self, connection, schema):
        self.connection, self.schema = connection, schema

    def query(self, sql, schema=None):
        require(schema in (None, self.schema), 'BACKUP_SCHEMA_CHANGED')
        # snapshot() 自带事务语句；外层已经建立只读快照，不能让它提交/重启。
        sql = re.sub(r"(?:SET time_zone='\+00:00'|SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ|START TRANSACTION WITH CONSISTENT SNAPSHOT|COMMIT);?\s*", '', sql)
        result = []
        with self.connection.cursor() as cursor:
            cursor.execute(sql)
            while True:
                if cursor.description:
                    for row in cursor.fetchall():
                        result.append('\t'.join('NULL' if x is None else x.decode() if isinstance(x, bytes) else str(x) for x in row))
                if not cursor.nextset():
                    break
        return ('\n'.join(result) + ('\n' if result else '')).encode()


def insert_statement(table, columns, row):
    """值只来自服务端 HEX，恢复按原列类型转换；不把数据或秘密拼进可执行标识符。"""
    require(len(columns) == len(row), 'BACKUP_ROW_INVALID')
    values = []
    for (_, kind), value in zip(columns, row):
        if value is None:
            values.append('NULL')
        else:
            require(isinstance(value, str) and re.fullmatch('[0-9A-Fa-f]*', value), 'BACKUP_HEX_INVALID')
            binary = kind in {"binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "bit"}
            if kind in {'float', 'double'}:
                values.append("ST_X(ST_GeomFromWKB(UNHEX('" + value + "'))) ")
            elif kind == 'bit':
                values.append("CAST(CONV('" + value + "',16,10) AS UNSIGNED)")
            else:
                values.append("UNHEX('" + value + "')" if binary else "CONVERT(UNHEX('" + value + "') USING utf8mb4)")
    return 'INSERT INTO ' + ident(table) + '(' + ','.join(ident(c) for c, _ in columns) + ') VALUES (' + ','.join(values) + ');\n'


def capture(db, source, folder):
    import pymysql
    from pymysql.constants import CLIENT
    ident(source)
    connection = pymysql.connect(host='127.0.0.1', port=3306, user='root', password=db.env['MYSQL_PWD'],
                                 database=source, charset='utf8mb4', autocommit=False, connect_timeout=5,
                                 read_timeout=300, write_timeout=30, client_flag=CLIENT.MULTI_STATEMENTS)
    backup, fidelity = folder / 'database.sql', folder / 'json-double-fidelity.sql'
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET time_zone='+00:00'; SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ; START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            while cursor.nextset():
                pass
        view = TransactionView(connection, source)
        for catalog in ('VIEWS', 'TRIGGERS', 'ROUTINES', 'EVENTS'):
            column = {'VIEWS': 'TABLE_SCHEMA', 'TRIGGERS': 'TRIGGER_SCHEMA', 'ROUTINES': 'ROUTINE_SCHEMA', 'EVENTS': 'EVENT_SCHEMA'}[catalog]
            require(view.query(f"SELECT COUNT(*) FROM information_schema.{catalog} WHERE {column}='{source}'").strip() == b'0', 'BACKUP_UNSUPPORTED_OBJECT')
        tables = view.query(f"SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='{source}' ORDER BY TABLE_NAME").decode().splitlines()
        require(tables and all(t.split('\t')[1] == 'InnoDB' for t in tables), 'BACKUP_REQUIRES_INNODB')
        with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            stream.write("SET time_zone='+00:00'; SET FOREIGN_KEY_CHECKS=0; SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n")
            for entry in tables:
                table = entry.split('\t')[0]
                ddl = view.query('SHOW CREATE TABLE ' + ident(table), source).decode().split('\t', 1)[1].rstrip('\n')
                stream.write(ddl + ';\n')
                columns = view.query(f"SELECT COLUMN_NAME,DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='{source}' AND TABLE_NAME='{table}' AND EXTRA NOT LIKE '%VIRTUAL GENERATED%' AND EXTRA NOT LIKE '%STORED GENERATED%' ORDER BY ORDINAL_POSITION").decode().splitlines()
                columns = [tuple(line.split('\t')) for line in columns]
                require(all(kind in {'binary', 'varbinary', 'tinyblob', 'blob', 'mediumblob', 'longblob', 'bit', 'char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext', 'enum', 'set', 'json', 'tinyint', 'smallint', 'mediumint', 'int', 'bigint', 'decimal', 'float', 'double', 'date', 'time', 'datetime', 'timestamp', 'year'} for _, kind in columns), 'BACKUP_UNSUPPORTED_COLUMN')
                # HEX 输出保持二进制/时区/转义边界；SSCursor 避免把整个业务表加载到内存。
                with connection.cursor(pymysql.cursors.SSCursor) as cursor:
                    cursor.execute('SELECT ' + ','.join('HEX(CONVERT(' + ident(c) + ' USING utf8mb4))' if kind in {'char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext', 'enum', 'set', 'json'} else hex_value(c, kind) for c, kind in columns) + ' FROM ' + ident(table))
                    for row in cursor:
                        stream.write(insert_statement(table, columns, row))
            stream.write('SET FOREIGN_KEY_CHECKS=1;\n')
            stream.flush()
            os.fsync(stream.fileno())
        require(tables == view.query(f"SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA='{source}' ORDER BY TABLE_NAME").decode().splitlines(), 'BACKUP_SCHEMA_CHANGED')
        source_snapshot = view.snapshot(source)
        write(folder / 'source-snapshot.json', source_snapshot)
        patches = view.json_fidelity(source, fidelity)
        return source_snapshot, backup, fidelity, patches
    finally:
        connection.rollback()
        connection.close()


def backup_restore(db, source, target, folder):
    """源库只读快照与恢复库逐字核验；临时库的删除仍由调用方 finally/drop_owned 负责。"""
    require(re.fullmatch(r'cyber_r6_restore_[0-9a-f]{16}', target), 'RESTORE_SCHEMA_INVALID')
    require(not db.query("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + target + "'"), 'RESTORE_SCHEMA_EXISTS')
    before, backup, fidelity, patches = capture(db, source, folder)
    db.query('CREATE DATABASE ' + ident(target) + ' CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin')
    db.owned_schema = target
    for file in (backup, fidelity):
        with file.open('rb') as stream:
            result = subprocess.run(db.client + [target], env=db.env, stdin=stream, capture_output=True, timeout=300)
        require(result.returncode == 0, 'DEMO_BACKUP_RESTORE_FAILED')
    restored = db.snapshot(target)
    write(folder / 'restored.json', restored)
    require(before == restored, 'RESTORE_PARITY_FAILED')
    write(folder / 'restore-proof.json', dict(backupSha256=sha(backup), fidelitySha256=sha(fidelity),
          sourceSha256=before['contentSha256'], restoredSha256=restored['contentSha256'],
          fidelityUpdates=patches, sourceReadOnly=True, consistentSnapshot=True, passed=True))
    return before, backup
