#!/usr/bin/env python3
"""只备份业务库并恢复到随机库逐表验证；不回写业务库，恢复库核对后删除，备份保留。"""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.register_alert_only import Database, HOME, require, write
from scripts.p7.j1_run import stamp


def main(args):
    os.umask(0o077)
    db = Database(args.mysql_service)
    require(int(db.query("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB='cyber_security' AND ID<>CONNECTION_ID()")) == 0,
            'BUSINESS_DATABASE_IN_USE')
    folder = args.mysql_service / 'backups' / ('cyber-security-' + stamp().replace(':', '-') + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {'passed': False, 'backupDirectory': str(folder)}
    try:
        snapshot, backup = db.backup_restore('cyber_security', 'cyber_r6_restore_' + uuid.uuid4().hex[:16], folder)
        result.update(passed=True, sourceSha256=snapshot['contentSha256'], tables=len(snapshot['tables']), backup=str(backup))
    except Exception as exc:
        result['errorType'] = type(exc).__name__
        raise
    finally:
        db.drop_owned()
        result['temporarySchemaDeleted'] = getattr(db, 'owned_schema', None) is None
        write(folder / 'result.json', result)
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mysql-service', type=Path, default=HOME / 'development/services/databases/mysql-server-8.0.42')
    try:
        main(parser.parse_args())
    except Exception:
        raise SystemExit(1) from None
