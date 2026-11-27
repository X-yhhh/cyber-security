#!/usr/bin/env python3
"""只备份业务库并恢复到随机库逐表验证；默认删除恢复库，--keep-restored 只保留核验通过的库。"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.register_alert_only import Database, HOME, require, write
from scripts.p7.j1_run import stamp, database_timeout


def main(args):
    if args.schedule:
        print("建议：每次发布切换前及批准的每日维护窗口运行本脚本；必须停写且业务库无人连接。"
              "只生成说明，不安装 launchd/cron。保留最近 7 次及每次发布前备份；删除与实际恢复须单独授权。"
              "检查 result.json passed=true 和两份 SQL 的 SHA256；默认 temporarySchemaDeleted=true，"
              "--keep-restored 成功时为 false，须按 restoredSchema 交接清理。")
        return
    os.umask(0o077)
    db = Database(args.mysql_service, timeout_seconds=args.timeout_seconds)
    require(int(db.query("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB='cyber_security' AND ID<>CONNECTION_ID()")) == 0,
            'BUSINESS_DATABASE_IN_USE')
    folder = args.mysql_service / 'backups' / ('cyber-security-' + stamp().replace(':', '-') + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    started = time.monotonic()
    target = 'cyber_r6_restore_' + uuid.uuid4().hex[:16]
    result = {'passed': False, 'backupDirectory': str(folder), 'restoredSchema': target,
              'timeoutSeconds': db.timeout_seconds, 'keepRestored': args.keep_restored}
    try:
        snapshot, backup = db.backup_restore('cyber_security', target, folder)
        result.update(passed=True, sourceSha256=snapshot['contentSha256'], tables=len(snapshot['tables']), backup=str(backup))
    except Exception as exc:
        result['errorType'] = type(exc).__name__
        raise
    finally:
        # 只保留已通过完整核验的克隆；失败仍清理本次拥有的随机库，备份永远保留。
        try:
            if not (args.keep_restored and result['passed']):
                db.drop_owned()
        except Exception as exc:
            result['passed'] = False
            result['cleanupErrorType'] = type(exc).__name__
            raise
        finally:
            result['temporarySchemaDeleted'] = getattr(db, 'owned_schema', None) is None
            result['elapsedSeconds'] = round(time.monotonic() - started, 3)
            write(folder / 'result.json', result)
            print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schedule', action='store_true', help='只显示备份调度与保留建议，不取密、不连接数据库')
    parser.add_argument('--timeout-seconds', type=database_timeout, help='整库操作超时秒数；默认 CYBER_DB_TIMEOUT_SECONDS 或 300')
    parser.add_argument('--keep-restored', action='store_true', help='核验通过后保留 result.json 中的随机库，由调用方按准确名称清理')
    parser.add_argument('--mysql-service', type=Path, default=HOME / 'development/services/databases/mysql-server-8.0.42')
    try:
        main(parser.parse_args())
    except Exception:
        raise SystemExit(1) from None
