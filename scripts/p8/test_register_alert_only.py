"""DB-9 的写入后审计门：合法新增可接受，旧记录、凭据、资产和结构变化均拒绝。"""
from copy import deepcopy
import unittest

from scripts.p8.register_alert_only import EXPECTED, deltas, digest


def snapshot():
    tables = {}
    for name in [*EXPECTED, 'sys_user', 'asset', 'audit_log']:
        rows = {'old-key': 'old-row'}
        tables[name] = {'count': 1, 'rows': rows, 'sha256': digest(rows), 'invariantSha256': digest(rows)}
    return {'schemaSha256': 'schema-v25', 'tables': tables}


def refresh(table):
    table['count'] = len(table['rows'])
    table['sha256'] = digest(table['rows'])


class DeltaTest(unittest.TestCase):
    def setUp(self):
        self.before = snapshot()
        self.after = deepcopy(self.before)
        for name, count in EXPECTED.items():
            self.after['tables'][name]['rows'].update({f'new-{i}': f'value-{i}' for i in range(count)})
            refresh(self.after['tables'][name])

    def test_accepts_expected_append_and_login_time(self):
        users = self.after['tables']['sys_user']
        users['rows']['old-key'] = 'login-time-only'
        refresh(users)  # 独立 invariant 摘要仍相同；生产 snapshot 只略过两位操作者的登录时间。
        self.assertEqual(deltas(self.before, self.after), EXPECTED | {'sys_user': 0})

    def test_rejects_existing_bundle_rewrite_even_when_counts_match(self):
        table = self.after['tables']['guard_release_bundle']
        table['rows']['old-key'] = 'modified-r5'
        refresh(table)
        with self.assertRaisesRegex(RuntimeError, 'EXISTING_ROW_CHANGED:guard_release_bundle'):
            deltas(self.before, self.after)

    def test_rejects_account_credential_change(self):
        table = self.after['tables']['sys_user']
        table['rows']['old-key'] = 'changed-password'
        refresh(table)
        table['invariantSha256'] = 'changed-invariant'
        with self.assertRaisesRegex(RuntimeError, 'ACCOUNT_IDENTITY_OR_CREDENTIAL_CHANGED'):
            deltas(self.before, self.after)

    def test_rejects_real_asset_creation(self):
        table = self.after['tables']['asset']
        table['rows']['new'] = 'unauthorized-asset'
        refresh(table)
        with self.assertRaisesRegex(RuntimeError, 'UNEXPECTED_TABLE_CHANGED:asset'):
            deltas(self.before, self.after)

    def test_rejects_schema_or_missing_business_increment(self):
        self.after['schemaSha256'] = 'schema-v26'
        with self.assertRaisesRegex(RuntimeError, 'DATABASE_STRUCTURE_CHANGED'):
            deltas(self.before, self.after)
        self.after['schemaSha256'] = self.before['schemaSha256']
        self.after['tables']['guard_evaluation_run'] = self.before['tables']['guard_evaluation_run']
        with self.assertRaisesRegex(RuntimeError, 'BUSINESS_DELTA_MISMATCH'):
            deltas(self.before, self.after)


if __name__ == '__main__':
    unittest.main()
