#!/usr/bin/env python3
"""U5 lab 演示：复用正式回放组件，只核验封禁/TTL/清零，不生成资格报告。

后端 lab 准入要求会话内可自动类别不少于 2 个且含 brute_force，故回放各类首个冻结场景：brute_force + port_scan。
"""
import argparse
import json
import os
import shlex
import subprocess
import time
import uuid
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p7 import lab_formal
from scripts.p7.lab_run import load, write, require
from scripts.p8.toolkit import safe_main, absolute, private_file, private_dir, sha, Human

# r5 已在 G3 登记 lab_auto；演示收尾会暂停组合，重演需同一 subject 的新批准组合（如 r5′）。
R5_SUBJECT = '66b4f341c859c3c445a2a825ca6ea19c1ba167f8da3b65e2b43b20edd745e391'
DEMO_FAMILIES = ('brute_force', 'port_scan')

STEPS = ['核对 r5 同一 subject 的已批准组合、原场景与 root 暂存摘要', '用户通过 G3 密码框启动 root g3-executor（最长 1800 秒）',
         '新建回环 lab 资产', '申请并独立批准不超过 30 分钟授权', '激活该组合到本次资产',
         '只读回放 brute_force、port_scan 各一个冻结场景（1 倍速、不注入报文）', '核验 applied → expired（TTL）及执行器零规则',
         '撤销本次授权、暂停本次组合', '保留演示审计，不导入 G3 报告、不登记来源资格']


class Demo(lab_formal.Formal):
    authorization_minutes = 30
    authorization_backdate_seconds = 0
    formal_g3_eligible = False
    human_session = Human
    csrf_path = '/api/v2/auth/csrf'
    session_timeout_seconds = 1800

    def scenario_rows(self):
        rows = super().scenario_rows()
        picked = [next((r for r in rows if r['family'] == f and r['trialAutoEligible']), None) for f in DEMO_FAMILIES]
        require(all(picked), 'DEMO_SCENARIO_MISSING')
        self.state.update(demoOnly=True, formalG3Eligible=False)
        return picked

    def prepare_bundle(self):
        super().prepare_bundle()
        # 暂停是组合级动作且不可再激活；只接受 r5 同一 subject 的组合，拒绝仍有活动资产的组合。
        require(self.subject_sha == R5_SUBJECT, 'DEMO_R5_SUBJECT_REQUIRED')
        active = int(self.db.query("SELECT COUNT(*) FROM guard_asset_binding b JOIN asset_authorization a ON a.id=b.authorization_id WHERE b.bundle_id=(SELECT id FROM guard_release_bundle WHERE public_id='" + self.bundle + "') AND b.status='active' AND a.status='active' AND a.valid_until>UTC_TIMESTAMP(6)", self.schema))
        require(active == 0, 'DEMO_BUNDLE_IN_USE')

    def collect(self):
        """仅从本次资产的投影回执核对同一命令的 applied/expired，不触碰资格或历史报告。"""
        rows = self.asset_rows("SELECT JSON_OBJECT('commandId',c.public_id,'status',r.status,'projected',r.projected) "
            "FROM guard_action_receipt r JOIN guard_command c ON c.id=r.command_id WHERE r.asset_id={asset} ORDER BY r.id")
        applied = {r['commandId'] for r in rows if r['status'] == 'applied' and r['projected']}
        expired = {r['commandId'] for r in rows if r['status'] == 'expired' and r['projected']}
        status = self.state['drain']['status'] or {}
        root = self.state.get('rootResult', {})
        passed = bool(applied & expired) and status.get('activeRuleCount') == 0 and not status.get('pendingReceipts') and root.get('passed') is True
        write(self.work / 'demo-result.json', {'passed': passed, 'demoOnly': True, 'sourceEligibilityRegistered': False,
              'ttlVerifiedCommands': sorted(applied & expired), 'rootResult': root})
        require(passed, 'DEMO_BLOCK_TTL_CLEARANCE_NOT_VERIFIED')
        self.lab_op('completions', {'outcome': 'completed', 'reason': 'U5 demo only; no G3 qualification'})
        self.state['formalG3Eligible'] = False
        self.state['demoPassed'] = True

    def finish(self):
        """失败也尝试撤销；收尾失败单独留证，绝不把未撤销的演示标记成功。"""
        errors = []
        if hasattr(self, 'rev'):
            if hasattr(self, 'auth'):
                try:
                    view = self.rev.v2('/authorizations/' + self.auth, method='GET')
                    if view['status'] == 'active':
                        self.rev.v2('/authorizations/' + self.auth + '/revocations', {'reason': 'U5 demo finished'}, view['revision'])
                except Exception:
                    errors.append('AUTHORIZATION_REVOCATION_FAILED')
            if self.state.get('activation'):
                try:
                    view = self.rev.v2('/release-bundles/' + self.bundle, method='GET')
                    self.rev.v2('/release-bundles/' + self.bundle + '/suspensions', {'reason': 'U5 demo finished', 'revokeExisting': True}, view['revision'])
                except Exception:
                    errors.append('BUNDLE_SUSPENSION_FAILED')
        try:
            super().finish()
        finally:
            if self.work.exists():
                write(self.work / 'demo-cleanup.json', {'passed': not errors, 'errors': errors})
        require(not errors, 'DEMO_CLEANUP_FAILED')


def root_command(plan, args):
    """生成与 G3 一致的 root 暂存启动命令；launcher 先复制到 root 私有目录再核验摘要。"""
    require(plan['manifestSha256'] == args.stage_manifest and plan['authorizationReference'] == args.authorization_reference,
            'DEMO_ROOT_PLAN_MISMATCH')
    launcher = private_file(plan['launcher'])
    require(sha(launcher) == plan['launcherSha256'], 'DEMO_ROOT_LAUNCHER_MISMATCH')
    stage = absolute(plan['stage'])
    require(sha(stage / 'manifest.json') == args.stage_manifest, 'DEMO_STAGE_MISMATCH')
    rendezvous = absolute(args.rendezvous)
    ready = rendezvous / 'root-ready.json'
    evidence = absolute(plan['evidenceCopy'])
    require(not evidence.exists() and not ready.exists(), 'DEMO_ROOT_OUTPUT_EXISTS')
    require(0 < os.getuid(), 'DEMO_MUST_START_AS_USER')
    installed = '/private/var/root/hostguard-launcher-' + uuid.uuid4().hex + '.py'
    quote = shlex.quote
    invocation = ['/usr/bin/python3', '-I', installed, '--stage', str(stage), '--manifest-sha256', args.stage_manifest,
        '--task', 'g3-executor', '--run-id', plan['runId'], '--authorization-reference', args.authorization_reference,
        '--owner-uid', str(os.getuid()), '--evidence-copy', str(evidence), '--rendezvous', str(rendezvous),
        '--ready-marker', str(ready), '--max-seconds', '1800']
    command = ('umask 077; /bin/cp ' + quote(str(launcher)) + ' ' + quote(installed) +
        ' && /usr/sbin/chown 0:0 ' + quote(installed) + ' && /bin/chmod 500 ' + quote(installed) +
        ' && test "$(/usr/bin/shasum -a 256 ' + quote(installed) + ')" = ' +
        quote(plan['launcherSha256'] + '  ' + installed) + ' && ' + shlex.join(invocation))
    return command, ready


def start_root(plan, args):
    command, ready = root_command(plan, args)
    private_dir(args.rendezvous)
    # osascript 只触发系统密码框；程序不读取、不缓存用户密码。
    expression = 'do shell script ' + json.dumps(command) + ' with administrator privileges'
    log = open(Path(args.rendezvous) / 'root-launch.log', 'xb')
    process = subprocess.Popen(['/usr/bin/osascript', '-e', expression], stdout=log, stderr=subprocess.STDOUT)
    log.close()
    deadline = time.monotonic() + args.root_timeout
    while not ready.exists():
        require(process.poll() is None, 'DEMO_ROOT_LAUNCH_FAILED')
        require(time.monotonic() < deadline, 'DEMO_ROOT_READY_TIMEOUT')
        time.sleep(1)
    return process


def main():
    if '--dry-run' in sys.argv:
        print(json.dumps({'demoOnly': True, 'family': 'brute_force', 'authorizationMinutes': 30, 'steps': STEPS,
                          'writes': False, 'rootStarted': False, 'sourceEligibilityRegistered': False}, ensure_ascii=False, indent=2))
        return
    extra = argparse.ArgumentParser(add_help=False)
    extra.add_argument('--root-plan', required=True)
    root_args, remaining = extra.parse_known_args()
    args = lab_formal.parse_args(remaining)
    require(not args.admission_probe and not args.gate_rehearsal, 'DEMO_REQUIRES_REAL_PF_AUTHORIZATION')
    require(args.final_ref and args.subject_sha256 == R5_SUBJECT, 'DEMO_R5_SUBJECT_REQUIRED')
    root_plan = load(root_args.root_plan)
    # 所有纯参数和输入检查先完成，再显示系统密码框。
    root_command(root_plan, args)
    runner = Demo(args)
    runner.root_dir = args.rendezvous
    try:
        start_root(root_plan, args)
        runner.run()
    finally:
        runner.finish()


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
