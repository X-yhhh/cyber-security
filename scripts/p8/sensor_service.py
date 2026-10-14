#!/usr/bin/env python3
"""一次授权采集入口：每次新 boot/spool、最长 30 分钟；正常退出不会由 launchd 自动续采。"""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.p8.toolkit import absolute, load, private_dir, require, safe_main, write


def prepare(root, release):
    root, release = absolute(root), absolute(release)
    c = load(root / 'config/sensor.json')
    remaining = int((datetime.fromisoformat(c['authorizedUntil'].replace('Z', '+00:00')) - datetime.now(timezone.utc)).total_seconds())
    require(remaining >= 1, 'AUTHORIZATION_EXPIRED')
    require(c['environment'] == 'authorized' and c['captureScope'] == 'all_inbound_tcp' and c['allowedInterfaces'] == [c['interface']], 'CAPTURE_SCOPE_INVALID')
    boot = str(uuid.uuid4())
    directory = private_dir(root / 'ledger/sensor' / boot)
    c['bootId'] = boot
    c['upload']['spoolDir'] = str(directory / 'spool')
    write(directory / 'config.json', c)
    return [str(release / 'guardlive'), '-config', str(directory / 'config.json'), '-out', str(directory / 'observations.jsonl'),
            '-trace', str(directory / 'trace.jsonl'), '-report', str(directory / 'report.json'), '-duration', str(min(1800, remaining)) + 's']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', required=True)
    p.add_argument('--release', required=True)
    args = p.parse_args()
    command = prepare(args.root, args.release)
    os.execv(command[0], command)


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
