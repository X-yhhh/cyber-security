#!/usr/bin/env python3
"""P3-A 已登记视角的可续跑离线编排；已有成功输出只核验，不覆盖。

并发只用于独立 PCAP 视角，失败立即记录并阻止冻结；不启动训练/服务。
"""
import argparse
import concurrent.futures
import json
import subprocess
import sys
from pathlib import Path

from multiclass_common import digest, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2, choices=(1, 2, 3, 4))
    args = parser.parse_args()
    root = args.run.resolve()
    params = json.loads((root / 'inputs/parameters.json').read_text())
    views = [(day, address, False) for day in ('monday', 'tuesday', 'wednesday', 'thursday', 'friday')
             for address in ('192.168.10.50', '192.168.10.3')]
    views += [('thursday', f'192.168.10.{suffix}', False)
              for suffix in (5, 9, 12, 14, 15, 16, 17, 19, 25, 51)]
    websites = json.loads((root / 'inputs/website-plan.json').read_text())['servers']
    views += [(row['day'], row['address'], True) for row in websites]
    command = [sys.executable, str(Path(__file__).with_name('prepare_multiclass.py')),
               '--run', str(root), '--raw', str(args.raw.resolve())]

    def run_view(view):
        day, address, website = view
        name = day + '-' + address.replace('.', '-')
        output = root / 'extract' / name
        if not output.exists():
            subprocess.run(command + ['extract', '--day', day, '--address', address], check=True)
        report = json.loads((output / 'extraction.json').read_text())
        if report['status'] != 'completed' or report['binarySha256'] != digest(root / 'bin/guardextract')['sha256']:
            raise ValueError('提取报告或二进制不符: ' + name)
        if not (output / 'association.json').exists():
            subprocess.run(command + ['join', '--view', name, '--tolerance-us', str(params['firstPacketToleranceUs'])]
                           + (['--web', '--web-cap', str(params['websitePerViewCap'])] if website else []), check=True)
        association = json.loads((output / 'association.json').read_text())
        if association['toleranceUs'] != params['firstPacketToleranceUs']:
            raise ValueError('关联参数漂移: ' + name)
        return {'view': name, 'website': website, 'connections': association['parentConnections'],
                'associationSha256': digest(output / 'association.json')['sha256']}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(run_view, view): view for view in views}
        for future in concurrent.futures.as_completed(pending):
            result = future.result()
            results.append(result)
            print(json.dumps({'completedViews': len(results), 'totalViews': len(views), 'view': result['view']}), flush=True)
    write_json(root / 'evidence/full-extraction.json', {'status': 'completed', 'views': results,
        'parametersSha256': digest(root / 'inputs/parameters.json')['sha256']})


if __name__ == '__main__':
    main()
