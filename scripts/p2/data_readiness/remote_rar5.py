#!/usr/bin/env python3
"""从公开 RAR5 归档中只取一个完整成员；固定 ETag、精确 Range、大小与 CRC32 校验。

只支持 HTTPS 公开对象、非固实、非分卷、未加密的 RAR5。按 Range 逐个读取文件头定位
成员，只下载该成员的文件头与压缩数据，拼成只含该成员的最小 RAR5 归档，交给本机
bsdtar（libarchive）解压，再按文件头中的原始大小与 CRC32 核对。成员不是完整归档，
报告明确区分两者。失败保留 .partial，绝不将其当作有效原件。
--parallel N 时用 N 路 Range 并行取压缩数据，每一段同样核对 ETag 与 Content-Range。
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zlib

import requests

SIGNATURE = b'Rar!\x1a\x07\x01\x00'
BSDTAR = '/usr/bin/bsdtar'


def vint(buf, i):
    value = shift = 0
    while True:
        byte = buf[i]
        i += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, i


def block(payload):
    """payload 从“头类型”开始；返回带 CRC32 与长度字段的完整头。"""
    assert len(payload) < 0x80
    body = bytes([len(payload)]) + payload
    return zlib.crc32(body).to_bytes(4, 'little') + body


class Remote:
    def __init__(self, url):
        if not url.startswith('https://'):
            raise ValueError('仅接受 HTTPS 公开来源')
        self.url = url
        self.session = requests.Session()
        r = self.session.head(url, allow_redirects=True, timeout=(20, 60))
        r.raise_for_status()
        self.size = int(r.headers['Content-Length'])
        self.etag = r.headers.get('ETag')
        if not self.etag or self.etag.startswith('W/'):
            raise ValueError('来源未提供强 ETag，不能保证跨请求一致性')
        self.transferred = 0
        self.sessions = threading.local()
        self.lock = threading.Lock()

    def read(self, start, length, retries=5):
        end = min(self.size, start + length) - 1
        for _ in range(retries):
            session = getattr(self.sessions, 'value', None) or requests.Session()
            self.sessions.value = session
            try:
                return self._get(session, start, end)
            except requests.RequestException:
                self.sessions.value = None
        raise ValueError('分段多次失败')

    def _get(self, session, start, end):
        r = session.get(self.url, headers={
            'Range': f'bytes={start}-{end}', 'If-Match': self.etag,
            'Accept-Encoding': 'identity'}, timeout=(20, 120))
        if (r.status_code != 206 or r.headers.get('ETag') != self.etag or
                r.headers.get('Content-Range') != f'bytes {start}-{end}/{self.size}'):
            raise ValueError('来源变更或不支持精确分段')
        if len(r.content) != end - start + 1:
            raise requests.RequestException('分段截断')
        with self.lock:
            self.transferred += len(r.content)
        return r.content


def locate(remote, member):
    if remote.read(0, 8) != SIGNATURE:
        raise ValueError('不是 RAR5 归档')
    pos = 8
    while pos < remote.size:
        buf = remote.read(pos, 512)
        i = 4
        hsize, i = vint(buf, i)
        hstart = i
        if hstart + hsize > len(buf):
            buf = remote.read(pos, hstart + hsize)
        htype, i = vint(buf, i)
        hflags, i = vint(buf, i)
        extra = data = 0
        if hflags & 0x01:
            extra, i = vint(buf, i)
        if hflags & 0x02:
            data, i = vint(buf, i)
        header_end = pos + hstart + hsize
        if zlib.crc32(buf[4:hstart + hsize]) != int.from_bytes(buf[:4], 'little'):
            raise ValueError('文件头 CRC 不符')
        if htype == 1:
            flags, _ = vint(buf, i)
            if flags & 0x01 or flags & 0x04:
                raise ValueError('不支持分卷或固实归档')
        elif htype == 4:
            raise ValueError('不支持加密归档')
        elif htype == 2:
            if hflags & 0x18:
                raise ValueError('不支持跨卷成员')
            fflags, i = vint(buf, i)
            unpacked, i = vint(buf, i)
            _, i = vint(buf, i)
            if fflags & 0x02:
                i += 4
            crc = None
            if fflags & 0x04:
                crc = int.from_bytes(buf[i:i + 4], 'little')
                i += 4
            comp, i = vint(buf, i)
            _, i = vint(buf, i)
            name_len, i = vint(buf, i)
            name = buf[i:i + name_len].decode('utf-8')
            i += name_len
            if name == member:
                if comp & 0x40:
                    raise ValueError('成员为固实压缩')
                extra_end = hstart + hsize
                j = extra_end - extra
                while j < extra_end:
                    rsize, k = vint(buf, j)
                    rtype, _ = vint(buf, k)
                    if rtype == 0x01:
                        raise ValueError('成员已加密')
                    j = k + rsize
                return dict(headerBytes=bytes(buf[:hstart + hsize]), dataOffset=header_end,
                            packedBytes=data, unpackedBytes=unpacked, crc32=crc,
                            method=(comp >> 7) & 0x07)
        elif htype == 5:
            break
        pos = header_end + data
    raise KeyError(f'归档中没有成员 {member}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', required=True)
    p.add_argument('--member', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--parallel', type=int, default=1)
    a = p.parse_args()
    partial = a.output.with_suffix(a.output.suffix + '.partial')
    mini = a.output.with_suffix(a.output.suffix + '.member.rar.partial')
    for path in (a.output, partial, mini):
        if path.exists():
            raise FileExistsError('已有输出或未完成传输必须保留')
    remote = Remote(a.url)
    info = locate(remote, a.member)
    if info['crc32'] is None:
        raise ValueError('成员文件头没有 CRC32，无法校验')
    with mini.open('xb') as out:
        os.chmod(mini, 0o600)
        prefix = SIGNATURE + block(b'\x01\x00\x00') + info['headerBytes']
        out.write(prefix)
        out.flush()
        start, end = info['dataOffset'], info['dataOffset'] + info['packedBytes']
        chunk = 16 * 1024 * 1024

        def fetch(begin):
            data = remote.read(begin, min(chunk, end - begin))
            os.pwrite(out.fileno(), data, len(prefix) + begin - start)
            return len(data)

        done = 0
        with ThreadPoolExecutor(max(1, a.parallel)) as pool:
            for n in pool.map(fetch, range(start, end, chunk)):
                done += n
                if done % (256 * 1024 * 1024) < chunk or done == info['packedBytes']:
                    print(json.dumps({'packedBytes': done, 'expectedPackedBytes': info['packedBytes']}), flush=True)
        out.seek(len(prefix) + info['packedBytes'])
        out.write(block(b'\x05\x00\x00'))
        out.flush()
        os.fsync(out.fileno())
    digest = hashlib.sha256()
    crc = count = 0
    with partial.open('xb') as target:
        os.chmod(partial, 0o600)
        proc = subprocess.Popen([BSDTAR, '-xOf', str(mini), a.member], stdout=subprocess.PIPE)
        while data := proc.stdout.read(8 * 1024 * 1024):
            target.write(data)
            digest.update(data)
            crc = zlib.crc32(data, crc)
            count += len(data)
        if proc.wait() != 0:
            raise ValueError(f'bsdtar 退出码 {proc.returncode}')
        target.flush()
        os.fsync(target.fileno())
    if count != info['unpackedBytes'] or crc != info['crc32']:
        raise ValueError('完整成员大小或 CRC32 不符')
    partial.rename(a.output)
    mini.unlink()
    version = subprocess.run([BSDTAR, '--version'], capture_output=True, text=True).stdout.strip()
    report = dict(version='p2-public-rar5-member-v1', sourceUrl=a.url,
                  archiveBytes=remote.size, archiveETag=remote.etag,
                  fullArchiveDownloaded=False, fullArchiveSha256Verified=False,
                  member=a.member, memberBytes=count, packedBytes=info['packedBytes'],
                  compressionMethod=info['method'], memberCRC32=f"{info['crc32']:08x}",
                  memberCRC32Verified=True, memberSha256=digest.hexdigest(),
                  transferredBytes=remote.transferred, parallelRanges=a.parallel, extractor=version,
                  status='complete_member')
    with a.output.with_suffix(a.output.suffix + '.source.json').open('x') as out:
        json.dump(report, out, indent=2)
    print(json.dumps({'status': report['status'], 'bytes': count, 'sha256': report['memberSha256']}))


if __name__ == '__main__':
    main()
