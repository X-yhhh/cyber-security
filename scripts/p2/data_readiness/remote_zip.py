#!/usr/bin/env python3
"""读取公开 ZIP 目录并取得完整成员；固定 ETag、严格 Range、CRC 和大小校验。

只支持 HTTPS 公开对象；不执行归档内容，不按归档路径写文件。成员不是完整
归档，报告明确区分两者。失败保留 .partial，绝不将其当作有效原件。
--parallel N（N > 1）时先用 N 路 Range 把该成员的本地头与压缩数据取到本地临时文件，
再在本地解压与校验；每一段同样核对 ETag 与 Content-Range。
"""
from concurrent.futures import ThreadPoolExecutor
import threading
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

import requests


class RemoteZip(io.RawIOBase):
    """为 zipfile 提供可定位只读对象；任何对象变更或范围不符立即失败。"""
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
        self.position = 0
        self.cached_at = 0
        self.cached = b''
        self.transferred = 0
        self.local = None

    def seekable(self):
        return True

    def readable(self):
        return True

    def seek(self, offset, whence=0):
        base = (0, self.position, self.size)[whence]
        self.position = base + offset
        if self.position < 0:
            raise ValueError('负位置')
        return self.position

    def tell(self):
        return self.position

    def prefetch(self, start, end, path, workers, chunk=16 * 1024 * 1024):
        """并行取 [start, end) 到本地文件；之后落在该区间内的读取不再访问远端。"""
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        os.ftruncate(fd, end - start)
        sessions = threading.local()

        def fetch(begin):
            last = min(end, begin + chunk) - 1
            for _ in range(5):
                session = getattr(sessions, 'value', None) or requests.Session()
                sessions.value = session
                try:
                    r = session.get(self.url, headers={
                        'Range': f'bytes={begin}-{last}', 'If-Match': self.etag,
                        'Accept-Encoding': 'identity'}, timeout=(20, 120))
                except requests.RequestException:
                    sessions.value = None
                    continue
                if (r.status_code != 206 or r.headers.get('ETag') != self.etag or
                        r.headers.get('Content-Range') != f'bytes {begin}-{last}/{self.size}'):
                    raise ValueError('来源变更或不支持精确分段')
                if len(r.content) == last - begin + 1:
                    os.pwrite(fd, r.content, begin - start)
                    return len(r.content)
            raise ValueError('分段多次失败或截断')

        done = 0
        with ThreadPoolExecutor(workers) as pool:
            for n in pool.map(fetch, range(start, end, chunk)):
                done += n
                if done % (256 * 1024 * 1024) < chunk:
                    print(json.dumps({'compressedBytes': done, 'expectedCompressedBytes': end - start}), flush=True)
        os.fsync(fd)
        self.transferred += done
        self.local = (start, end, fd)

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.position
        size = min(size, self.size - self.position)
        if size <= 0:
            return b''
        if self.local and self.local[0] <= self.position and self.position + size <= self.local[1]:
            result = os.pread(self.local[2], size, self.position - self.local[0])
            self.position += len(result)
            return result
        if not (self.cached_at <= self.position and
                self.position + size <= self.cached_at + len(self.cached)):
            start = self.position
            end = min(self.size, start + max(size, 8 * 1024 * 1024)) - 1
            r = self.session.get(self.url, headers={
                'Range': f'bytes={start}-{end}', 'If-Match': self.etag,
                'Accept-Encoding': 'identity'}, timeout=(20, 90))
            if (r.status_code != 206 or r.headers.get('ETag') != self.etag or
                    r.headers.get('Content-Range') != f'bytes {start}-{end}/{self.size}'):
                raise ValueError('来源变更或不支持精确分段')
            self.cached = r.content
            if len(self.cached) != end - start + 1:
                raise ValueError('分段截断')
            self.cached_at = start
            self.transferred += len(self.cached)
        begin = self.position - self.cached_at
        result = self.cached[begin:begin + size]
        self.position += len(result)
        return result

    def close(self):
        self.session.close()
        super().close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url', required=True)
    p.add_argument('--member')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--parallel', type=int, default=1)
    a = p.parse_args()
    if a.output.exists() or a.output.with_suffix(a.output.suffix + '.partial').exists():
        raise FileExistsError('已有输出或未完成传输必须保留')
    with RemoteZip(a.url) as raw, zipfile.ZipFile(raw) as archive:
        report = dict(version='p2-public-zip-member-v1', sourceUrl=a.url,
                      archiveBytes=raw.size, archiveETag=raw.etag,
                      fullArchiveDownloaded=False, fullArchiveSha256Verified=False)
        if not a.member:
            report['members'] = [dict(name=i.filename, bytes=i.file_size,
                                     compressedBytes=i.compress_size, crc32=f'{i.CRC:08x}',
                                     method=i.compress_type) for i in archive.infolist()]
            with a.output.open('x') as out:
                json.dump(report, out, indent=2)
            print(json.dumps({'members': len(report['members']), 'transferred': raw.transferred}))
            return
        info = archive.getinfo(a.member)
        prefetched = None
        if a.parallel > 1:
            raw.seek(info.header_offset)
            local = raw.read(30)
            if local[:4] != b'PK\x03\x04':
                raise ValueError('本地文件头不符')
            data_start = info.header_offset + 30 + int.from_bytes(local[26:28], 'little') + int.from_bytes(local[28:30], 'little')
            prefetched = a.output.with_suffix(a.output.suffix + '.compressed.partial')
            raw.prefetch(info.header_offset, data_start + info.compress_size, prefetched, a.parallel)
        partial = a.output.with_suffix(a.output.suffix + '.partial')
        count = 0
        digest = hashlib.sha256()
        with archive.open(info) as source, partial.open('xb') as target:
            os.chmod(partial, 0o600)
            while data := source.read(8 * 1024 * 1024):
                target.write(data)
                digest.update(data)
                count += len(data)
                if count % (128 * 1024 * 1024) == 0:
                    print(json.dumps({'uncompressedBytes': count, 'expectedBytes': info.file_size}), flush=True)
            target.flush()
            os.fsync(target.fileno())
        if count != info.file_size:
            raise ValueError('完整成员大小不符')
        # zipfile 在 EOF 校验 CRC32；只在验证成功后公布正式原件。
        partial.rename(a.output)
        if prefetched:
            os.close(raw.local[2])
            raw.local = None
            prefetched.unlink()
        report.update(member=a.member, memberBytes=count, parallelRanges=a.parallel,
                      compressedBytes=info.compress_size, memberCRC32=f'{info.CRC:08x}',
                      memberCRC32Verified=True, memberSha256=digest.hexdigest(),
                      transferredBytes=raw.transferred, status='complete_member')
        with a.output.with_suffix(a.output.suffix + '.source.json').open('x') as out:
            json.dump(report, out, indent=2)
        print(json.dumps({'status': report['status'], 'bytes': count, 'sha256': digest.hexdigest()}))


if __name__ == '__main__':
    main()
