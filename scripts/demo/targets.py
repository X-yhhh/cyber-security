#!/usr/bin/env python3
"""一次运行专用 HTTP/FTP/SSH 靶服务；不提供 shell、磁盘访问、FTP 数据通道或端口转发。"""
from __future__ import annotations
import argparse
import asyncio
from pathlib import Path
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.demo.common import address, instant, load, require, safe_main, write


async def http(reader, writer):
    try:
        # 有界头部与连接时间允许演示慢连接，不能把测试进程变成无界资源消耗服务。
        data = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 40)
        require(len(data) <= 8192 and data.startswith(b'GET / HTTP/1.1\r\n'), 'HTTP_REQUEST_REJECTED')
        body = b'hostguard isolated demo\n'
        writer.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        await writer.drain()
    except (Exception, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def ftp(reader, writer):
    """仅实现测试登录握手；任何文件、数据通道或未知命令都拒绝。"""
    writer.write(b'220 Hostguard disposable demo FTP\r\n')
    await writer.drain()
    user = False
    try:
        for _ in range(12):
            line = await asyncio.wait_for(reader.readline(), 3)
            if not line or len(line) > 256:
                break
            command = line.decode('ascii', errors='replace').strip()
            if command == 'USER demo':
                user, answer = True, b'331 Password required\r\n'
            elif command.startswith('PASS '):
                answer = b'230 Demo login only; no files\r\n' if user and command == 'PASS demo-test-only' else b'530 Authentication failed\r\n'
            elif command == 'QUIT':
                writer.write(b'221 Goodbye\r\n')
                await writer.drain()
                break
            else:
                answer = b'502 Not implemented\r\n'
            writer.write(answer)
            await writer.drain()
    except (Exception, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


def ssh_connection(sock, host_key):
    """独立 Paramiko 握手只验证固定测试账号；所有 channel/shell/exec/forward 请求沿用拒绝默认值。"""
    import paramiko
    class Auth(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL if username == 'demo' and password == 'demo-test-only' else paramiko.AUTH_FAILED
        def get_allowed_auths(self, username):
            return 'password'
    with sock:
        sock.settimeout(5)
        with paramiko.Transport(sock) as transport:
            transport.banner_timeout = 3
            transport.auth_timeout = 5
            transport.add_server_key(host_key)
            transport.start_server(server=Auth())
            deadline = time.monotonic() + 8
            while transport.is_active() and time.monotonic() < deadline:
                time.sleep(.05)


async def serve(c, folder):
    bind, peer = address(c['macAddress']), address(c['peerAddress'])
    require(bind != peer and 0 < instant(c['validUntil']) - time.time() <= 1800, 'TARGET_AUTHORIZATION_INVALID')
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    active = set()
    async def guarded(handler, r, w):
        # 即使 ACL 配错也只接受登记对端；健康就绪通过本地文件，不对外额外暴露管理端口。
        who = w.get_extra_info('peername')
        if not who or who[0] != peer or len(active) >= 32:
            w.close()
            await w.wait_closed()
            return
        task = asyncio.current_task()
        active.add(task)
        try:
            await handler(r, w)
        finally:
            active.discard(task)
    servers = []
    listener = accept = pool = None
    in_flight = set()
    try:
        for name, handler in (('http', http), ('ftp', ftp)):
            port = c['ports'][name]
            require(type(port) is int and 1024 <= port <= 65535, 'TARGET_PORT_INVALID')
            servers.append(await asyncio.start_server(lambda r, w, h=handler: guarded(h, r, w), bind, port, limit=8192, backlog=32))
        if c.get('ssh', False):
            import socket
            import paramiko
            from concurrent.futures import ThreadPoolExecutor
            # 靶服务密钥每次运行新建，不复用机器 sshd 身份。
            key = paramiko.RSAKey.generate(2048)
            listener = socket.socket()
            listener.bind((bind, c['ports']['ssh']))
            listener.listen(16)
            listener.setblocking(False)
            pool = ThreadPoolExecutor(max_workers=16)
            in_flight = set()
            async def accept_ssh():
                while not stop.is_set():
                    sock, remote = await loop.sock_accept(listener)
                    if remote[0] != peer or len(in_flight) >= 16:
                        sock.close()
                        continue
                    sock.setblocking(True)
                    f = loop.run_in_executor(pool, ssh_connection, sock, key)
                    in_flight.add(f)
                    f.add_done_callback(in_flight.discard)
            accept = asyncio.create_task(accept_ssh())
        write(folder / 'targets-ready.json', {'pid': __import__('os').getpid(), 'ports': c['ports']})
        try:
            await asyncio.wait_for(stop.wait(), instant(c['validUntil']) - time.time())
        except asyncio.TimeoutError:
            pass
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for task in list(active):
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        if accept:
            accept.cancel()
            await asyncio.gather(accept, return_exceptions=True)
        if listener:
            listener.close()
        await asyncio.gather(*in_flight, return_exceptions=True)
        if pool:
            pool.shutdown(wait=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    args = p.parse_args()
    asyncio.run(serve(load(args.config), Path(args.config).parent))


if __name__ == '__main__':
    raise SystemExit(safe_main(main))
