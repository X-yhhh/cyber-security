"""E3 外部执行器的用户态中继：JUnit 仍按标准输入/输出协议通信，执行端改在 root 暂存副本中运行。

创建两个仅属主可读写的命名管道并在两端间逐行转发；不解析、不修改协议内容。打开顺序与
joint_executor.open_pipes 一致（先读执行端输出，再写其输入），避免互等。root 执行端在限定时间内
未连接则退出，避免 JUnit 无限挂起。最后一条应答含 "cleaned": true 且无 error 时以 0 退出。
"""
import argparse
import json
import os
from pathlib import Path
import sys
import threading

FIFOS = ("from-executor.fifo", "to-executor.fifo")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--connect-timeout", type=float, default=900)
    args = parser.parse_args()
    for name in FIFOS:
        os.mkfifo(args.directory / name, 0o600)
    connected = threading.Event()

    def watchdog():
        if not connected.wait(args.connect_timeout):
            sys.stderr.write("LAB_EXTERNAL_EXECUTOR_NOT_CONNECTED\n")
            sys.stderr.flush()
            os._exit(3)
    threading.Thread(target=watchdog, daemon=True).start()
    source = open(args.directory / FIFOS[0], "r", encoding="utf-8")
    sink = open(args.directory / FIFOS[1], "w", encoding="utf-8")
    connected.set()

    def forward():
        try:
            for line in sys.stdin:
                sink.write(line)
                sink.flush()
        except (BrokenPipeError, ValueError):
            pass
        finally:
            try:
                sink.close()
            except BrokenPipeError:
                pass
    threading.Thread(target=forward, daemon=True).start()
    last = None
    for line in source:
        sys.stdout.write(line)
        sys.stdout.flush()
        last = line
    try:
        final = json.loads(last) if last else {}
    except ValueError:
        final = {}
    raise SystemExit(0 if final.get("cleaned") is True and "error" not in final else 1)


if __name__ == "__main__":
    main()
