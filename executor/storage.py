"""SQLite FULL 持久账本与跨进程锁；OS 动作之前提交意图，之后才确认实态。"""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import time

from .common import canonical, parse, require


class Store:
    def __init__(self, directory):
        self.root = Path(directory)
        require(self.root.is_absolute() and not self.root.is_symlink(), "STATE_DIRECTORY_INVALID")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            require(self.root.stat().st_uid == os.geteuid() and self.root.stat().st_mode & 0o077 == 0,
                    "STATE_DIRECTORY_PERMISSIONS_INVALID")
        self.path = self.root / "ledger.sqlite3"
        require(not self.path.is_symlink(), "STATE_DIRECTORY_INVALID")
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS commands (
                  id TEXT PRIMARY KEY, action TEXT NOT NULL UNIQUE, idem TEXT NOT NULL UNIQUE,
                  hash TEXT NOT NULL, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS revocations (id TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, operation TEXT NOT NULL, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, at REAL NOT NULL,
                  event TEXT NOT NULL, subject TEXT, detail TEXT NOT NULL);
            """)
        if os.name != "nt":
            self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def lock(self, name="actions", blocking=True):
        """锁覆盖本命名空间的短 OS 事务；进程崩溃由内核释放。"""
        path = self.root / (name + ".lock")
        require(not path.is_symlink(), "STATE_DIRECTORY_INVALID")
        with open(path, "a+b") as stream:
            if os.name == "nt":
                import msvcrt
                stream.seek(0)
                if stream.read(1) == b"":
                    stream.write(b"0"); stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            try:
                yield
            finally:
                if os.name == "nt":
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def get(self, key, default=None):
        with self.db() as db:
            row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return parse(row[0]) if row else default

    def set(self, key, value):
        with self.db() as db:
            db.execute("INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, canonical(value).decode()))

    def commands(self):
        with self.db() as db:
            return [parse(row[0]) for row in db.execute("SELECT value FROM commands ORDER BY rowid")]

    def command(self, command):
        return next((row for row in self.commands() if row["payload"]["commandId"] == command), None)

    def save(self, row):
        p = row["payload"]
        with self.db() as db:
            db.execute("INSERT INTO commands VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                       (p["commandId"], p["actionId"], p["idempotencyKey"], row["hash"], canonical(row).decode()))

    def revocations(self):
        with self.db() as db:
            return [parse(row[0]) for row in db.execute("SELECT value FROM revocations ORDER BY rowid")]

    def revoke(self, value):
        with self.db() as db:
            db.execute("INSERT INTO revocations VALUES (?,?) ON CONFLICT(id) DO NOTHING",
                       (value["revocationId"], canonical(value).decode()))

    def queue(self, operation, key, value):
        with self.db() as db:
            db.execute("INSERT INTO outbox VALUES (?,?,?) ON CONFLICT(id) DO NOTHING",
                       (key, operation, canonical(value).decode()))

    def pending(self):
        with self.db() as db:
            return [(key, operation, parse(value)) for key, operation, value in
                    db.execute("SELECT id,operation,value FROM outbox ORDER BY rowid LIMIT 100")]

    def ack(self, key):
        with self.db() as db:
            db.execute("DELETE FROM outbox WHERE id=?", (key,))

    def audit(self, event, subject=None, **detail):
        with self.db() as db:
            db.execute("INSERT INTO audit(at,event,subject,detail) VALUES (?,?,?,?)",
                       (time.time(), event, subject, canonical(detail).decode()))
