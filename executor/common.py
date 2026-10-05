"""规范化、受控文件和稳定错误；不在错误中返回地址、凭据或原始命令。"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import rfc8785


class Rejected(Exception):
    """code 可进入脱敏回执；底层异常只作为本机诊断链保留。"""


def require(condition, code):
    if not condition:
        raise Rejected(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: require(False, "INVALID_JSON_NUMBER"))
    except (ValueError, UnicodeError) as exc:
        raise Rejected("INVALID_JSON") from exc


def canonical(value):
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError) as exc:
        raise Rejected("INVALID_CANONICAL_JSON") from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def instant(value):
    try:
        require(isinstance(value, str) and value.endswith("Z"), "INVALID_TIMESTAMP")
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError) as exc:
        raise Rejected("INVALID_TIMESTAMP") from exc


def stamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def ident():
    return str(uuid.uuid4())


def private_file(path):
    """仅接受本机绝对普通文件；Windows 的目录 ACL 由安装身份预配。"""
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "PRIVATE_FILE_REQUIRED")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), "PRIVATE_FILE_REQUIRED")
    if os.name != "nt":
        require(info.st_uid in (0, os.geteuid()) and info.st_mode & 0o077 == 0,
                "PRIVATE_FILE_PERMISSIONS_INVALID")
    return path


def read_private(path):
    return parse(private_file(path).read_bytes())


def write_new(path, data):
    """独占创建；不覆盖用户已有密钥、配置和账本。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def public_der(key):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(key.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
