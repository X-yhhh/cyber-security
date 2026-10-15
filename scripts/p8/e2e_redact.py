"""脱敏本次 runner 生成的文本和 Playwright trace，不改 JSON/ZIP 格式。

密码、机器凭据、会话和 CSRF 由私有注册表提供；额外按字段清理认证头。
禁用截图/视频，避免位图中的一次性凭据无法可靠脱敏。原件仅存在于 0700 运行目录。
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import zipfile

REDACTED = '[REDACTED]'
SENSITIVE = {'password', 'credential', 'token', 'cookie', 'set-cookie', 'authorization',
             'x-csrf-token', 'x-xsrf-token', 'csrf', 'secret', 'initialpassword'}


def scrub_text(text, secrets):
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return re.sub(r'(?i)Bearer [A-Za-z0-9._~+/=-]+', 'Bearer ' + REDACTED, text)


def scrub_value(value, secrets):
    if isinstance(value, dict):
        if str(value.get('name', '')).lower() in SENSITIVE and 'value' in value:
            return {key: REDACTED if key == 'value' else scrub_value(item, secrets) for key, item in value.items()}
        return {key: REDACTED if key.lower() in SENSITIVE else scrub_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_value(item, secrets) for item in value]
    if isinstance(value, str):
        result = scrub_text(value, secrets)
        # network postData.text / response resources 可再包含一层 JSON。
        if result.startswith(('{', '[')):
            try:
                return json.dumps(scrub_value(json.loads(result), secrets), ensure_ascii=False)
            except (ValueError, RecursionError):
                pass
        return result
    return value


def scrub_bytes(content, secrets):
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        return content
    lines = []
    for line in text.splitlines(keepends=True):
        try:
            lines.append(json.dumps(scrub_value(json.loads(line), secrets), ensure_ascii=False) + ('\n' if line.endswith('\n') else ''))
        except ValueError:
            lines.append(scrub_text(line, secrets))
    return ''.join(lines).encode('utf-8')


def redact_artifacts(work: Path):
    secrets = []
    registry = work / 'private/secrets.json'
    if registry.is_file():
        secrets.extend(json.loads(registry.read_text()))
    extra = work / 'private/browser-secrets.jsonl'
    if extra.is_file():
        secrets.extend(json.loads(line) for line in extra.read_text().splitlines() if line)
    secrets = sorted({value for value in secrets if isinstance(value, str) and len(value) >= 6}, key=len, reverse=True)
    for path in work.rglob('*'):
        if not path.is_file() or work / 'private' in path.parents:
            continue
        if path.suffix == '.zip':
            pending = path.with_suffix('.redacted.zip')
            with zipfile.ZipFile(path) as source, zipfile.ZipFile(pending, 'w', zipfile.ZIP_DEFLATED) as target:
                for entry in source.infolist():
                    content = scrub_bytes(source.read(entry), secrets)
                    target.writestr(entry, content)
            pending.replace(path)
        else:
            path.write_bytes(scrub_bytes(path.read_bytes(), secrets))
