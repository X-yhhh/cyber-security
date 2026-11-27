"""BE-30 机器证书到期检查与轮换：只用临时目录，不触碰部署目录或系统服务。"""
from datetime import datetime, timedelta, timezone
import json
import os
import pytest
from executor import pki
from executor.common import Rejected
from scripts.p8 import machine_tls


def deploy(tmp_path, *, leaf_days=30, demo_ca=True):
    """仿照真实部署目录：tls/、ipc/、带演示 CA 的信任包、钉住指纹的 targets.json。"""
    config = tmp_path / 'config'
    config.mkdir(mode=0o700)
    fingerprints = {name: pki.create(config / name, leaf_days=leaf_days) for name in ('tls', 'ipc')}
    demo = tmp_path / 'demo'
    pki.create(demo)
    bundle = (config / 'ipc/ca.pem').read_bytes() + ((demo / 'ca.pem').read_bytes() if demo_ca else b'')
    fd = os.open(config / 'ipc' / machine_tls.BUNDLE, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, bundle); os.close(fd)
    targets = {'listen': '127.0.0.1:18443', 'caFile': str(config / 'ipc/ca.pem'),
               'scope': {'AssetID': 5, 'CollectorCertSHA256': fingerprints['ipc']['collector'],
                         'ExecutorCertSHA256': fingerprints['ipc']['executor']}}
    fd = os.open(config / 'targets.json', os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, json.dumps(targets, indent=2).encode()); os.close(fd)
    return config, fingerprints, (demo / 'ca.pem').read_bytes()


def test_validity_is_configurable_and_bounded(tmp_path):
    assert pki.validity(180, 730) == (180, 730)
    for leaf, ca in ((0, 365), (365, 365), (400, 365), (30, 4000), (True, 365)):
        with pytest.raises(Rejected):
            pki.validity(leaf, ca)
    pki.create(tmp_path / 'set', leaf_days=180, ca_days=730)
    certificate = machine_tls.certificates(tmp_path / 'set/server.pem')[0]
    days = (certificate.not_valid_after_utc - datetime.now(timezone.utc)).days
    assert 178 <= days <= 180
    # 默认值保持原 30 天，兼容 lab/演示调用方。
    pki.create(tmp_path / 'default')
    assert (machine_tls.certificates(tmp_path / 'default/collector.pem')[0].not_valid_after_utc
            - datetime.now(timezone.utc)).days in (29, 30)


def test_assess_warns_before_expiry_and_flags_unreadable(tmp_path):
    config, _, _ = deploy(tmp_path)
    value, ok = machine_tls.assess(config, warn_days=7)
    assert ok and value['state'] == 'ok' and 29 <= value['minDaysRemaining'] <= 30
    assert {item['file'] for item in value['items']} >= {'tls/server.pem', 'ipc/collector.pem', 'ipc/' + machine_tls.BUNDLE}
    soon = datetime.now(timezone.utc) + timedelta(days=25)
    value, ok = machine_tls.assess(config, warn_days=7, now=soon)
    assert not ok and value['state'] == 'expiring'
    value, ok = machine_tls.assess(config, warn_days=7, now=soon + timedelta(days=10))
    assert not ok and value['state'] == 'expired'
    (config / 'tls/server.pem').write_bytes(b'not a certificate')
    value, ok = machine_tls.assess(config)
    assert not ok and value['state'] == 'unknown' and value['unreadable'] == ['tls/server.pem']


def test_rotate_replaces_both_sets_and_keeps_pins_and_demo_ca(tmp_path):
    config, old, demo_ca = deploy(tmp_path)
    targets_before = (config / 'targets.json').read_text()
    result = machine_tls.rotate(config, leaf_days=180, ca_days=730, stamp='t1')
    new = result['newFingerprints']
    assert new['ipc']['collector'] != old['ipc']['collector'] and 178 <= result['minDaysRemaining'] <= 180
    for name in ('tls', 'ipc'):
        assert json.loads((config / name / 'fingerprints.json').read_bytes()) == new[name]
        backup = config / (name + '.bak-t1')
        assert json.loads((backup / 'fingerprints.json').read_bytes()) == old[name]
        assert (config / name / 'server.key').stat().st_mode & 0o777 == 0o600
    scope = json.loads((config / 'targets.json').read_text())['scope']
    assert scope['CollectorCertSHA256'] == new['ipc']['collector'] and scope['ExecutorCertSHA256'] == new['ipc']['executor']
    # 指纹之外的字节不变。
    expected = targets_before.replace(old['ipc']['collector'], new['ipc']['collector']).replace(
        old['ipc']['executor'], new['ipc']['executor'])
    assert (config / 'targets.json').read_text() == expected
    assert (config / 'targets.json.bak-t1').read_text() == targets_before
    blocks = machine_tls.PEM_BLOCK.findall((config / 'ipc' / machine_tls.BUNDLE).read_bytes())
    assert blocks[0].strip() == (config / 'ipc/ca.pem').read_bytes().strip() and blocks[1].strip() == demo_ca.strip()
    assert not any(path.name.startswith('.rotate-') for path in config.iterdir())


def test_dry_run_writes_nothing(tmp_path):
    config, old, _ = deploy(tmp_path)
    before = {path: path.read_bytes() for path in config.rglob('*') if path.is_file()}
    result = machine_tls.rotate(config, stamp='dry', dry_run=True)
    assert result['dryRun'] and result['backups'] == {}
    assert {path: path.read_bytes() for path in config.rglob('*') if path.is_file()} == before


@pytest.mark.parametrize('damage,code', [
    ('fingerprint', 'FINGERPRINT_RECORD_MISMATCH'),
    ('targets', 'TARGETS_FINGERPRINT_MISMATCH'),
    ('bundle', 'TRUST_BUNDLE_LAYOUT_UNEXPECTED'),
    ('permission', 'PRIVATE_PERMISSION_REQUIRED'),
    ('backup', 'BACKUP_ALREADY_EXISTS'),
])
def test_rotate_refuses_unknown_layouts_without_writing(tmp_path, damage, code):
    config, old, _ = deploy(tmp_path)
    if damage == 'fingerprint':
        (config / 'tls/fingerprints.json').write_text(json.dumps({**old['tls'], 'server': '0' * 64}))
    elif damage == 'targets':
        text = (config / 'targets.json').read_text().replace(old['ipc']['executor'], 'f' * 64)
        (config / 'targets.json').write_text(text)
    elif damage == 'bundle':
        (config / 'ipc' / machine_tls.BUNDLE).write_bytes((tmp_path / 'demo/ca.pem').read_bytes())
    elif damage == 'permission':
        os.chmod(config / 'ipc/collector.key', 0o644)
    elif damage == 'backup':
        (config / 'tls.bak-x').mkdir()
    before = {path: path.read_bytes() for path in (config / 'tls').iterdir()}
    with pytest.raises(ValueError, match=code):
        machine_tls.rotate(config, stamp='x')
    assert {path: path.read_bytes() for path in (config / 'tls').iterdir()} == before
    assert not any(path.name.startswith('.rotate-') for path in config.iterdir())


def test_rotate_rolls_back_when_install_fails(tmp_path, monkeypatch):
    config, old, _ = deploy(tmp_path)
    before = {path: path.read_bytes() for path in config.rglob('*') if path.is_file()}
    real = os.replace
    calls = []
    def flaky(source, target):
        calls.append(target)
        if len(calls) == 5:
            raise OSError('disk full')
        return real(source, target)
    monkeypatch.setattr(machine_tls.os, 'replace', flaky)
    with pytest.raises(OSError):
        machine_tls.rotate(config, stamp='rb')
    after = {path: path.read_bytes() for path in config.rglob('*')
             if path.is_file() and '.bak-rb' not in str(path)}
    assert after == before


def test_restart_order_and_pf_mode_is_manual():
    seen = []
    result = machine_tls.restart(execute=lambda argv: seen.append(argv[-1].split('.')[-1]) or 0)
    assert seen == ['targets', 'backend', 'recovery', 'executor'] and result['manual'] == []
    with pytest.raises(ValueError, match='RESTART_FAILED:backend'):
        machine_tls.restart(execute=lambda argv: 1 if argv[-1].endswith('backend') else 0)
    manual = machine_tls.restart(mode='pf')
    assert manual['restarted'] == [] and any(line.startswith('sudo ') and line.endswith('executor') for line in manual['manual'])
