#!/usr/bin/env python3
"""A4 root 运行前的用户态打包：把已提交代码、解释器、依赖与 guardtargets 冻结成带逐文件 SHA 的暂存包。

root 只运行该暂存包的 root 所有副本（见 lab_root_launch.py），因此授权后到执行前用户态进程
改动仓库、venv 或解释器都不会进入 root 进程。本脚本不需要 root，不修改 PF 或系统配置。
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
APP_PATHS = ("executor", "scripts/p1", "scripts/p5", "docs/contracts")
STDLIB_SKIP = {"site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "__pycache__"}


def sha(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_tree(source, target, skip=frozenset()):
    def ignore(directory, names):
        return [n for n in names if n in skip or n == "__pycache__" or n.endswith(".pyc")]
    shutil.copytree(source, target, symlinks=True, ignore=ignore)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True, help="已提交的代码版本；不打包工作区未提交改动")
    parser.add_argument("--guardtargets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--subject-binding", type=Path, help="K6：运行前冻结的 bundleId、完整 subject 和 JCS 摘要")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit("output exists")
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--verify", args.commit + "^{commit}"],
                            capture_output=True, text=True, check=True).stdout.strip()
    output.mkdir(mode=0o700, parents=True)
    stage = output / "stage"
    app = stage / "app"
    app.mkdir(parents=True)
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", commit, *APP_PATHS],
                             capture_output=True, check=True).stdout
    subprocess.run(["/usr/bin/tar", "-x", "-C", str(app)], input=archive, check=True)
    base = Path(sys.base_prefix)
    framework = stage / "python/Python.framework/Versions" / base.name
    (framework / "bin").mkdir(parents=True)
    shutil.copy2(base / "Python", framework / "Python")
    executable = f"python{sys.version_info.major}.{sys.version_info.minor}"
    shutil.copy2(base / "bin" / executable, framework / "bin" / executable)
    copy_tree(base / "lib" / executable, framework / "lib" / executable, STDLIB_SKIP)
    # 框架版 bin/pythonX.Y 是桩程序，会转执行 Resources/Python.app 内的真实解释器。
    copy_tree(base / "Resources" / "Python.app", framework / "Resources" / "Python.app")
    # _ssl 等扩展按安装时绝对路径引用 lib 下的 OpenSSL 等动态库；启动器以 DYLD 路径指向副本。
    for library in sorted((base / "lib").glob("*.dylib")):
        shutil.copy2(library, framework / "lib" / library.name, follow_symlinks=False)
    site = next(Path(p) for p in sys.path if p.endswith("site-packages") and Path(p).is_dir()
                and Path(p).resolve().is_relative_to(Path(sys.prefix).resolve()))
    copy_tree(site, stage / "site")
    shutil.copy2(args.guardtargets, stage / "guardtargets")
    binding=None
    if args.subject_binding:
        from executor.subject_binding import validate
        from executor.common import canonical
        binding=validate(json.loads(args.subject_binding.read_bytes()))
        (stage/'subject-binding.json').write_bytes(canonical(binding))
    files, links = {}, {}
    for path in sorted(stage.rglob("*")):
        relative = str(path.relative_to(stage))
        if path.is_symlink():
            target = os.readlink(path)
            resolved = (path.parent / target).resolve()
            if os.path.isabs(target) or not resolved.is_relative_to(stage.resolve()):
                raise SystemExit("symlink escapes stage: " + relative)
            links[relative] = target
        elif path.is_file():
            files[relative] = {"sha256": sha(path), "executable": os.access(path, os.X_OK)}
    manifest = {"kind": "hostguard-lab-root-stage/1", "commit": commit, "appPaths": list(APP_PATHS),
                "python": f"python/Python.framework/Versions/{base.name}/bin/{executable}",
                "pythonVersion": sys.version.split()[0], "files": files, "symlinks": links,
                "dyldLibraryPath": f"python/Python.framework/Versions/{base.name}/lib",
                "dyldFrameworkPath": "python"}
    if binding is not None:manifest['subjectBinding']=binding
    path = output / "manifest.json"
    path.write_text(json.dumps(manifest, sort_keys=True, indent=1) + "\n")
    print(json.dumps({"commit": commit, "files": len(files), "manifestSha256": sha(path)}))


if __name__ == "__main__":
    main()
