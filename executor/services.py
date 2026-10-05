"""生成可审查的本机启动配置；不自动安装、提权、启用防火墙或重启主机。"""
from pathlib import Path
import plistlib

from .common import require, write_new


def launchd(directory, python, source, config, target_binary, target_config):
    paths = [Path(p) for p in (directory, python, source, config, target_binary, target_config)]
    require(all(p.is_absolute() for p in paths), "ABSOLUTE_PATH_REQUIRED")
    output, interpreter, root, configuration, targets, target_configuration = paths
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    entries = {"executor": [str(interpreter), "-m", "executor", "run", "--config", str(configuration)],
               "recovery": [str(interpreter), "-m", "executor", "recover", "--config", str(configuration)],
               "targets": [str(targets), "-config", str(target_configuration)]}
    for role, args in entries.items():
        definition = {"Label": "com.xyh.hostguard." + role, "ProgramArguments": args,
                      "WorkingDirectory": str(root), "RunAtLoad": True, "KeepAlive": True,
                      "ThrottleInterval": 2, "ExitTimeOut": 10, "Umask": 0o077,
                      "StandardOutPath": str(output / (role + ".stdout.log")),
                      "StandardErrorPath": str(output / (role + ".stderr.log"))}
        write_new(output / ("com.xyh.hostguard." + role + ".plist"), plistlib.dumps(definition))
