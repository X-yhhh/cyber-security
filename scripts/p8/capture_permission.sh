#!/bin/sh
# root helper 只为登记的普通用户临时开放一个 BPF 设备；不执行用户命令，不读取任何网络内容。
# PID 文件由持有传感器唯一锁的后端原子写入；后端退出或身份不符后恢复 root:wheel 0600。
set -eu
capture_uid=$1
capture_pid_file=$2
case "$capture_uid" in ''|*[!0-9]*) exit 2;; esac
[ "$capture_uid" -ge 501 ] || exit 2
revoke() {
    if [ -c /dev/bpf0 ]; then
        /usr/sbin/chown root:wheel /dev/bpf0
        /bin/chmod 600 /dev/bpf0
    fi
}
trap 'revoke; exit 0' INT TERM
trap revoke EXIT
revoke
while :; do
    capture_pid=
    if [ -f "$capture_pid_file" ] && [ ! -L "$capture_pid_file" ] &&
        [ "$(/usr/bin/stat -f %u "$capture_pid_file")" = "$capture_uid" ]; then
        IFS= read -r capture_pid < "$capture_pid_file" || capture_pid=
    fi
    case "$capture_pid" in ''|*[!0-9]*) capture_pid=0;; esac
    capture_owner=$(/bin/ps -p "$capture_pid" -o uid= 2>/dev/null | /usr/bin/tr -d ' ' || true)
    capture_program=$(/bin/ps -p "$capture_pid" -o comm= 2>/dev/null || true)
    capture_arguments=$(/bin/ps -p "$capture_pid" -o args= 2>/dev/null || true)
    if [ "$capture_pid" -gt 1 ] && [ "$capture_owner" = "$capture_uid" ]; then
        case "$capture_program:$capture_arguments" in
            */bin/java:*cyber-security*|*/bin/java:*com.xyh.cybersecurity.CyberSecurityApplication*)
                if [ -c /dev/bpf0 ]; then
                    /usr/sbin/chown "$capture_uid":wheel /dev/bpf0
                    /bin/chmod 600 /dev/bpf0
                fi;;
            *) revoke;;
        esac
    else
        revoke
    fi
    /bin/sleep 1
done
