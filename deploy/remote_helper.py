#!/usr/bin/env python3
"""Remote server helper: SSH through HTTP CONNECT proxy."""
import sys
import socket
import os
import stat
import paramiko

HOST = "175.178.103.242"
PORT = 22
USER = "root"
PASSWORD = "Jq399$FQJF@*&^"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 18080


def make_proxy_socket(target_host, target_port, timeout=30):
    """Create a socket tunneled through the HTTP CONNECT proxy."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((PROXY_HOST, PROXY_PORT))
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    sock.send(req.encode())
    # Read response
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    if b" 200 " not in resp.split(b"\r\n")[0]:
        raise RuntimeError(f"Proxy CONNECT failed: {resp.split(b'\r\n')[0].decode()}")
    return sock


def connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sock = make_proxy_socket(HOST, PORT)
    client.connect(HOST, PORT, username=USER, password=PASSWORD, sock=sock, timeout=30, look_for_keys=False, allow_agent=False)
    return client


def run_cmd(client, cmd, timeout=120):
    """Run a command and return (exit_code, stdout, stderr)."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=False)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def sftp_mkdirs(sftp, remote_dir):
    """Make remote dir tree like mkdir -p."""
    parts = remote_dir.strip("/").split("/")
    cur = ""
    for p in parts:
        cur = cur + "/" + p
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def upload_dir(local_dir, remote_dir, sftp):
    """Upload a directory recursively via SFTP."""
    sftp_mkdirs(sftp, remote_dir)
    count = 0
    for root, dirs, files in os.walk(local_dir):
        rel = os.path.relpath(root, local_dir)
        rdir = remote_dir if rel == "." else remote_dir + "/" + rel.replace(os.sep, "/")
        try:
            sftp.stat(rdir)
        except FileNotFoundError:
            sftp.mkdir(rdir)
        for f in files:
            local_path = os.path.join(root, f)
            remote_path = rdir + "/" + f
            sftp.put(local_path, remote_path)
            count += 1
            print(f"  [upload] {remote_path}")
    return count


def main():
    if len(sys.argv) < 2:
        print("Usage: remote_helper.py <test|upload|exec 'cmd'|start>")
        return 1
    action = sys.argv[1]
    try:
        client = connect()
        print(f"[OK] Connected to {USER}@{HOST}")
    except Exception as e:
        print(f"[ERROR] Connection failed: {type(e).__name__}: {e}")
        return 1

    if action == "test":
        code, out, err = run_cmd(client, "uname -a; echo '---'; cat /etc/os-release 2>/dev/null | head -3; echo '---'; which python3; python3 --version 2>&1; echo '---'; which pip3 pip 2>&1; echo '---'; df -h / | tail -2")
        print("=== system info ===")
        print(out)
        if err.strip():
            print("STDERR:", err)

    elif action == "exec":
        if len(sys.argv) < 3:
            print("Usage: remote_helper.py exec 'cmd'")
            return 1
        cmd = sys.argv[2]
        code, out, err = run_cmd(client, cmd)
        print(out, end="")
        if err.strip():
            print("STDERR:", err, end="")
        print(f"\n[exit={code}]")

    elif action == "upload":
        local_dir = sys.argv[2] if len(sys.argv) > 2 else "/workspace/ip-system"
        remote_dir = sys.argv[3] if len(sys.argv) > 3 else "/root/ip-system"
        sftp = client.open_sftp()
        # Remove old deploy dir contents
        try:
            run_cmd(client, f"rm -rf {remote_dir}")
        except Exception:
            pass
        n = upload_dir(local_dir, remote_dir, sftp)
        print(f"[OK] Uploaded {n} files to {remote_dir}")
        sftp.close()

    elif action == "start":
        remote_dir = sys.argv[2] if len(sys.argv) > 2 else "/root/ip-system"
        # Install deps and start service
        cmds = [
            f"cd {remote_dir}/backend && python3 -m pip install --quiet --break-system-packages fastapi uvicorn openpyxl python-multipart 2>&1 | tail -3",
            f"cd {remote_dir} && bash -c 'pkill -f \"uvicorn main:app\" 2>/dev/null; sleep 1; nohup python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir {remote_dir}/backend > {remote_dir}/server.log 2>&1 & sleep 3; echo started; cat {remote_dir}/server.log | tail -10'",
        ]
        for c in cmds:
            print(f">>> {c[:120]}")
            code, out, err = run_cmd(client, c, timeout=180)
            print(out, end="")
            if err.strip():
                print("STDERR:", err, end="")

    else:
        print(f"Unknown action: {action}")

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
