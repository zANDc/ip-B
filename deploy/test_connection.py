#!/usr/bin/env python3
"""Test SSH connection to remote server."""
import paramiko
import sys

HOST = "175.178.103.242"
USER = "root"
PASSWORD = "Jq399$FQJF@*&^"

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Connecting to {USER}@{HOST}...")
        client.connect(HOST, username=USER, password=PASSWORD, timeout=15)
        print("[OK] SSH connection established")
        stdin, stdout, stderr = client.exec_command("uname -a; echo '---'; cat /etc/os-release 2>/dev/null | head -3; echo '---'; which python3 python pip3; echo '---'; python3 --version 2>&1")
        out = stdout.read().decode()
        err = stderr.read().decode()
        print("STDOUT:", out)
        if err:
            print("STDERR:", err)
        client.close()
        return 0
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
